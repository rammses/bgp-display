use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex, RwLock};
use uuid::Uuid;

use crate::events::AppEvent;
use crate::logging::thresholds;
use crate::router::{RouterConfig, RouterVendor, SSH_MUX_CONTROL_PATH};

mod mikrotik;

pub use mikrotik::{
    NativeCommand, NativeCommandKind, NativeEndpoint, NativeExecutor, NativeLease,
    NativeRegistration,
};
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "retained public native executor error/future contract for staged mutation consumers"
    )
)]
pub use mikrotik::{NativeExecError, NativeFuture};

/// Native probes validate the decoded envelope's data, not stdout/mux success.
pub(crate) async fn probe_native<E: NativeExecutor>(io: &E) -> Result<()> {
    let request = Uuid::new_v4();
    let quoted = crate::router::mikrotik::ros_string(&request.to_string());
    let script = format!(":local mtresult {{\"request\"={quoted};\"ok\"=true;\"data\"=\"ok\"}}; :put [:serialize value=$mtresult to=json options=json.no-string-conversion]");
    let command = NativeCommand::checked(request, "native-probe", NativeCommandKind::Read, script)?;
    let value = io.exec(command).await?;
    anyhow::ensure!(value.as_str() == Some("ok"), "native-probe-data");
    Ok(())
}

#[derive(Clone)]
struct ProbeTarget {
    config: RouterConfig,
    registration: NativeRegistration,
}

// Borrowed invocation data only, never Debug-rendered (stdin/scripts may contain
// credentials). This is shared by real execution and external-I/O-only tests.
#[derive(Clone, Copy)]
enum LegacyOperation<'a> {
    Command(&'a str),
    Piped { data: &'a str, timeout: Duration },
    ShellPipe(&'a str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Warming,
    Ready,
    Dead(String),
}

#[cfg(test)]
mod monitoring_tests {
    use super::*;
    use crate::router::mikrotik::test_support::{Reply, TranscriptExecutor};
    use crate::router::RouterVendor;

    #[tokio::test]
    async fn mikrotik_warm_requires_checked_json_ok_data() {
        let io = TranscriptExecutor::new(vec![Reply::Data(serde_json::json!("ok"))]);
        probe_native(&io).await.unwrap();
        assert_eq!(io.seen_labels(), vec!["native-probe"]);
        assert_eq!(io.mutation_attempts(), 0);
        for value in [
            serde_json::json!(null),
            serde_json::json!({"data":"ok"}),
            serde_json::json!("not-ok"),
        ] {
            let io = TranscriptExecutor::new(vec![Reply::Data(value)]);
            assert!(probe_native(&io).await.is_err());
        }
    }

    #[tokio::test]
    async fn mikrotik_warm_vendor_branch_for_initial_health_and_rewarm_is_native_only() {
        let config = RouterConfig {
            vendor: RouterVendor::MikroTik,
            ..RouterConfig::default()
        };
        let id = config.id;
        let manager = SshSessionManager::new(&[config]);
        let io = Arc::new(TranscriptExecutor::new(vec![
            Reply::Data(serde_json::json!("ok")),
            Reply::Data(serde_json::json!("ok")),
            Reply::Data(serde_json::json!("ok")),
        ]));
        for health in [false, true, false] {
            let target = manager.probe_targets().await.pop().unwrap();
            let expected = target.registration.clone();
            let probing = Arc::clone(&manager);
            let io = Arc::clone(&io);
            let result = manager
                .run_probe_with(target, |cfg, token| async move {
                    probing
                        .probe_target_with(
                            cfg,
                            token,
                            health,
                            |lease| async move {
                                assert_eq!(lease.registration(), &expected);
                                probe_native(io.as_ref()).await
                            },
                            |_, _| async {
                                panic!("native probe must never use legacy echo or mux")
                            },
                        )
                        .await
                })
                .await;
            assert!(result.unwrap().1.is_ok());
            assert_eq!(
                manager.sessions.read().await[&id].state,
                SessionState::Ready
            );
        }
        assert_eq!(io.seen_labels().len(), 3);
        assert_eq!(io.mutation_attempts(), 0);
    }

    #[tokio::test]
    async fn mikrotik_warm_late_result_cannot_mark_re_registered_vendor_ready() {
        let config = RouterConfig {
            vendor: RouterVendor::MikroTik,
            ..RouterConfig::default()
        };
        let id = config.id;
        let manager = SshSessionManager::new(&[config.clone()]);
        let target = manager.probe_targets().await.pop().unwrap();
        let original = target.registration.clone();
        let io = TranscriptExecutor::new(vec![Reply::Data(serde_json::json!("ok"))]);
        let probing = Arc::clone(&manager);
        let result = manager
            .run_probe_with(target, |cfg, token| async move {
                assert_eq!(cfg.id, id);
                assert_eq!(token, original);
                let mut replacement = config;
                replacement.vendor = RouterVendor::Cisco;
                probing.register_router(replacement).await;
                probe_native(&io).await
            })
            .await;
        assert!(result.is_none());
        assert_eq!(
            manager.sessions.read().await[&id].state,
            SessionState::Warming
        );
    }

    #[tokio::test]
    async fn mikrotik_warm_queued_lease_never_retargets_after_registration_change() {
        let config = RouterConfig {
            vendor: RouterVendor::MikroTik,
            hostname: "lab.invalid".into(),
            ..RouterConfig::default()
        };
        let id = config.id;
        let manager = SshSessionManager::new(&[config.clone()]);
        let target = manager.probe_targets().await.pop().unwrap();
        let held = manager.native_lease(&target.registration).await.unwrap();
        let other = Arc::clone(&manager);
        let io = Arc::new(TranscriptExecutor::new(vec![]));
        let observed = Arc::clone(&io);
        let task = tokio::spawn(async move {
            let probing = Arc::clone(&other);
            other
                .run_probe_with(target, |cfg, token| async move {
                    assert_eq!(cfg.hostname, "lab.invalid");
                    let lease = probing.native_lease(&token).await?;
                    assert_eq!(lease.registration(), &token);
                    probe_native(observed.as_ref()).await
                })
                .await
        });
        tokio::task::yield_now().await;
        let mut replacement = config;
        replacement.hostname = "other.invalid".into();
        manager.register_router(replacement).await;
        drop(held);
        assert!(task.await.unwrap().is_none());
        assert!(io.seen_labels().is_empty());
        assert_eq!(
            manager.sessions.read().await[&id].state,
            SessionState::Warming
        );
    }
}

pub(super) struct RegisteredSession {
    config: RouterConfig,
    state: SessionState,
    native_revision: Uuid,
}

impl RegisteredSession {
    fn new(config: RouterConfig) -> Self {
        Self {
            config,
            state: SessionState::Warming,
            native_revision: Uuid::new_v4(),
        }
    }

    fn native_registration(&self) -> NativeRegistration {
        NativeRegistration {
            router_id: self.config.id,
            revision: self.native_revision,
            endpoint: NativeEndpoint {
                hostname: self.config.hostname.clone(),
                ssh_port: self.config.ssh_port,
                username: self.config.username.clone(),
            },
        }
    }
}

/// Centralized SSH connection manager.
///
/// Holds per-router config and session state, pre-warms ControlMaster
/// connections at startup, and provides `run_cmd` / `run_piped` /
/// `run_shell_pipe` as the single entry point for all SSH transport.
/// Mux-error retry is handled internally so callers never need to.
pub struct SshSessionManager {
    sessions: Arc<RwLock<HashMap<Uuid, RegisteredSession>>>,
    native_endpoints: Mutex<HashMap<NativeEndpoint, Arc<Mutex<()>>>>,
}

impl SshSessionManager {
    pub fn new(routers: &[RouterConfig]) -> Arc<Self> {
        let sessions = routers
            .iter()
            .map(|r| (r.id, RegisteredSession::new(r.clone())))
            .collect();
        Arc::new(Self {
            sessions: Arc::new(RwLock::new(sessions)),
            native_endpoints: Mutex::new(HashMap::new()),
        })
    }

    pub async fn register_router(&self, router: RouterConfig) {
        tracing::info!(router = %router.name, id = %router.id, "registering router in SSH manager");
        self.sessions
            .write()
            .await
            .insert(router.id, RegisteredSession::new(router));
    }

    pub async fn unregister_router(&self, id: Uuid) {
        tracing::info!(id = %id, "unregistering router from SSH manager");
        self.sessions.write().await.remove(&id);
    }

    pub async fn get_config(&self, router_id: Uuid) -> Option<RouterConfig> {
        self.sessions
            .read()
            .await
            .get(&router_id)
            .map(|session| session.config.clone())
    }

    /// Capture dispatch decisions and their token under the SAME registry read.
    /// The config contains credentials: do not log or Debug-render this tuple.
    pub(crate) async fn registered_snapshot(
        &self,
        router_id: Uuid,
    ) -> Result<(RouterConfig, NativeRegistration)> {
        self.sessions
            .read()
            .await
            .get(&router_id)
            .map(|session| (session.config.clone(), session.native_registration()))
            .ok_or_else(|| anyhow::anyhow!("stale-native-registration"))
    }

    // Retained token-only API for guarded mutation workflows; monitoring must
    // capture config + token atomically via registered_snapshot instead.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "token-only native API retained for guarded mutation phase; monitoring uses atomic config/token snapshots"
        )
    )]
    pub async fn native_registration(&self, router_id: Uuid) -> Result<NativeRegistration> {
        self.sessions
            .read()
            .await
            .get(&router_id)
            .map(RegisteredSession::native_registration)
            .ok_or_else(|| anyhow::anyhow!("stale-native-registration"))
    }

    pub async fn native_lease(&self, expected: &NativeRegistration) -> Result<NativeLease> {
        {
            let sessions = self.sessions.read().await;
            if !sessions
                .get(&expected.router_id)
                .is_some_and(|session| session.native_registration() == *expected)
            {
                bail!("stale-native-registration");
            }
        }
        // Never hold the session registry across the endpoint-lock wait, and
        // never resolve an endpoint from the UUID again after this first check.
        let endpoint_lock = {
            let mut endpoints = self.native_endpoints.lock().await;
            Arc::clone(
                endpoints
                    .entry(expected.endpoint.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let permit = endpoint_lock.lock_owned().await;
        let config = {
            let sessions = self.sessions.read().await;
            let session = sessions
                .get(&expected.router_id)
                .filter(|session| session.native_registration() == *expected)
                .ok_or_else(|| anyhow::anyhow!("stale-native-registration"))?;
            session.config.clone()
        };
        Ok(NativeLease::new(
            config,
            expected.clone(),
            Arc::clone(&self.sessions),
            permit,
        ))
    }

    // ── Connection warming ──────────────────────────────────────────────────

    async fn probe_targets(&self) -> Vec<ProbeTarget> {
        self.sessions
            .read()
            .await
            .values()
            .map(|session| ProbeTarget {
                config: session.config.clone(),
                registration: session.native_registration(),
            })
            .collect()
    }

    /// Injection boundary is only the external probe. Registry comparison and
    /// state attribution are the same in tests and all production probe paths.
    async fn run_probe_with<F, Fut>(
        &self,
        target: ProbeTarget,
        probe: F,
    ) -> Option<(String, Result<()>)>
    where
        F: FnOnce(RouterConfig, NativeRegistration) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let expected = target.registration;
        if !self
            .sessions
            .read()
            .await
            .get(&expected.router_id)
            .is_some_and(|session| session.native_registration() == expected)
        {
            return None;
        }
        let name = target.config.name.clone();
        let result = probe(target.config, expected.clone()).await;
        let state = match &result {
            Ok(()) => SessionState::Ready,
            Err(error) => SessionState::Dead(error.to_string()),
        };
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&expected.router_id)
            .filter(|session| session.native_registration() == expected)?;
        session.state = state;
        Some((name, result))
    }

    async fn probe_target(
        &self,
        cfg: &RouterConfig,
        expected: &NativeRegistration,
        health: bool,
    ) -> Result<()> {
        self.probe_target_with(
            cfg.clone(),
            expected.clone(),
            health,
            |lease| async move { probe_native(&lease).await },
            |cfg, health| async move { Self::legacy_probe(&cfg, health).await },
        )
        .await
    }

    async fn probe_target_with<F, Fut, G, LegacyFut>(
        &self,
        cfg: RouterConfig,
        expected: NativeRegistration,
        health: bool,
        native: F,
        legacy: G,
    ) -> Result<()>
    where
        F: FnOnce(NativeLease) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
        G: FnOnce(RouterConfig, bool) -> LegacyFut,
        LegacyFut: std::future::Future<Output = Result<()>>,
    {
        if cfg.vendor == RouterVendor::MikroTik {
            return native(self.native_lease(&expected).await?).await;
        }
        legacy(cfg, health).await
    }

    async fn legacy_probe(cfg: &RouterConfig, health: bool) -> Result<()> {
        if !health {
            Self::exec_cmd(cfg, "echo ok").await?;
            return Ok(());
        }
        // Legacy mux-check command/options/auth remain unchanged.
        let control_path_arg = format!("ControlPath={SSH_MUX_CONTROL_PATH}");
        let target = format!("{}@{}", cfg.username, cfg.hostname);
        let port_str = cfg.ssh_port.to_string();
        let healthy = tokio::time::timeout(
            Duration::from_secs(5),
            Command::new("ssh")
                .args([
                    "-O",
                    "check",
                    "-p",
                    &port_str,
                    "-o",
                    &control_path_arg,
                    &target,
                ])
                .stderr(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .output(),
        )
        .await
        .is_ok_and(|r| r.is_ok_and(|o| o.status.success()));
        anyhow::ensure!(healthy, "health check failed");
        Ok(())
    }

    /// Pre-warm ControlMaster connections to every registered router in parallel.
    /// Sends an `SshWarmComplete` event when finished.
    pub async fn warm_all(self: &Arc<Self>, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        let start = Instant::now();
        let targets = self.probe_targets().await;
        let total = targets.len();
        tracing::info!(count = total, "warming SSH connections");
        let handles: Vec<_> = targets
            .into_iter()
            .map(|target| {
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    let probing = Arc::clone(&this);
                    this.run_probe_with(target, |cfg, token| async move {
                        probing.probe_target(&cfg, &token, false).await
                    })
                    .await
                })
            })
            .collect();

        let mut ready = 0usize;
        let mut failed: Vec<(String, String)> = Vec::new();
        for h in handles {
            match h.await {
                Ok(Some((_, Ok(())))) => ready += 1,
                Ok(Some((name, Err(error)))) => failed.push((name, error.to_string())),
                Ok(None) => {} // Replaced registrations are not current results.
                Err(e) => failed.push(("unknown".into(), e.to_string())),
            }
        }

        let elapsed_ms = start.elapsed().as_millis();
        tracing::info!(
            ready,
            failed = failed.len(),
            elapsed_ms,
            "SSH warm-all complete"
        );

        let _ = event_tx.send(AppEvent::SshWarmComplete(ready, failed));
    }

    /// Native JSON probes / legacy mux checks; re-warm original dead targets.
    /// Sends an `SshHealthReport` event when finished.
    pub async fn health_check_all(self: &Arc<Self>, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        let start = Instant::now();
        let entries = self.probe_targets().await;
        tracing::debug!(count = entries.len(), "starting SSH health check");

        let handles: Vec<_> = entries
            .into_iter()
            .map(|target| {
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    let probing = Arc::clone(&this);
                    let result = this
                        .run_probe_with(target.clone(), |cfg, token| async move {
                            probing.probe_target(&cfg, &token, true).await
                        })
                        .await;
                    (target, result)
                })
            })
            .collect();

        let mut healthy_count = 0usize;
        let mut dead_targets = Vec::new();

        for h in handles {
            if let Ok((target, Some((_, result)))) = h.await {
                if result.is_ok() {
                    healthy_count += 1;
                } else {
                    dead_targets.push(target);
                }
            }
        }

        // Re-warm dead sessions
        let dead_count = dead_targets.len();
        let rewarm_handles: Vec<_> = dead_targets
            .into_iter()
            .map(|target| {
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    let probing = Arc::clone(&this);
                    this.run_probe_with(target, |cfg, token| async move {
                        probing.probe_target(&cfg, &token, false).await
                    })
                    .await
                })
            })
            .collect();

        let mut rewarmed = 0usize;
        let mut still_dead: Vec<String> = Vec::new();
        for h in rewarm_handles {
            if let Ok(Some((name, result))) = h.await {
                if result.is_ok() {
                    rewarmed += 1;
                } else {
                    still_dead.push(name);
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis();
        tracing::info!(
            healthy = healthy_count,
            dead = dead_count,
            rewarmed,
            still_dead = still_dead.len(),
            elapsed_ms,
            "SSH health check complete"
        );

        let _ = event_tx.send(AppEvent::SshHealthReport {
            healthy: healthy_count + rewarmed,
            rewarmed,
            dead: still_dead,
        });
    }

    // ── Simple command execution (ssh user@host "cmd") ──────────────────────

    fn require_legacy_config(config: &RouterConfig) -> Result<()> {
        anyhow::ensure!(
            config.vendor != RouterVendor::MikroTik,
            "MikroTik requires a native lease; generic SSH rejected"
        );
        Ok(())
    }

    async fn legacy_config(
        &self,
        router_id: Uuid,
        expected: Option<&RouterConfig>,
    ) -> Result<RouterConfig> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(&router_id)
            .ok_or_else(|| anyhow::anyhow!("Router {router_id} not registered"))?;
        // Check the ACTUAL captured registry record, not an earlier dispatcher
        // decision. No payload logging or external I/O may precede this guard.
        Self::require_legacy_config(&session.config)?;
        anyhow::ensure!(
            expected.is_none_or(|config| config == &session.config),
            "stale legacy registration; router configuration changed"
        );
        Ok(session.config.clone())
    }

    async fn run_legacy(
        &self,
        router_id: Uuid,
        expected: Option<&RouterConfig>,
        operation: LegacyOperation<'_>,
    ) -> Result<String> {
        self.run_legacy_with(
            router_id,
            expected,
            operation,
            Self::execute_legacy,
            Self::cleanup_legacy,
        )
        .await
    }

    async fn execute_legacy(
        config: RouterConfig,
        operation: LegacyOperation<'_>,
    ) -> Result<String> {
        match operation {
            LegacyOperation::Command(command) => Self::exec_cmd(&config, command).await,
            LegacyOperation::Piped { data, timeout } => {
                Self::exec_piped(&config, data, timeout).await
            }
            LegacyOperation::ShellPipe(script) => Self::exec_shell_pipe(&config, script).await,
        }
    }

    async fn cleanup_legacy(config: RouterConfig) {
        crate::router::cleanup_mux_socket(&config.username, &config.hostname, config.ssh_port)
            .await;
    }

    async fn run_legacy_with<'a, F, Fut, C, Cleanup>(
        &self,
        router_id: Uuid,
        expected: Option<&RouterConfig>,
        operation: LegacyOperation<'a>,
        mut execute: F,
        cleanup: C,
    ) -> Result<String>
    where
        F: FnMut(RouterConfig, LegacyOperation<'a>) -> Fut,
        Fut: std::future::Future<Output = Result<String>>,
        C: FnOnce(RouterConfig) -> Cleanup,
        Cleanup: std::future::Future<Output = ()>,
    {
        let config = self.legacy_config(router_id, expected).await?;
        match operation {
            LegacyOperation::Command(command) => {
                tracing::debug!(router = %config.name, cmd = %command, "run_cmd")
            }
            LegacyOperation::Piped { .. } => tracing::debug!(router = %config.name, "run_piped"),
            LegacyOperation::ShellPipe(_) => {
                tracing::debug!(router = %config.name, "run_shell_pipe")
            }
        }
        match execute(config.clone(), operation).await {
            Err(error) if crate::router::is_ssh_mux_error(&error) => {
                match operation {
                    LegacyOperation::Command(_) => {
                        tracing::warn!(router = %config.name, "stale mux socket — cleaning up and retrying")
                    }
                    LegacyOperation::Piped { .. } => {
                        tracing::warn!(router = %config.name, "stale mux socket (piped) — cleaning up and retrying")
                    }
                    LegacyOperation::ShellPipe(_) => {
                        tracing::warn!(router = %config.name, "stale mux socket (shell pipe) — cleaning up and retrying")
                    }
                }
                // A re-registration during the first attempt cannot retarget
                // cleanup/retry: neither operation resolves the UUID again.
                cleanup(config.clone()).await;
                execute(config, operation).await
            }
            other => other,
        }
    }

    fn exec_cmd_builder(cfg: &RouterConfig) -> (Command, String, String, String) {
        let target = format!("{}@{}", cfg.username, cfg.hostname);
        let port_str = cfg.ssh_port.to_string();
        let control_path_arg = format!("ControlPath={SSH_MUX_CONTROL_PATH}");

        let cmd = if cfg.password.is_some() {
            let mut c = Command::new("sshpass");
            c.env("SSHPASS", cfg.password.as_deref().unwrap_or(""));
            c.arg("-e").arg("ssh");
            c
        } else {
            Command::new("ssh")
        };

        (cmd, target, port_str, control_path_arg)
    }

    async fn exec_cmd(cfg: &RouterConfig, remote_cmd: &str) -> Result<String> {
        Self::require_legacy_config(cfg)?;
        let (mut cmd, target, port_str, control_path_arg) = Self::exec_cmd_builder(cfg);

        let mut args: Vec<&str> = vec![
            "-p",
            &port_str,
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ControlMaster=auto",
            "-o",
            &control_path_arg,
            "-o",
            "ControlPersist=600",
        ];

        if cfg.password.is_some() {
            args.push("-o");
            args.push("PreferredAuthentications=password,keyboard-interactive");
        } else {
            args.push("-o");
            args.push("BatchMode=yes");
        }

        cmd.args(&args).arg(&target).arg(remote_cmd);

        let start = Instant::now();
        let output = tokio::time::timeout(Duration::from_secs(15), cmd.output())
            .await
            .map_err(|_| anyhow::anyhow!("SSH timed out connecting to {}", cfg.hostname))??;
        let elapsed_us = start.elapsed().as_micros();

        if elapsed_us > thresholds::SSH_WARN_US {
            tracing::warn!(
                host = %cfg.hostname, cmd = %remote_cmd,
                elapsed_ms = elapsed_us / 1000, "SSH command slow"
            );
        } else {
            tracing::debug!(
                host = %cfg.hostname, cmd = %remote_cmd,
                elapsed_ms = elapsed_us / 1000, "SSH command complete"
            );
        }

        if !output.status.success() && output.stdout.is_empty() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            tracing::warn!(host = %cfg.hostname, stderr = %err.trim(), "SSH command failed");
            bail!("SSH error: {}", err.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run a simple SSH command on a router (no stdin piping).
    // Retained UUID-only compatibility API. Backends bind their immutable cfg.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained guarded UUID-only compatibility entrypoint; legacy backends use config-bound calls"
        )
    )]
    pub async fn run_cmd(&self, router_id: Uuid, remote_cmd: &str) -> Result<String> {
        self.run_legacy(router_id, None, LegacyOperation::Command(remote_cmd))
            .await
    }

    pub(crate) async fn run_cmd_for(
        &self,
        expected: &RouterConfig,
        remote_cmd: &str,
    ) -> Result<String> {
        self.run_legacy(
            expected.id,
            Some(expected),
            LegacyOperation::Command(remote_cmd),
        )
        .await
    }

    // ── Piped stdin execution (ssh -T user@host < stdin) ────────────────────

    async fn exec_piped(
        cfg: &RouterConfig,
        stdin_data: &str,
        command_timeout: Duration,
    ) -> Result<String> {
        Self::require_legacy_config(cfg)?;
        let (mut cmd, target, port_str, control_path_arg) = Self::exec_cmd_builder(cfg);

        let mut args: Vec<&str> = vec![
            "-p",
            &port_str,
            "-T",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ControlMaster=auto",
            "-o",
            &control_path_arg,
            "-o",
            "ControlPersist=600",
        ];

        if cfg.password.is_some() {
            args.push("-o");
            args.push("PreferredAuthentications=password,keyboard-interactive");
        } else {
            args.push("-o");
            args.push("BatchMode=yes");
        }

        cmd.args(&args).arg(&target);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let start = Instant::now();
        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn SSH: {e}"))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_data.as_bytes()).await?;
            drop(stdin);
        }

        let output = tokio::time::timeout(command_timeout, child.wait_with_output())
            .await
            .map_err(|_| anyhow::anyhow!("SSH piped command timed out on {}", cfg.hostname))??;
        let elapsed_us = start.elapsed().as_micros();

        if elapsed_us > thresholds::SSH_WARN_US {
            tracing::warn!(
                host = %cfg.hostname, elapsed_ms = elapsed_us / 1000,
                "SSH piped command slow"
            );
        } else {
            tracing::debug!(
                host = %cfg.hostname, elapsed_ms = elapsed_us / 1000,
                "SSH piped command complete"
            );
        }

        if !output.status.success() && output.stdout.is_empty() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            tracing::warn!(host = %cfg.hostname, stderr = %err.trim(), "SSH piped command failed");
            bail!("SSH error: {}", err.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run SSH with piped stdin (for pfSense menu bypass, FortiGate CLI pipeline).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained guarded UUID-only compatibility entrypoint; legacy backends use config-bound calls"
        )
    )]
    pub async fn run_piped(&self, router_id: Uuid, stdin_data: &str) -> Result<String> {
        self.run_legacy(
            router_id,
            None,
            LegacyOperation::Piped {
                data: stdin_data,
                timeout: Duration::from_secs(15),
            },
        )
        .await
    }

    pub(crate) async fn run_piped_for(
        &self,
        expected: &RouterConfig,
        stdin_data: &str,
    ) -> Result<String> {
        self.run_piped_with_timeout_for(expected, stdin_data, Duration::from_secs(15))
            .await
    }

    /// Run SSH with piped stdin, allowing a longer timeout for NVUE applies.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained guarded UUID-only compatibility entrypoint; legacy backends use config-bound calls"
        )
    )]
    pub async fn run_piped_with_timeout(
        &self,
        router_id: Uuid,
        stdin_data: &str,
        command_timeout: Duration,
    ) -> Result<String> {
        self.run_legacy(
            router_id,
            None,
            LegacyOperation::Piped {
                data: stdin_data,
                timeout: command_timeout,
            },
        )
        .await
    }

    pub(crate) async fn run_piped_with_timeout_for(
        &self,
        expected: &RouterConfig,
        stdin_data: &str,
        command_timeout: Duration,
    ) -> Result<String> {
        self.run_legacy(
            expected.id,
            Some(expected),
            LegacyOperation::Piped {
                data: stdin_data,
                timeout: command_timeout,
            },
        )
        .await
    }

    // ── Shell pipeline execution (for Citrix: { printf ...; } | ssh ...) ────

    /// Build the SSH command string for use in shell pipelines.
    pub fn build_ssh_cmd_str(cfg: &RouterConfig) -> String {
        let target = format!("{}@{}", cfg.username, cfg.hostname);
        let base_args = format!(
            "-p {} -T -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
             -o LogLevel=ERROR -o ControlMaster=auto -o ControlPath={} \
             -o ControlPersist=600",
            cfg.ssh_port, SSH_MUX_CONTROL_PATH,
        );
        if cfg.password.is_some() {
            format!(
                "sshpass -e ssh {base_args} \
                 -o PreferredAuthentications=password,keyboard-interactive {target}"
            )
        } else {
            format!("ssh {base_args} -o BatchMode=yes {target}")
        }
    }

    async fn exec_shell_pipe(cfg: &RouterConfig, script: &str) -> Result<String> {
        Self::require_legacy_config(cfg)?;
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(script);
        if let Some(ref pw) = cfg.password {
            cmd.env("SSHPASS", pw);
        }

        let start = Instant::now();
        let output = tokio::time::timeout(Duration::from_secs(15), cmd.output())
            .await
            .map_err(|_| anyhow::anyhow!("SSH timed out connecting to {}", cfg.hostname))??;
        let elapsed_us = start.elapsed().as_micros();

        if elapsed_us > thresholds::SSH_WARN_US {
            tracing::warn!(
                host = %cfg.hostname, elapsed_ms = elapsed_us / 1000,
                "SSH shell pipe slow"
            );
        } else {
            tracing::debug!(
                host = %cfg.hostname, elapsed_ms = elapsed_us / 1000,
                "SSH shell pipe complete"
            );
        }

        if !output.status.success() && output.stdout.is_empty() {
            let err = String::from_utf8_lossy(&output.stderr).to_string();
            tracing::warn!(host = %cfg.hostname, stderr = %err.trim(), "SSH shell pipe failed");
            bail!("SSH error: {}", err.trim());
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run a shell pipeline that pipes into SSH (used by Citrix interactive vtysh).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained guarded UUID-only compatibility entrypoint; legacy backends use config-bound calls"
        )
    )]
    pub async fn run_shell_pipe(&self, router_id: Uuid, script: &str) -> Result<String> {
        self.run_legacy(router_id, None, LegacyOperation::ShellPipe(script))
            .await
    }

    pub(crate) async fn run_shell_pipe_for(
        &self,
        expected: &RouterConfig,
        script: &str,
    ) -> Result<String> {
        self.run_legacy(
            expected.id,
            Some(expected),
            LegacyOperation::ShellPipe(script),
        )
        .await
    }

    // ── Cleanup ─────────────────────────────────────────────────────────────

    /// Gracefully close all ControlMaster connections.
    pub async fn cleanup_all(&self) {
        tracing::info!("cleaning up all SSH ControlMaster connections");
        let routers: Vec<RouterConfig> = self
            .sessions
            .read()
            .await
            .values()
            .map(|session| session.config.clone())
            .collect();
        crate::router::cleanup_ssh_sessions(&routers).await;
    }
}

#[cfg(test)]
mod legacy_security_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config(vendor: RouterVendor) -> RouterConfig {
        RouterConfig {
            id: Uuid::nil(),
            hostname: "origin.invalid".into(),
            username: "tester".into(),
            vendor,
            password: Some("synthetic-origin-password".into()),
            ..RouterConfig::default()
        }
    }

    #[tokio::test]
    async fn mikrotik_sec_001_compatibility_entries_reject_unregistered_router() {
        let manager = SshSessionManager::new(&[]);
        for result in [
            manager
                .run_cmd(Uuid::nil(), "synthetic-sensitive-command")
                .await,
            manager
                .run_piped(Uuid::nil(), "synthetic-sensitive-stdin")
                .await,
            manager
                .run_piped_with_timeout(
                    Uuid::nil(),
                    "synthetic-sensitive-stdin",
                    Duration::from_secs(120),
                )
                .await,
            manager
                .run_shell_pipe(Uuid::nil(), "synthetic-sensitive-shell")
                .await,
        ] {
            assert!(result.unwrap_err().to_string().contains("not registered"));
        }
    }

    #[tokio::test]
    async fn mikrotik_sec_001_generic_native_entries_reject_before_external_io() {
        let cfg = config(RouterVendor::MikroTik);
        let manager = SshSessionManager::new(&[cfg.clone()]);
        let calls = AtomicUsize::new(0);
        let mut rejected = Vec::new();
        for operation in [
            LegacyOperation::Command("synthetic-sensitive-command"),
            LegacyOperation::Piped {
                data: "synthetic-sensitive-stdin",
                timeout: Duration::from_secs(15),
            },
            LegacyOperation::Piped {
                data: "synthetic-sensitive-stdin",
                timeout: Duration::from_secs(120),
            },
            LegacyOperation::ShellPipe("synthetic-sensitive-shell"),
        ] {
            let result = manager
                .run_legacy_with(
                    cfg.id,
                    None,
                    operation,
                    |_, _| {
                        calls.fetch_add(1, Ordering::SeqCst);
                        async { Ok(String::new()) }
                    },
                    |_| async { panic!("rejected native call must not clean up a mux") },
                )
                .await;
            rejected.push(result.is_err());
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "generic native calls must stop before external I/O"
        );
        assert!(rejected.into_iter().all(|value| value));
    }

    #[derive(Clone)]
    struct LogWriter(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn mikrotik_sec_001_native_rejection_never_logs_sensitive_payload() {
        let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = LogWriter(Arc::clone(&bytes));
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let cfg = config(RouterVendor::MikroTik);
        let manager = SshSessionManager::new(&[cfg.clone()]);
        let _result = manager
            .run_legacy_with(
                cfg.id,
                None,
                LegacyOperation::Command("synthetic-credential-payload-sec001"),
                |_, _| async { Ok(String::new()) },
                |_| async {},
            )
            .await;
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(
            !output.contains("synthetic-credential-payload-sec001"),
            "rejected native payload was logged"
        );
        assert!(!output.contains("synthetic-origin-password"));
    }

    #[tokio::test]
    async fn mikrotik_sec_001_bound_two_call_workflow_never_retargets_after_registration() {
        for change in ["native-endpoint", "legacy-endpoint", "legacy-auth"] {
            let original = config(RouterVendor::Cumulus);
            let manager = SshSessionManager::new(&[original.clone()]);
            let mut replacement = original.clone();
            if change == "native-endpoint" {
                replacement.vendor = RouterVendor::MikroTik;
            }
            if change == "legacy-auth" {
                replacement.username = "replacement-user".into();
            } else {
                replacement.hostname = "replacement.invalid".into();
            }
            let manager_ref = &manager;
            let read = manager
                .run_legacy_with(
                    original.id,
                    Some(&original),
                    LegacyOperation::Command("cat /etc/os-release"),
                    |captured, _| {
                        let replacement = replacement.clone();
                        async move {
                            assert_eq!(captured.hostname, "origin.invalid");
                            manager_ref.register_router(replacement).await;
                            Ok("VERSION_ID=\"5.14.0\"".into())
                        }
                    },
                    |_| async {},
                )
                .await
                .unwrap();
            assert!(read.contains("5.14.0"));
            let writes = AtomicUsize::new(0);
            let result = manager.run_legacy_with(original.id, Some(&original),
                LegacyOperation::Piped { data: "nv set router bgp neighbor peer password synthetic-secret\nnv config apply --y\n", timeout: Duration::from_secs(120) },
                |_, _| { writes.fetch_add(1, Ordering::SeqCst); async { Ok("applied".into()) } },
                |_| async {},
            ).await;
            assert_eq!(
                writes.load(Ordering::SeqCst),
                0,
                "a later batch must not use a replacement config: {change}"
            );
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn mikrotik_sec_001_retry_keeps_one_original_config_and_endpoint() {
        let original = config(RouterVendor::Cisco);
        let manager = SshSessionManager::new(&[original.clone()]);
        let calls = AtomicUsize::new(0);
        let cleanups = AtomicUsize::new(0);
        let manager_ref = &manager;
        let original_ref = &original;
        let result = manager
            .run_legacy_with(
                original.id,
                Some(&original),
                LegacyOperation::Command("show ip bgp summary"),
                |captured, _| {
                    let attempt = calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert!(
                            captured == *original_ref,
                            "retry must retain full original config without re-resolving UUID"
                        );
                        if attempt == 0 {
                            let mut replacement = original_ref.clone();
                            replacement.hostname = "replacement.invalid".into();
                            replacement.vendor = RouterVendor::MikroTik;
                            manager_ref.register_router(replacement).await;
                            anyhow::bail!("control master unavailable");
                        }
                        Ok("origin-result".into())
                    }
                },
                |captured| {
                    cleanups.fetch_add(1, Ordering::SeqCst);
                    assert!(captured == original);
                    async {}
                },
            )
            .await
            .unwrap();
        assert_eq!(result, "origin-result");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cleanups.load(Ordering::SeqCst), 1);
    }
}
