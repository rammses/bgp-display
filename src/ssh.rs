use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::events::AppEvent;
use crate::logging::thresholds;
use crate::router::{RouterConfig, SSH_MUX_CONTROL_PATH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Warming,
    Ready,
    Dead(String),
}

/// Centralized SSH connection manager.
///
/// Holds per-router config and session state, pre-warms ControlMaster
/// connections at startup, and provides `run_cmd` / `run_piped` /
/// `run_shell_pipe` as the single entry point for all SSH transport.
/// Mux-error retry is handled internally so callers never need to.
pub struct SshSessionManager {
    sessions: RwLock<HashMap<Uuid, (RouterConfig, SessionState)>>,
}

impl SshSessionManager {
    pub fn new(routers: &[RouterConfig]) -> Arc<Self> {
        let sessions = routers
            .iter()
            .map(|r| (r.id, (r.clone(), SessionState::Warming)))
            .collect();
        Arc::new(Self {
            sessions: RwLock::new(sessions),
        })
    }

    #[allow(dead_code)]
    pub async fn register_router(&self, router: RouterConfig) {
        tracing::info!(router = %router.name, id = %router.id, "registering router in SSH manager");
        self.sessions
            .write()
            .await
            .insert(router.id, (router, SessionState::Warming));
    }

    #[allow(dead_code)]
    pub async fn unregister_router(&self, id: Uuid) {
        tracing::info!(id = %id, "unregistering router from SSH manager");
        self.sessions.write().await.remove(&id);
    }

    pub async fn get_config(&self, router_id: Uuid) -> Option<RouterConfig> {
        self.sessions
            .read()
            .await
            .get(&router_id)
            .map(|(cfg, _)| cfg.clone())
    }

    // ── Connection warming ──────────────────────────────────────────────────

    /// Pre-warm ControlMaster connections to every registered router in parallel.
    /// Sends an `SshWarmComplete` event when finished.
    pub async fn warm_all(self: &Arc<Self>, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        let start = Instant::now();
        let configs: Vec<RouterConfig> = self
            .sessions
            .read()
            .await
            .values()
            .map(|(c, _)| c.clone())
            .collect();

        let total = configs.len();
        tracing::info!(count = total, "warming SSH connections");

        let handles: Vec<_> = configs
            .into_iter()
            .map(|cfg| {
                let this = Arc::clone(self);
                let id = cfg.id;
                let name = cfg.name.clone();
                let host = cfg.hostname.clone();
                tokio::spawn(async move {
                    let t = Instant::now();
                    let result = Self::exec_cmd(&cfg, "echo ok").await;
                    let elapsed_ms = t.elapsed().as_millis();

                    let (new_state, err) = match result {
                        Ok(_) => {
                            tracing::info!(
                                router = %name, host = %host,
                                elapsed_ms, "SSH warm OK"
                            );
                            (SessionState::Ready, None)
                        }
                        Err(e) => {
                            tracing::warn!(
                                router = %name, host = %host,
                                elapsed_ms, error = %e, "SSH warm FAILED"
                            );
                            (
                                SessionState::Dead(e.to_string()),
                                Some((name.clone(), e.to_string())),
                            )
                        }
                    };
                    if let Some((_, state)) = this.sessions.write().await.get_mut(&id) {
                        *state = new_state;
                    }
                    err
                })
            })
            .collect();

        let mut ready = 0usize;
        let mut failed: Vec<(String, String)> = Vec::new();
        for h in handles {
            match h.await {
                Ok(None) => ready += 1,
                Ok(Some(pair)) => failed.push(pair),
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

    /// Run `ssh -O check` against every router; re-warm dead sessions.
    /// Sends an `SshHealthReport` event when finished.
    pub async fn health_check_all(self: &Arc<Self>, event_tx: &mpsc::UnboundedSender<AppEvent>) {
        let start = Instant::now();
        let entries: Vec<(Uuid, RouterConfig)> = self
            .sessions
            .read()
            .await
            .iter()
            .map(|(&id, (cfg, _))| (id, cfg.clone()))
            .collect();

        tracing::debug!(count = entries.len(), "starting SSH health check");

        let handles: Vec<_> = entries
            .into_iter()
            .map(|(id, cfg)| {
                let this = Arc::clone(self);
                let name = cfg.name.clone();
                tokio::spawn(async move {
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

                    let mut sessions = this.sessions.write().await;
                    if let Some((_, state)) = sessions.get_mut(&id) {
                        if healthy {
                            *state = SessionState::Ready;
                        } else {
                            tracing::debug!(router = %name, "health check failed — marking dead");
                            *state = SessionState::Dead("health check failed".into());
                        }
                    }
                    (id, name, healthy)
                })
            })
            .collect();

        let mut healthy_count = 0usize;
        let mut dead_names: Vec<(Uuid, String, RouterConfig)> = Vec::new();

        for h in handles {
            if let Ok((id, name, is_healthy)) = h.await {
                if is_healthy {
                    healthy_count += 1;
                } else {
                    let cfg = self.get_config(id).await;
                    if let Some(cfg) = cfg {
                        dead_names.push((id, name, cfg));
                    }
                }
            }
        }

        // Re-warm dead sessions
        let dead_count = dead_names.len();
        let rewarm_handles: Vec<_> = dead_names
            .into_iter()
            .map(|(id, name, cfg)| {
                let this = Arc::clone(self);
                tokio::spawn(async move {
                    let t = Instant::now();
                    let new_state = match Self::exec_cmd(&cfg, "echo ok").await {
                        Ok(_) => {
                            tracing::info!(router = %name, elapsed_ms = t.elapsed().as_millis(), "SSH re-warm OK");
                            SessionState::Ready
                        }
                        Err(e) => {
                            tracing::warn!(router = %name, elapsed_ms = t.elapsed().as_millis(), error = %e, "SSH re-warm FAILED");
                            SessionState::Dead(e.to_string())
                        }
                    };
                    let rewarmed = matches!(new_state, SessionState::Ready);
                    if let Some((_, state)) = this.sessions.write().await.get_mut(&id) {
                        *state = new_state;
                    }
                    (name, rewarmed)
                })
            })
            .collect();

        let mut rewarmed = 0usize;
        let mut still_dead: Vec<String> = Vec::new();
        for h in rewarm_handles {
            if let Ok((name, ok)) = h.await {
                if ok {
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
    pub async fn run_cmd(&self, router_id: Uuid, remote_cmd: &str) -> Result<String> {
        let cfg = self
            .get_config(router_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Router {router_id} not registered"))?;

        tracing::debug!(router = %cfg.name, cmd = %remote_cmd, "run_cmd");

        match Self::exec_cmd(&cfg, remote_cmd).await {
            Err(e) if crate::router::is_ssh_mux_error(&e) => {
                tracing::warn!(router = %cfg.name, "stale mux socket — cleaning up and retrying");
                crate::router::cleanup_mux_socket(&cfg.username, &cfg.hostname, cfg.ssh_port).await;
                Self::exec_cmd(&cfg, remote_cmd).await
            }
            other => other,
        }
    }

    // ── Piped stdin execution (ssh -T user@host < stdin) ────────────────────

    async fn exec_piped(cfg: &RouterConfig, stdin_data: &str) -> Result<String> {
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

        let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
            .await
            .map_err(|_| anyhow::anyhow!("SSH timed out connecting to {}", cfg.hostname))??;
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
    pub async fn run_piped(&self, router_id: Uuid, stdin_data: &str) -> Result<String> {
        let cfg = self
            .get_config(router_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Router {router_id} not registered"))?;

        tracing::debug!(router = %cfg.name, "run_piped");

        match Self::exec_piped(&cfg, stdin_data).await {
            Err(e) if crate::router::is_ssh_mux_error(&e) => {
                tracing::warn!(router = %cfg.name, "stale mux socket (piped) — cleaning up and retrying");
                crate::router::cleanup_mux_socket(&cfg.username, &cfg.hostname, cfg.ssh_port).await;
                Self::exec_piped(&cfg, stdin_data).await
            }
            other => other,
        }
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
    pub async fn run_shell_pipe(&self, router_id: Uuid, script: &str) -> Result<String> {
        let cfg = self
            .get_config(router_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Router {router_id} not registered"))?;

        tracing::debug!(router = %cfg.name, "run_shell_pipe");

        match Self::exec_shell_pipe(&cfg, script).await {
            Err(e) if crate::router::is_ssh_mux_error(&e) => {
                tracing::warn!(router = %cfg.name, "stale mux socket (shell pipe) — cleaning up and retrying");
                crate::router::cleanup_mux_socket(&cfg.username, &cfg.hostname, cfg.ssh_port).await;
                Self::exec_shell_pipe(&cfg, script).await
            }
            other => other,
        }
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
            .map(|(c, _)| c.clone())
            .collect();
        crate::router::cleanup_ssh_sessions(&routers).await;
    }
}
