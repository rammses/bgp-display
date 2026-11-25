// Native consumers are staged for Tasks3–4; this is compiled production code.
#![cfg_attr(not(test), allow(dead_code))]

use super::{RegisteredSession, SshSessionManager};
use crate::router::mikrotik::decode_envelope;
use crate::router::RouterConfig;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::process::{Child, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{OwnedMutexGuard, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCommandKind {
    Read,
    Mutation,
}

pub struct NativeCommand {
    pub request: Uuid,
    pub label: &'static str,
    pub kind: NativeCommandKind,
    script: String,
}

impl NativeCommand {
    pub fn checked(
        request: Uuid,
        label: &'static str,
        kind: NativeCommandKind,
        script: String,
    ) -> Result<Self> {
        if script.len() > 32768 {
            bail!("native-command-budget");
        }
        if script.chars().any(char::is_control) {
            bail!("native-command-control");
        }
        Ok(Self {
            request,
            label,
            kind,
            script,
        })
    }
}

impl std::fmt::Debug for NativeCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeCommand")
            .field("request", &self.request)
            .field("label", &self.label)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// `started` means the local process was launched, NOT that the remote mutation
/// is known to have run (or not run). A launched failure must be reconciled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeExecError {
    pub code: &'static str,
    pub started: bool,
}

impl std::fmt::Display for NativeExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for NativeExecError {}

pub type NativeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Value, NativeExecError>> + Send + 'a>>;

pub trait NativeExecutor: Send + Sync {
    fn exec<'a>(&'a self, command: NativeCommand) -> NativeFuture<'a>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NativeEndpoint {
    pub hostname: String,
    pub ssh_port: u16,
    pub username: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRegistration {
    pub router_id: Uuid,
    pub revision: Uuid,
    pub endpoint: NativeEndpoint,
}

pub struct NativeLease {
    config: RouterConfig,
    registration: NativeRegistration,
    registry: Arc<RwLock<HashMap<Uuid, RegisteredSession>>>,
    permit: OwnedMutexGuard<()>,
}

impl NativeLease {
    pub(super) fn new(
        config: RouterConfig,
        registration: NativeRegistration,
        registry: Arc<RwLock<HashMap<Uuid, RegisteredSession>>>,
        permit: OwnedMutexGuard<()>,
    ) -> Self {
        Self {
            config,
            registration,
            registry,
            permit,
        }
    }

    pub fn registration(&self) -> &NativeRegistration {
        &self.registration
    }

    async fn exec_with<P: NativeChild>(
        &self,
        command: NativeCommand,
        spawn: impl FnOnce(Command) -> io::Result<P>,
        limits: NativeLimits,
    ) -> Result<Value, NativeExecError> {
        {
            let registry = self.registry.read().await;
            if !registry
                .get(&self.registration.router_id)
                .is_some_and(|session| session.native_registration() == self.registration)
            {
                return Err(NativeExecError {
                    code: "stale-native-registration",
                    started: false,
                });
            }
        }
        // The permit is already owned for the entire sequence. No endpoint
        // lookup, get_config, lock reacquisition, mux fallback or replay here.
        execute_native(&self.config, command, spawn, limits).await
    }
}

impl NativeExecutor for NativeLease {
    fn exec<'a>(&'a self, command: NativeCommand) -> NativeFuture<'a> {
        // Only std OS spawn may report a proven prelaunch error. Async pipe
        // conversion happens later, with the actual std child already guarded.
        Box::pin(self.exec_with(
            command,
            |mut cmd| cmd.as_std_mut().spawn(),
            NativeLimits::PRODUCTION,
        ))
    }
}

#[derive(Clone, Copy)]
struct NativeLimits {
    output_bytes: usize,
    timeout: Duration,
}

impl NativeLimits {
    const PRODUCTION: Self = Self {
        output_bytes: 64 * 1024 * 1024,
        timeout: Duration::from_secs(30),
    };
}

fn native_process_command(config: &RouterConfig, command: &NativeCommand) -> Command {
    let (mut cmd, target, port, control_path) = SshSessionManager::exec_cmd_builder(config);
    // Same system OpenSSH, authentication, mux and host-key policy as legacy
    // exec_piped; no call to a permissive/logging/retry execution wrapper.
    cmd.args([
        "-p",
        &port,
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
        &control_path,
        "-o",
        "ControlPersist=600",
        "-o",
        if config.password.is_some() {
            "PreferredAuthentications=password,keyboard-interactive"
        } else {
            "BatchMode=yes"
        },
    ])
    .arg(target)
    .arg(&command.script)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    cmd
}

async fn collect_bounded<R: AsyncRead + Unpin>(reader: R, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native output budget",
        ));
    }
    Ok(bytes)
}

async fn empty_stderr<R: AsyncRead + Unpin>(mut reader: R) -> io::Result<()> {
    let mut byte = [0];
    if reader.read(&mut byte).await? != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "native stderr"));
    }
    Ok(())
}

type ProcessFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Spawn returns an owned OS child BEFORE any fallible async pipe setup.
/// Blocking wait is used only by the guard's pre-created cleanup thread.
trait NativeChild: Send + 'static {
    type Stdout: AsyncRead + Unpin + Send;
    type Stderr: AsyncRead + Unpin + Send;
    fn take_stdout(&mut self) -> io::Result<Option<Self::Stdout>>;
    fn take_stderr(&mut self) -> io::Result<Option<Self::Stderr>>;
    fn wait(&mut self) -> ProcessFuture<'_, bool>;
    fn start_kill(&mut self) -> io::Result<()>;
    fn wait_blocking(&mut self) -> io::Result<()>;
}

impl NativeChild for Child {
    type Stdout = tokio::process::ChildStdout;
    type Stderr = tokio::process::ChildStderr;

    fn take_stdout(&mut self) -> io::Result<Option<Self::Stdout>> {
        self.stdout
            .take()
            .map(tokio::process::ChildStdout::from_std)
            .transpose()
    }
    fn take_stderr(&mut self) -> io::Result<Option<Self::Stderr>> {
        self.stderr
            .take()
            .map(tokio::process::ChildStderr::from_std)
            .transpose()
    }

    fn wait(&mut self) -> ProcessFuture<'_, bool> {
        Box::pin(async move {
            loop {
                // std try_wait is documented nonblocking and reaps on success.
                // Polling stays inside the original command/cleanup deadline.
                if let Some(status) = self.try_wait()? {
                    return Ok(status.success());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    }

    fn start_kill(&mut self) -> io::Result<()> {
        self.kill()
    }

    fn wait_blocking(&mut self) -> io::Result<()> {
        Child::wait(self).map(|_| ())
    }
}

enum ReapState<P> {
    Waiting,
    Complete,
    Child(P),
}

struct ReapSlot<P> {
    state: Mutex<ReapState<P>>,
    ready: Condvar,
}

struct ChildGuard<P: NativeChild> {
    child: Option<P>,
    reaper: Arc<ReapSlot<P>>,
    kill_sent: bool,
}

impl<P: NativeChild> ChildGuard<P> {
    fn new() -> io::Result<Self> {
        let reaper: Arc<ReapSlot<P>> = Arc::new(ReapSlot {
            state: Mutex::new(ReapState::Waiting),
            ready: Condvar::new(),
        });
        let worker = Arc::clone(&reaper);
        // Allocate the one-child cleanup owner BEFORE OS launch. A resource
        // failure here is genuinely prelaunch. No fallible scheduling remains
        // after launch, including cancellation or Tokio runtime shutdown.
        std::thread::Builder::new()
            .name("native-ssh-reap".into())
            .spawn(move || {
                let mut state = worker.state.lock().unwrap_or_else(|e| e.into_inner());
                while matches!(*state, ReapState::Waiting) {
                    state = worker.ready.wait(state).unwrap_or_else(|e| e.into_inner());
                }
                let ReapState::Child(mut child) =
                    std::mem::replace(&mut *state, ReapState::Complete)
                else {
                    return;
                };
                drop(state);
                // This dedicated owner is independent of Tokio shutdown. Do
                // not drop an unreaped child on wait error or recursively spawn
                // replacement jobs. Retain it here and retry only local reaping.
                while child.wait_blocking().is_err() {
                    std::thread::park_timeout(Duration::from_millis(10));
                }
            })?;
        Ok(Self {
            child: None,
            reaper,
            kill_sent: false,
        })
    }

    fn signal(&mut self) {
        if !self.kill_sent {
            if let Some(child) = self.child.as_mut() {
                self.kill_sent = child.start_kill().is_ok();
            }
        }
    }

    async fn terminate(&mut self, deadline: tokio::time::Instant) {
        self.signal();
        if let Some(child) = self.child.as_mut() {
            // No new grace period: if the original deadline has elapsed,
            // pending reaping transfers to the already-owned cleanup thread.
            if tokio::time::timeout_at(deadline, child.wait())
                .await
                .is_ok_and(|result| result.is_ok())
            {
                self.child.take();
            }
        }
    }
}

impl<P: NativeChild> Drop for ChildGuard<P> {
    fn drop(&mut self) {
        self.signal();
        let mut state = self.reaper.state.lock().unwrap_or_else(|e| e.into_inner());
        *state = match self.child.take() {
            Some(child) => ReapState::Child(child),
            None => ReapState::Complete,
        };
        self.reaper.ready.notify_one();
    }
}

async fn execute_native<P: NativeChild>(
    config: &RouterConfig,
    command: NativeCommand,
    spawn: impl FnOnce(Command) -> io::Result<P>,
    limits: NativeLimits,
) -> Result<Value, NativeExecError> {
    let deadline = tokio::time::Instant::now() + limits.timeout;
    let not_started = |_| NativeExecError {
        code: "spawn",
        started: false,
    };
    let mut guard = ChildGuard::new().map_err(not_started)?;
    // The guard and its cleanup worker already exist. After std OS launch,
    // immediately install ownership before any fallible pipe/reactor setup.
    guard.child = Some(spawn(native_process_command(config, &command)).map_err(not_started)?);
    let failed = |code| NativeExecError {
        code,
        started: true,
    };
    let result = tokio::time::timeout_at(deadline, async {
        let child = guard.child.as_mut().ok_or_else(|| failed("process"))?;
        let stdout = child
            .take_stdout()
            .map_err(|_| failed("stdout-pipe"))?
            .ok_or_else(|| failed("stdout-pipe"))?;
        let stderr = child
            .take_stderr()
            .map_err(|_| failed("stderr-pipe"))?
            .ok_or_else(|| failed("stderr-pipe"))?;
        let (bytes, (), ()) = tokio::try_join!(
            async {
                collect_bounded(stdout, limits.output_bytes)
                    .await
                    .map_err(|error| {
                        failed(if error.kind() == io::ErrorKind::InvalidData {
                            "output-budget"
                        } else {
                            "stdout-read"
                        })
                    })
            },
            async { empty_stderr(stderr).await.map_err(|_| failed("stderr")) },
            async {
                match child.wait().await {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(failed("exit-status")),
                    Err(_) => Err(failed("wait")),
                }
            },
        )?;
        Ok(bytes)
    })
    .await
    .unwrap_or_else(|_| Err(failed("timeout")));

    let bytes = match result {
        Ok(bytes) => {
            // All streams reached EOF and wait succeeded: already reaped.
            guard.child.take();
            bytes
        }
        Err(error) => {
            guard.terminate(deadline).await;
            return Err(error);
        }
    };
    decode_envelope(&bytes, command.request).map_err(|error| failed(error.code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::RouterConfig;
    use crate::ssh::SshSessionManager;
    use crate::ssh::{NativeCommand, NativeCommandKind, NativeExecutor, NativeRegistration};
    use futures::{poll, FutureExt};
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
    use tokio::process::Command;
    use tokio::sync::Notify;
    use uuid::Uuid;

    // All process fixtures are synthetic. Only the OS spawn/wait/kill boundary
    // is replaced; command building, collectors, lifecycle and leases stay real.
    #[derive(Default)]
    struct ProcessStats {
        attempts: AtomicUsize,
        killed: AtomicUsize,
        reaped: AtomicUsize,
        unreaped_drops: AtomicUsize,
        waiting: Notify,
        cleanup: Notify,
        reap_complete: (Mutex<bool>, std::sync::Condvar),
        target: Mutex<Option<(String, String)>>,
    }

    impl ProcessStats {
        fn mark_reaped(&self) {
            self.reaped.fetch_add(1, Ordering::SeqCst);
            *self.reap_complete.0.lock().unwrap() = true;
            self.reap_complete.1.notify_one();
            self.cleanup.notify_one();
        }
    }

    struct PendingReader;

    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    type Reader = Box<dyn AsyncRead + Unpin + Send>;

    #[derive(Default)]
    struct ReapGate {
        released: Mutex<bool>,
        async_ready: Notify,
        blocking_ready: std::sync::Condvar,
    }

    impl ReapGate {
        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.async_ready.notify_one();
            self.blocking_ready.notify_one();
        }

        async fn wait(&self) {
            while !*self.released.lock().unwrap() {
                self.async_ready.notified().await;
            }
        }

        fn wait_blocking(&self) {
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.blocking_ready.wait(released).unwrap();
            }
        }
    }

    struct FakeChild {
        stdout: Option<Reader>,
        stderr: Option<Reader>,
        success: bool,
        hang: bool,
        killed: bool,
        setup_error: bool,
        reap_gate: Option<Arc<ReapGate>>,
        stats: Arc<ProcessStats>,
    }

    impl Drop for FakeChild {
        fn drop(&mut self) {
            if self.stats.reaped.load(Ordering::SeqCst) == 0 {
                self.stats.unreaped_drops.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    impl NativeChild for FakeChild {
        type Stdout = Reader;
        type Stderr = Reader;

        fn take_stdout(&mut self) -> io::Result<Option<Reader>> {
            if self.setup_error {
                return Err(io::Error::other("SENTINEL_MD5 async pipe setup"));
            }
            Ok(self.stdout.take())
        }

        fn take_stderr(&mut self) -> io::Result<Option<Reader>> {
            Ok(self.stderr.take())
        }

        fn wait(&mut self) -> ProcessFuture<'_, bool> {
            Box::pin(async move {
                self.stats.waiting.notify_one();
                if self.hang && !self.killed {
                    std::future::pending::<()>().await;
                }
                if let Some(gate) = &self.reap_gate {
                    gate.wait().await;
                }
                self.stats.mark_reaped();
                Ok(self.success)
            })
        }

        fn start_kill(&mut self) -> io::Result<()> {
            self.killed = true;
            self.stats.killed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn wait_blocking(&mut self) -> io::Result<()> {
            if let Some(gate) = &self.reap_gate {
                gate.wait_blocking();
            }
            self.stats.mark_reaped();
            Ok(())
        }
    }

    fn fake(
        stats: &Arc<ProcessStats>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        success: bool,
    ) -> impl FnOnce(Command) -> io::Result<FakeChild> {
        let stats = Arc::clone(stats);
        move |cmd| {
            stats.attempts.fetch_add(1, Ordering::SeqCst);
            let args: Vec<_> = cmd.as_std().get_args().collect();
            *stats.target.lock().unwrap() = Some((
                args[args.len() - 2].to_string_lossy().into_owned(),
                cmd.as_std()
                    .get_envs()
                    .find(|(key, _)| *key == "SSHPASS")
                    .and_then(|(_, value)| value)
                    .map(|value| value.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ));
            Ok(FakeChild {
                stdout: Some(Box::new(std::io::Cursor::new(stdout))),
                stderr: Some(Box::new(std::io::Cursor::new(stderr))),
                success,
                hang: false,
                killed: false,
                setup_error: false,
                reap_gate: None,
                stats,
            })
        }
    }

    fn hanging(stats: &Arc<ProcessStats>) -> impl FnOnce(Command) -> io::Result<FakeChild> {
        let stats = Arc::clone(stats);
        move |_| {
            stats.attempts.fetch_add(1, Ordering::SeqCst);
            Ok(FakeChild {
                stdout: Some(Box::new(PendingReader)),
                stderr: Some(Box::new(PendingReader)),
                success: false,
                hang: true,
                killed: false,
                setup_error: false,
                reap_gate: None,
                stats,
            })
        }
    }

    fn command() -> NativeCommand {
        NativeCommand::checked(
            Uuid::nil(),
            "neighbor.patch",
            NativeCommandKind::Mutation,
            ":put \"SENTINEL_MD5\"".into(),
        )
        .unwrap()
    }

    fn envelope() -> Vec<u8> {
        br#"{"request":"00000000-0000-0000-0000-000000000000","ok":true,"data":{"value":"001234"}}"#
            .to_vec()
    }

    #[tokio::test]
    async fn mikrotik_stream_budget_is_not_silent_truncation() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let writing = tokio::spawn(async move { writer.write_all(b"12345").await.unwrap() });
        assert_eq!(
            collect_bounded(reader, 4).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        writing.await.unwrap();
        assert_eq!(collect_bounded(&b"1234"[..], 4).await.unwrap(), b"1234");
        assert!(collect_bounded(&b""[..], 0).await.unwrap().is_empty());
    }

    #[test]
    fn mikrotik_command_debug_never_contains_payload() {
        assert!(!format!("{:?}", command()).contains("SENTINEL_MD5"));
    }

    #[test]
    fn mikrotik_command_checks_single_line_controls_and_utf8_byte_budget() {
        for script in ["a\nb", "a\rb", "a\0b", "a\tb", "a\u{1b}b", "a\u{7f}b"] {
            let error =
                NativeCommand::checked(Uuid::nil(), "read", NativeCommandKind::Read, script.into())
                    .unwrap_err();
            assert!(!format!("{error:?}").contains(script));
        }
        for script in ["x".repeat(32769), "α".repeat(16385)] {
            assert!(
                NativeCommand::checked(Uuid::nil(), "read", NativeCommandKind::Read, script)
                    .is_err()
            );
        }
        for script in [
            "x".repeat(32768),
            "α".repeat(16384),
            r#":put "a\nb""#.into(),
        ] {
            assert!(
                NativeCommand::checked(Uuid::nil(), "read", NativeCommandKind::Read, script)
                    .is_ok()
            );
        }
    }

    #[test]
    fn mikrotik_command_uses_existing_auth_options_one_remote_arg_and_no_shell() {
        for password in [None, Some("SENTINEL_MD5".to_owned())] {
            let cfg = RouterConfig {
                hostname: "reviewed.example".into(),
                password,
                ..Default::default()
            };
            let cmd = native_process_command(&cfg, &command());
            let args: Vec<_> = cmd
                .as_std()
                .get_args()
                .map(|arg| arg.to_str().unwrap())
                .collect();
            let mut expected = vec![];
            if cfg.password.is_some() {
                expected.extend(["-e", "ssh"]);
            }
            expected.extend([
                "-p",
                "22",
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
                "ControlPath=/tmp/bgp-lm-%C",
                "-o",
                "ControlPersist=600",
                "-o",
                if cfg.password.is_some() {
                    "PreferredAuthentications=password,keyboard-interactive"
                } else {
                    "BatchMode=yes"
                },
                "admin@reviewed.example",
                ":put \"SENTINEL_MD5\"",
            ]);
            assert_eq!(args, expected);
            assert_eq!(
                cmd.as_std().get_program(),
                if cfg.password.is_some() {
                    "sshpass"
                } else {
                    "ssh"
                }
            );
            assert!(cmd.get_kill_on_drop());
        }
    }

    #[tokio::test]
    async fn mikrotik_transport_accepts_only_success_empty_stderr_matching_complete_envelope() {
        let cfg = RouterConfig::default();
        let cases = [
            (b"SENTINEL_MD5 error text".to_vec(), vec![], true, "invalid-envelope"),
            (envelope(), vec![], false, "exit-status"),
            (envelope(), b"SENTINEL_MD5".to_vec(), true, "stderr"),
            (vec![], vec![], true, "invalid-envelope"),
            ([envelope(), envelope()].concat(), vec![], true, "invalid-envelope"),
            (br#"{"request":"other","ok":true,"data":[]}"#.to_vec(), vec![], true, "request-mismatch"),
            (br#"{"request":"00000000-0000-0000-0000-000000000000","ok":false,"data":"SENTINEL_MD5"}"#.to_vec(), vec![], true, "command-rejected"),
            (vec![b'x'; 1025], vec![], true, "output-budget"),
            (envelope(), vec![b'x'; 1025], true, "stderr"),
            (envelope(), b"mux_client_request_session: SENTINEL_MD5".to_vec(), false, "stderr"),
        ];
        for (stdout, stderr, success, code) in cases {
            let stats = Arc::new(ProcessStats::default());
            let error = execute_native(
                &cfg,
                command(),
                fake(&stats, stdout, stderr, success),
                NativeLimits {
                    output_bytes: 1024,
                    timeout: Duration::from_secs(30),
                },
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, code);
            assert!(error.started);
            assert!(!format!("{error:?} {error}").contains("SENTINEL_MD5"));
            assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
            assert!(stats.reaped.load(Ordering::SeqCst) >= 1);
        }
        let stats = Arc::new(ProcessStats::default());
        let result = execute_native(
            &cfg,
            command(),
            fake(&stats, envelope(), vec![], true),
            NativeLimits::PRODUCTION,
        )
        .await
        .unwrap();
        assert_eq!(result, serde_json::json!({"value":"001234"}));
        assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(stats.killed.load(Ordering::SeqCst), 0);
        assert_eq!(stats.reaped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mikrotik_transport_first_stderr_byte_aborts_indefinitely_waiting_child() {
        let stats = Arc::new(ProcessStats::default());
        let child_stats = Arc::clone(&stats);
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"SENTINEL_MD5").await.unwrap();
        let error = execute_native(
            &RouterConfig::default(),
            command(),
            move |cmd| {
                let mut child = hanging(&child_stats)(cmd)?;
                child.stderr = Some(Box::new(reader));
                Ok(child)
            },
            NativeLimits::PRODUCTION,
        )
        .now_or_never()
        .expect("first stderr byte waited for EOF or child exit")
        .unwrap_err();
        drop(writer);
        assert_eq!(error.code, "stderr");
        assert!(error.started);
        assert_eq!(stats.killed.load(Ordering::SeqCst), 1);
        assert_eq!(stats.reaped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mikrotik_transport_timeout_kills_and_reaps_uncertain_mutation_once() {
        let stats = Arc::new(ProcessStats::default());
        let error = execute_native(
            &RouterConfig::default(),
            command(),
            hanging(&stats),
            NativeLimits {
                output_bytes: 1024,
                timeout: Duration::ZERO,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "timeout");
        assert!(error.started);
        assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(stats.killed.load(Ordering::SeqCst), 1);
        assert_eq!(stats.reaped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mikrotik_transport_cancellation_schedules_kill_and_reap() {
        let stats = Arc::new(ProcessStats::default());
        let task_stats = Arc::clone(&stats);
        let task = tokio::spawn(async move {
            execute_native(
                &RouterConfig::default(),
                command(),
                hanging(&task_stats),
                NativeLimits::PRODUCTION,
            )
            .await
        });
        stats.waiting.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        stats.cleanup.notified().await;
        assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(stats.killed.load(Ordering::SeqCst), 1);
        assert_eq!(stats.reaped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mikrotik_transport_sec01_setup_failure_after_os_launch_keeps_cleanup_owner() {
        let stats = Arc::new(ProcessStats::default());
        let error = execute_native(
            &RouterConfig::default(),
            command(),
            |cmd| {
                // Return the modeled OS child; production now owns it before
                // the fallible async pipe conversion (take_stdout) is invoked.
                let mut child = fake(&stats, envelope(), vec![], true)(cmd)?;
                child.setup_error = true;
                Ok(child)
            },
            NativeLimits::PRODUCTION,
        )
        .await
        .unwrap_err();
        assert!(
            error.started,
            "post-OS-launch error was classified not started"
        );
        assert_eq!(error.code, "stdout-pipe");
        assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(stats.killed.load(Ordering::SeqCst), 1);
        assert_eq!(stats.reaped.load(Ordering::SeqCst), 1);
        assert_eq!(stats.unreaped_drops.load(Ordering::SeqCst), 0);
        assert!(!format!("{error:?} {error}").contains("SENTINEL_MD5"));
    }

    #[tokio::test]
    async fn mikrotik_transport_sec02_delayed_reap_does_not_extend_foreground_deadline() {
        let cfg = router("reviewed.example");
        let manager = SshSessionManager::new(std::slice::from_ref(&cfg));
        let token = manager.native_registration(cfg.id).await.unwrap();
        let lease = manager.native_lease(&token).await.unwrap();
        let stats = Arc::new(ProcessStats::default());
        let gate = Arc::new(ReapGate::default());
        let child_gate = Arc::clone(&gate);
        let execution = lease.exec_with(
            command(),
            |cmd| {
                let mut child = hanging(&stats)(cmd)?;
                child.reap_gate = Some(child_gate);
                Ok(child)
            },
            NativeLimits {
                output_bytes: 1024,
                timeout: Duration::ZERO,
            },
        );
        // Safety bound only: no sleeping, and no extra production cleanup grace.
        let result = tokio::time::timeout(Duration::from_secs(1), execution).await;
        let retained_before_release = stats.unreaped_drops.load(Ordering::SeqCst) == 0;
        let not_yet_reaped = stats.reaped.load(Ordering::SeqCst) == 0;
        drop(lease);
        let replacement = manager
            .native_lease(&token)
            .now_or_never()
            .unwrap()
            .unwrap();
        drop(replacement);
        gate.release();
        tokio::time::timeout(Duration::from_secs(1), stats.cleanup.notified())
            .await
            .expect("eventual reap was not retained");
        assert!(
            result.is_ok(),
            "foreground reap escaped the command deadline"
        );
        let error = result.unwrap().unwrap_err();
        assert_eq!(error.code, "timeout");
        assert!(error.started);
        assert!(retained_before_release);
        assert!(not_yet_reaped);
        assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
        assert!(stats.killed.load(Ordering::SeqCst) >= 1);
        assert_eq!(stats.reaped.load(Ordering::SeqCst), 1);
        assert_eq!(stats.unreaped_drops.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mikrotik_transport_cleanup_owner_survives_tokio_shutdown() {
        let stats = Arc::new(ProcessStats::default());
        let gate = Arc::new(ReapGate::default());
        let child_gate = Arc::clone(&gate);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(1),
                execute_native(
                    &RouterConfig::default(),
                    command(),
                    |cmd| {
                        let mut child = hanging(&stats)(cmd)?;
                        child.reap_gate = Some(child_gate);
                        Ok(child)
                    },
                    NativeLimits {
                        output_bytes: 1024,
                        timeout: Duration::ZERO,
                    },
                ),
            )
            .await
            .expect("foreground cleanup blocked runtime shutdown")
            .unwrap_err()
        });
        drop(runtime);
        let retained = stats.unreaped_drops.load(Ordering::SeqCst) == 0;
        let not_yet_reaped = stats.reaped.load(Ordering::SeqCst) == 0;
        gate.release();
        // Outside every Tokio runtime: the same production cleanup worker must
        // still own the modeled child and complete its blocking reap.
        let (complete, _) = stats
            .reap_complete
            .1
            .wait_timeout_while(
                stats.reap_complete.0.lock().unwrap(),
                Duration::from_secs(1),
                |done| !*done,
            )
            .unwrap();
        assert!(*complete, "shutdown lost the child cleanup owner");
        assert!(error.started);
        assert_eq!(error.code, "timeout");
        assert!(retained);
        assert!(not_yet_reaped);
        assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(stats.killed.load(Ordering::SeqCst), 1);
        assert_eq!(stats.reaped.load(Ordering::SeqCst), 1);
        assert_eq!(stats.unreaped_drops.load(Ordering::SeqCst), 0);
    }

    #[derive(Clone, Default)]
    struct LogBuffer(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for LogBuffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn mikrotik_transport_redacts_stdout_stderr_spawn_and_reader_errors() {
        use tracing::instrument::WithSubscriber;
        let log = LogBuffer::default();
        let writer = log.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || writer.clone())
            .finish();
        async {
            let cfg = RouterConfig {
                password: Some("SENTINEL_MD5".into()),
                ..Default::default()
            };
            for (stdout, stderr) in [
                (b"SENTINEL_MD5".to_vec(), vec![]),
                (envelope(), b"SENTINEL_MD5".to_vec()),
            ] {
                let stats = Arc::new(ProcessStats::default());
                let error = execute_native(
                    &cfg,
                    command(),
                    fake(&stats, stdout, stderr, true),
                    NativeLimits::PRODUCTION,
                )
                .await
                .unwrap_err();
                assert!(!format!("{error:?} {error}").contains("SENTINEL_MD5"));
            }
            let stats = Arc::new(ProcessStats::default());
            let error = execute_native(
                &cfg,
                command(),
                |_| -> io::Result<FakeChild> {
                    stats.attempts.fetch_add(1, Ordering::SeqCst);
                    Err(io::Error::other("SENTINEL_MD5"))
                },
                NativeLimits::PRODUCTION,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "spawn");
            assert!(!error.started);
            assert!(!format!("{error:?} {error}").contains("SENTINEL_MD5"));
            assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
            assert_eq!(stats.killed.load(Ordering::SeqCst), 0);
            assert_eq!(stats.reaped.load(Ordering::SeqCst), 0);

            struct ErrorReader;
            impl AsyncRead for ErrorReader {
                fn poll_read(
                    self: Pin<&mut Self>,
                    _: &mut std::task::Context<'_>,
                    _: &mut ReadBuf<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Err(io::Error::other("SENTINEL_MD5")))
                }
            }
            let stats = Arc::new(ProcessStats::default());
            let error = execute_native(
                &cfg,
                command(),
                |cmd| {
                    let mut child = fake(&stats, vec![], vec![], true)(cmd)?;
                    child.stdout = Some(Box::new(ErrorReader));
                    Ok(child)
                },
                NativeLimits::PRODUCTION,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "stdout-read");
            assert!(!format!("{error:?} {error}").contains("SENTINEL_MD5"));
        }
        .with_subscriber(subscriber)
        .await;
        let bytes = log.0.lock().unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("SENTINEL_MD5"));
    }

    fn router(hostname: &str) -> RouterConfig {
        RouterConfig {
            hostname: hostname.into(),
            ..Default::default()
        }
    }

    async fn waiting_lease(
        manager: &Arc<SshSessionManager>,
        token: &NativeRegistration,
    ) -> tokio::task::JoinHandle<Result<NativeLease>> {
        let manager = Arc::clone(manager);
        let token = token.clone();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let waiting = manager.native_lease(&token);
            tokio::pin!(waiting);
            assert!(poll!(&mut waiting).is_pending());
            // A real pending acquisition is the scheduling barrier, not a sleep.
            entered.send(()).unwrap();
            waiting.await
        });
        ready.await.unwrap();
        task
    }

    #[tokio::test]
    async fn mikrotik_endpoint_same_endpoint_serializes_different_uuid_and_distinct_endpoints_do_not(
    ) {
        let first = router("same.example");
        let second = router("same.example");
        let third = router("other.example");
        let manager = SshSessionManager::new(&[first.clone(), second.clone(), third.clone()]);
        let one = manager.native_registration(first.id).await.unwrap();
        let two = manager.native_registration(second.id).await.unwrap();
        let three = manager.native_registration(third.id).await.unwrap();
        let lease = manager.native_lease(&one).await.unwrap();
        let waiting = manager.native_lease(&two);
        tokio::pin!(waiting);
        assert!(poll!(&mut waiting).is_pending());
        let independent = manager
            .native_lease(&three)
            .now_or_never()
            .unwrap()
            .unwrap();
        drop(independent);
        let NativeLease { permit, .. } = lease;
        drop(permit);
        assert_eq!(waiting.await.unwrap().registration(), &two);
    }

    #[tokio::test]
    async fn mikrotik_endpoint_exact_port_and_username_are_independent() {
        let first = router("same.example");
        let mut second = router("same.example");
        second.ssh_port = 2222;
        let mut third = router("same.example");
        third.username = "other-user".into();
        let manager = SshSessionManager::new(&[first.clone(), second.clone(), third.clone()]);
        let one = manager.native_registration(first.id).await.unwrap();
        let held = manager.native_lease(&one).await.unwrap();
        for id in [second.id, third.id] {
            let token = manager.native_registration(id).await.unwrap();
            let lease = manager
                .native_lease(&token)
                .now_or_never()
                .unwrap()
                .unwrap();
            assert_eq!(lease.registration(), &token);
        }
        drop(held);
    }

    #[tokio::test]
    async fn mikrotik_endpoint_registration_rejects_change_before_acquisition_and_forged_endpoint()
    {
        let cfg = router("reviewed.example");
        let manager = SshSessionManager::new(std::slice::from_ref(&cfg));
        let token = manager.native_registration(cfg.id).await.unwrap();
        let mut forged = token.clone();
        forged.endpoint.hostname = "wrong.example".into();
        assert!(manager.native_lease(&forged).await.is_err());
        let held = manager.native_lease(&token).await.unwrap();
        let mut changed = cfg.clone();
        changed.hostname = "replacement.example".into();
        manager.register_router(changed).await;
        // A stale token must reject BEFORE waiting, even while its reviewed
        // endpoint is still busy. Removing the first check would deadlock here.
        let error = manager
            .native_lease(&token)
            .now_or_never()
            .expect("stale token waited on endpoint")
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "stale-native-registration");
        assert_ne!(
            manager.native_registration(cfg.id).await.unwrap().revision,
            token.revision
        );
        drop(held);
    }

    #[tokio::test]
    async fn mikrotik_endpoint_registration_rechecks_after_expected_lock_wait() {
        let blocker = router("reviewed.example");
        let cfg = router("reviewed.example");
        let manager = SshSessionManager::new(&[blocker.clone(), cfg.clone()]);
        let blocking_token = manager.native_registration(blocker.id).await.unwrap();
        let token = manager.native_registration(cfg.id).await.unwrap();
        let held = manager.native_lease(&blocking_token).await.unwrap();
        let waiting = waiting_lease(&manager, &token).await;
        let mut changed = cfg;
        changed.hostname = "replacement.example".into();
        manager.register_router(changed).await;
        drop(held);
        assert_eq!(
            waiting.await.unwrap().err().unwrap().to_string(),
            "stale-native-registration"
        );
    }

    #[tokio::test]
    async fn mikrotik_endpoint_credential_config_replacement_and_removal_invalidate_waiters() {
        for replacement in [0, 1, 2, 3] {
            let cfg = router("reviewed.example");
            let manager = SshSessionManager::new(std::slice::from_ref(&cfg));
            let token = manager.native_registration(cfg.id).await.unwrap();
            let held = manager.native_lease(&token).await.unwrap();
            let waiting = waiting_lease(&manager, &token).await;
            let mut changed = cfg.clone();
            match replacement {
                0 => changed.password = Some("SENTINEL_MD5".into()),
                1 => changed.vdom = Some("reviewed-instance".into()),
                2 => {} // Even an identical replacement renews the revision.
                _ => manager.unregister_router(cfg.id).await,
            }
            if replacement != 3 {
                manager.register_router(changed).await;
            }
            drop(held);
            assert_eq!(
                waiting.await.unwrap().err().unwrap().to_string(),
                "stale-native-registration"
            );
            assert!(manager.native_lease(&token).await.is_err());
            if replacement == 3 {
                assert!(manager.native_registration(cfg.id).await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn mikrotik_endpoint_lease_exec_pins_reviewed_config_and_rechecks_each_command() {
        let mut cfg = router("reviewed.example");
        cfg.password = Some("reviewed-password".into());
        let manager = SshSessionManager::new(std::slice::from_ref(&cfg));
        let token = manager.native_registration(cfg.id).await.unwrap();
        let lease = manager.native_lease(&token).await.unwrap();
        let stats = Arc::new(ProcessStats::default());
        let result = lease
            .exec_with(
                command(),
                fake(&stats, envelope(), vec![], true),
                NativeLimits::PRODUCTION,
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({"value":"001234"}));
        assert_eq!(
            stats.target.lock().unwrap().as_ref().unwrap(),
            &("admin@reviewed.example".into(), "reviewed-password".into())
        );
        cfg.hostname = "replacement.example".into();
        cfg.password = Some("replacement-password".into());
        manager.register_router(cfg).await;
        let error = lease
            .exec_with(
                command(),
                fake(&stats, envelope(), vec![], true),
                NativeLimits::PRODUCTION,
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, "stale-native-registration");
        assert!(!error.started);
        assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(lease.registration(), &token);
        manager.unregister_router(token.router_id).await;
        let future: crate::ssh::NativeFuture<'_> = NativeExecutor::exec(&lease, command());
        let error: crate::ssh::NativeExecError = future.await.unwrap_err();
        assert_eq!(error.code, "stale-native-registration");
        assert!(!error.started);
    }

    #[tokio::test]
    async fn mikrotik_endpoint_final_check_launch_race_can_only_target_pinned_endpoint() {
        let cfg = router("reviewed.example");
        let manager = SshSessionManager::new(std::slice::from_ref(&cfg));
        let token = manager.native_registration(cfg.id).await.unwrap();
        let lease = manager.native_lease(&token).await.unwrap();
        let stats = Arc::new(ProcessStats::default());
        let result = lease
            .exec_with(
                command(),
                |cmd| {
                    // The spawn callback is the exact synchronous check/launch boundary.
                    // No async scheduling is required to model a concurrent replacement.
                    let mut registry = manager.sessions.try_write().unwrap();
                    let session = registry.get_mut(&cfg.id).unwrap();
                    session.config.hostname = "replacement.example".into();
                    session.native_revision = Uuid::new_v4();
                    drop(registry);
                    fake(&stats, envelope(), vec![], true)(cmd)
                },
                NativeLimits::PRODUCTION,
            )
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!({"value":"001234"}));
        assert_eq!(
            stats.target.lock().unwrap().as_ref().unwrap().0,
            "admin@reviewed.example"
        );
        assert_eq!(lease.registration(), &token);
        assert!(lease
            .exec_with(
                command(),
                fake(&stats, envelope(), vec![], true),
                NativeLimits::PRODUCTION
            )
            .await
            .is_err());
        assert_eq!(stats.attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn mikrotik_endpoint_tokens_have_no_credentials_and_health_does_not_renew() {
        let cfg = RouterConfig {
            password: Some("SENTINEL_MD5".into()),
            ..router("reviewed.example")
        };
        let manager = SshSessionManager::new(std::slice::from_ref(&cfg));
        let token = manager.native_registration(cfg.id).await.unwrap();
        manager
            .sessions
            .write()
            .await
            .get_mut(&cfg.id)
            .unwrap()
            .state = crate::ssh::SessionState::Ready;
        assert_eq!(manager.native_registration(cfg.id).await.unwrap(), token);
        let wire = serde_json::to_value(&token).unwrap();
        assert_eq!(wire.as_object().unwrap().len(), 3);
        assert_eq!(
            wire["endpoint"],
            serde_json::json!({"hostname":"reviewed.example", "ssh_port":22, "username":"admin"})
        );
        assert!(!format!("{token:?} {wire}").contains("SENTINEL_MD5"));
        assert_eq!(
            serde_json::from_value::<NativeRegistration>(wire).unwrap(),
            token
        );
        manager.unregister_router(cfg.id).await;
        manager.register_router(cfg).await;
        assert_ne!(
            manager
                .native_registration(token.router_id)
                .await
                .unwrap()
                .revision,
            token.revision
        );
        assert!(manager.native_lease(&token).await.is_err());
    }
}
