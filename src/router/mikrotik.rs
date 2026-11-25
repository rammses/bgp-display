//! Native RouterOS monitoring through a pinned SSH lease.

mod codec;
mod model;
mod read;
mod scope;

#[cfg(test)]
pub(crate) mod test_support;

pub use codec::{decode_envelope, presentation_text, require_target_version, ros_string};
pub use model::{
    ConfigGuard, MikroTikSnapshot, NativeConnectionRef, NativeDiscovery, NativeInventory,
    NativePeerRow, NativeRead, NativeRecord, NativeWireError, Properties, ScopeEligibility,
};
pub use read::fetch_native;
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "retained native join/compiler API for guarded consumers and offline fixtures"
    )
)]
pub use read::{join_native_peers, native_read_command, NativeMenu};
pub use scope::{config_guard, connection_scope};

use crate::router::{ConnectionStatus, RouterConfig, RouterVendor};
use crate::ssh::{NativeLease, NativeRegistration, SshSessionManager};
use anyhow::{ensure, Context, Result};
use std::sync::Arc;
use uuid::Uuid;

pub struct MikroTikBackend {
    config: RouterConfig,
    registration: Option<NativeRegistration>,
    ssh: Arc<SshSessionManager>,
    status: ConnectionStatus,
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    use crate::router::mikrotik::test_support::{documented_snapshot, TranscriptExecutor};
    use crate::router::RouterVendor;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn config() -> RouterConfig {
        RouterConfig {
            id: Uuid::nil(),
            hostname: "lab.invalid".into(),
            username: "tester".into(),
            vendor: RouterVendor::MikroTik,
            mikrotik_instance: Some("blue".into()),
            ..RouterConfig::default()
        }
    }

    #[tokio::test]
    async fn mikrotik_cache_discovery_atomic_decision_cannot_retarget_new_registration() {
        for change in ["same-config", "endpoint", "scope", "vendor"] {
            let original = config();
            let ssh = SshSessionManager::new(&[original.clone()]);
            let (captured, registration) = ssh.registered_snapshot(original.id).await.unwrap();
            let backend =
                MikroTikBackend::new_registered(&captured, registration.clone(), Arc::clone(&ssh));
            let mut replacement = original;
            match change {
                "endpoint" => replacement.hostname = "replacement.invalid".into(),
                "scope" => replacement.mikrotik_instance = Some("green".into()),
                "vendor" => replacement.vendor = RouterVendor::Cisco,
                _ => {}
            }
            ssh.register_router(replacement).await;
            let read_called = AtomicBool::new(false);
            let read_flag = &read_called;
            let result = backend
                .discover_bound_with(
                    Uuid::new_v4(),
                    Some("blue"),
                    &registration,
                    |lease, request, _| async move {
                        read_flag.store(true, Ordering::SeqCst);
                        let mut snapshot = documented_snapshot();
                        snapshot.registration = lease.registration().clone();
                        snapshot.request = request;
                        Ok(NativeDiscovery::Snapshot(snapshot))
                    },
                )
                .await;
            assert!(result.is_err());
            assert!(!read_called.load(Ordering::SeqCst));
            assert_eq!(captured.hostname, "lab.invalid");
            assert_eq!(captured.vendor, RouterVendor::MikroTik);
            assert_eq!(registration.endpoint.hostname, "lab.invalid");
            if change != "same-config" {
                assert!(backend.resolve_registration().await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn mikrotik_cache_discovery_scope_mismatch_rejects_before_read() {
        let original = config();
        let ssh = SshSessionManager::new(&[original.clone()]);
        let (captured, registration) = ssh.registered_snapshot(original.id).await.unwrap();
        let backend = MikroTikBackend::new(&captured, ssh);
        let io = TranscriptExecutor::new(vec![]);
        let read_io = &io;
        let result = backend
            .discover_bound_with(
                Uuid::new_v4(),
                Some("green"),
                &registration,
                |lease, request, instance| async move {
                    fetch_native(read_io, lease.registration(), request, instance.as_deref()).await
                },
            )
            .await;
        assert!(result.is_err());
        assert!(io.seen_labels().is_empty());
    }

    #[tokio::test]
    async fn mikrotik_cache_discovery_queued_original_token_and_scope_survive_wait() {
        let original = config();
        let ssh = SshSessionManager::new(&[original.clone()]);
        let (captured, registration) = ssh.registered_snapshot(original.id).await.unwrap();
        let held = ssh.native_lease(&registration).await.unwrap();
        let backend = MikroTikBackend::new(&captured, Arc::clone(&ssh));
        let called = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&called);
        let task = tokio::spawn(async move {
            backend
                .discover_bound_with(
                    Uuid::new_v4(),
                    Some("blue"),
                    &registration,
                    |_, _, _| async move {
                        observed.store(true, Ordering::SeqCst);
                        anyhow::bail!("unexpected read after replacement")
                    },
                )
                .await
        });
        tokio::task::yield_now().await;
        let mut replacement = original;
        replacement.hostname = "other.invalid".into();
        replacement.mikrotik_instance = Some("red".into());
        ssh.register_router(replacement).await;
        drop(held);
        assert!(task.await.unwrap().is_err());
        assert!(!called.load(Ordering::SeqCst));
    }
}

impl MikroTikBackend {
    pub fn new(config: &RouterConfig, ssh: Arc<SshSessionManager>) -> Self {
        Self {
            config: config.clone(),
            registration: None,
            ssh,
            status: ConnectionStatus::Disconnected,
        }
    }

    pub(crate) fn new_registered(
        config: &RouterConfig,
        registration: NativeRegistration,
        ssh: Arc<SshSessionManager>,
    ) -> Self {
        let mut backend = Self::new(config, ssh);
        backend.registration = Some(registration);
        backend
    }

    async fn resolve_registration(&self) -> Result<NativeRegistration> {
        let (config, registration) = self.ssh.registered_snapshot(self.config.id).await?;
        ensure!(
            config == self.config && config.vendor == RouterVendor::MikroTik,
            "native backend configuration changed"
        );
        Ok(registration)
    }

    pub fn status(&self) -> &ConnectionStatus {
        &self.status
    }

    pub async fn connect(&mut self) -> Result<()> {
        let registration = match &self.registration {
            Some(registration) => registration.clone(),
            None => self.resolve_registration().await?,
        };
        let lease = self.ssh.native_lease(&registration).await?;
        crate::ssh::probe_native(&lease).await?;
        self.status = ConnectionStatus::Connected;
        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.status = ConnectionStatus::Disconnected;
        Ok(())
    }

    pub async fn discover(&self, request: Uuid, instance: Option<&str>) -> Result<NativeDiscovery> {
        let registration = match &self.registration {
            Some(registration) => registration.clone(),
            None => self
                .resolve_registration()
                .await
                .context("cannot resolve native registration")?,
        };
        self.discover_bound_with(
            request,
            instance,
            &registration,
            |lease, request, instance| async move {
                fetch_native(&lease, lease.registration(), request, instance.as_deref()).await
            },
        )
        .await
    }

    async fn discover_bound_with<F, Fut>(
        &self,
        request: Uuid,
        instance: Option<&str>,
        registration: &NativeRegistration,
        read: F,
    ) -> Result<NativeDiscovery>
    where
        F: FnOnce(NativeLease, Uuid, Option<String>) -> Fut,
        Fut: std::future::Future<Output = Result<NativeDiscovery>>,
    {
        let selected = instance.filter(|name| !name.trim().is_empty());
        let configured = self
            .config
            .mikrotik_instance
            .as_deref()
            .filter(|name| !name.trim().is_empty());
        ensure!(
            self.config.vendor == RouterVendor::MikroTik
                && self.config.id == registration.router_id
                && self.config.hostname == registration.endpoint.hostname
                && self.config.ssh_port == registration.endpoint.ssh_port
                && self.config.username == registration.endpoint.username,
            "native registration decision mismatch"
        );
        ensure!(selected == configured, "native selected scope changed");
        // One lease covers version, discovery and every optional read. The
        // actual token/configuration is never reconstructed from the UI.
        let lease = self
            .ssh
            .native_lease(registration)
            .await
            .context("cannot acquire native read lease")?;
        read(lease, request, selected.map(str::to_owned)).await
    }
}
