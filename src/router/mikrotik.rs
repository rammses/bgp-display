//! Native RouterOS reads through a pinned SSH lease; no selectable vendor yet.

// Intentionally staged native APIs acquire real consumers in subsequent tasks.
#![cfg_attr(not(test), allow(dead_code))]

mod codec;
mod model;
mod read;
mod scope;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg_attr(not(test), allow(unused_imports))]
pub use codec::{decode_envelope, presentation_text, require_target_version, ros_string};
#[cfg_attr(not(test), allow(unused_imports))]
pub use model::{
    ConfigGuard, MikroTikSnapshot, NativeConnectionRef, NativeDiscovery, NativeInventory,
    NativePeerRow, NativeRead, NativeRecord, NativeWireError, Properties, ScopeEligibility,
};
#[cfg_attr(not(test), allow(unused_imports))]
pub use read::{fetch_native, join_native_peers, native_read_command, NativeMenu};
#[cfg_attr(not(test), allow(unused_imports))]
pub use scope::{config_guard, connection_scope};

use crate::router::RouterConfig;
use crate::ssh::SshSessionManager;
use anyhow::{Context, Result};
use std::sync::Arc;
use uuid::Uuid;

pub struct MikroTikBackend {
    router_id: Uuid,
    ssh: Arc<SshSessionManager>,
}

impl MikroTikBackend {
    pub fn new(config: &RouterConfig, ssh: Arc<SshSessionManager>) -> Self {
        Self {
            router_id: config.id,
            ssh,
        }
    }

    pub async fn discover(&self, request: Uuid, instance: Option<&str>) -> Result<NativeDiscovery> {
        let registration = self
            .ssh
            .native_registration(self.router_id)
            .await
            .context("cannot resolve native registration")?;
        // One lease covers version, discovery and every optional read. The
        // actual token/configuration is never reconstructed from the UI.
        let lease = self
            .ssh
            .native_lease(&registration)
            .await
            .context("cannot acquire native read lease")?;
        fetch_native(&lease, lease.registration(), request, instance).await
    }
}
