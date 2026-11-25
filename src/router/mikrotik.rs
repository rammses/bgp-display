//! Pure native RouterOS foundation; no transport or selectable vendor yet.

// Intentionally staged native APIs acquire real consumers in subsequent tasks.
#![cfg_attr(not(test), allow(dead_code))]

mod codec;
mod model;
mod scope;

#[cfg_attr(not(test), allow(unused_imports))]
pub use codec::{decode_envelope, presentation_text, require_target_version, ros_string};
#[cfg_attr(not(test), allow(unused_imports))]
pub use model::{
    ConfigGuard, NativeConnectionRef, NativeInventory, NativeRecord, NativeWireError, Properties,
    ScopeEligibility,
};
#[cfg_attr(not(test), allow(unused_imports))]
pub use scope::{config_guard, connection_scope};
