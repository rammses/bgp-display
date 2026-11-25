use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::ssh::NativeRegistration;

pub type Properties = BTreeMap<String, Value>;

/// Observed source values are retained verbatim, including unknown properties.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeRecord {
    #[serde(rename = ".id")]
    pub id: String,
    #[serde(flatten)]
    pub props: Properties,
}

/// No `Default`: an unavailable collection must not become a complete empty read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeInventory {
    pub version: String,
    pub instances: Vec<NativeRecord>,
    pub connections: Vec<NativeRecord>,
    pub templates: Vec<NativeRecord>,
    pub sessions: Vec<NativeRecord>,
    pub rules: Vec<NativeRecord>,
    pub bgp_reference_inventory_complete: bool,
    /// Positive observations only. Nested script/other-protocol consumers are
    /// unknown even when the direct BGP reference inventory is complete; this
    /// is never a complete dependency audit or a no-consumers assertion.
    pub known_other_protocol_chains: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEligibility {
    Main,
    ReadOnly(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigGuard(pub Properties);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeConnectionRef {
    pub instance: String,
    pub name: String,
    pub observed_id: String,
    pub generation: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePeerRow {
    pub connection: Option<NativeConnectionRef>,
    pub session_id: Option<String>,
    pub record: NativeRecord,
    pub session: Option<NativeRecord>,
    pub scope: ScopeEligibility,
    pub read_only_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeRead<T> {
    Available(T),
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MikroTikSnapshot {
    pub router_id: Uuid,
    pub registration: NativeRegistration,
    pub request: Uuid,
    pub generation: Uuid,
    pub instance: String,
    pub inventory: NativeInventory,
    /// For incomplete reference reads this is an explicit non-actionable marker,
    /// not a configuration guard: it has completeness=false and no config rows.
    /// `config_guard` still rejects that inventory; actions must never accept it.
    pub guard: ConfigGuard,
    pub peers: Vec<NativePeerRow>,
    pub routes: NativeRead<Vec<NativeRecord>>,
    pub advertisements: NativeRead<Vec<NativeRecord>>,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// The approved Task3 caller contract returns Snapshot(MikroTikSnapshot), not a
// boxed variant. Keep that boundary verbatim rather than silently changing it.
#[expect(
    clippy::large_enum_variant,
    reason = "approved inline native discovery DTO contract"
)]
pub enum NativeDiscovery {
    Instances {
        router_id: Uuid,
        registration: NativeRegistration,
        request: Uuid,
        names: Vec<String>,
    },
    Snapshot(MikroTikSnapshot),
}

/// Only fixed client codes cross the wire-error boundary; never device text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeWireError {
    pub code: &'static str,
}

impl std::fmt::Display for NativeWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for NativeWireError {}

#[cfg(test)]
mod tests {
    use crate::router::mikrotik::{NativeConnectionRef, NativeRecord};
    use serde_json::json;

    // Synthetic, documentation-derived records, not captured device output.
    #[test]
    fn mikrotik_model_preserves_native_ids_unknown_values_and_source_text() {
        let source = json!({
            ".id": "*A0F", "name": "peer-1", "instance": "blue",
            "as": "001234", "comment": "α\u{1b}[2J\n\"\\$",
            "vendor.future": {"values": [null, false, "0007", 9]}
        });
        let record: NativeRecord = serde_json::from_value(source.clone()).unwrap();
        assert_eq!(record.id, "*A0F");
        assert_eq!(record.props["as"], "001234");
        assert_eq!(record.props["comment"], "α\u{1b}[2J\n\"\\$");
        assert_eq!(record, record.clone());
        assert_eq!(serde_json::to_value(record).unwrap(), source);
        for invalid in [json!({"name": "peer"}), json!({".id": 1})] {
            assert!(serde_json::from_value::<NativeRecord>(invalid).is_err());
        }
    }

    #[test]
    fn mikrotik_model_connection_reference_keeps_generation_and_scoped_identity() {
        let reference = NativeConnectionRef {
            instance: "blue".into(),
            name: "peer-1".into(),
            observed_id: "*FF".into(),
            generation: uuid::Uuid::nil(),
        };
        assert_eq!(reference, reference.clone());
        let mut replaced = reference.clone();
        replaced.generation = uuid::Uuid::from_u128(1);
        assert_ne!(reference, replaced);
        replaced = reference.clone();
        replaced.instance = "red".into();
        assert_ne!(reference, replaced);
        replaced = reference.clone();
        replaced.observed_id = "*100".into();
        assert_ne!(reference, replaced);
    }
}
