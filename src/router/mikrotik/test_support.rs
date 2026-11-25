//! Synthetic documentation-derived fixtures/transcripts, NOT device captures.

use super::{NativeInventory, NativeRecord};
use crate::ssh::{
    NativeCommand, NativeCommandKind, NativeEndpoint, NativeExecError, NativeExecutor,
    NativeFuture, NativeRegistration,
};
use serde_json::{json, Value};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Mutex;
use uuid::Uuid;

pub enum Reply {
    Data(Value),
    Failure { code: &'static str, started: bool },
}

pub struct TranscriptExecutor {
    replies: Mutex<VecDeque<Reply>>,
    seen: Mutex<Vec<(&'static str, NativeCommandKind)>>,
}

impl TranscriptExecutor {
    pub fn new(replies: Vec<Reply>) -> Self {
        Self {
            replies: Mutex::new(replies.into()),
            seen: Mutex::new(Vec::new()),
        }
    }

    pub fn seen_labels(&self) -> Vec<&'static str> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(label, _)| *label)
            .collect()
    }

    pub fn mutation_attempts(&self) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, kind)| *kind == NativeCommandKind::Mutation)
            .count()
    }
}

impl NativeExecutor for TranscriptExecutor {
    fn exec<'a>(&'a self, command: NativeCommand) -> NativeFuture<'a> {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap()
                .push((command.label, command.kind));
            // Only the validated data Value is supplied at this boundary. The
            // real transport already checks request/object/envelope correlation.
            match self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected native transcript exhaustion")
            {
                Reply::Data(data) => Ok(data),
                Reply::Failure { code, started } => Err(NativeExecError { code, started }),
            }
        })
    }
}

pub fn documented_registration() -> NativeRegistration {
    NativeRegistration {
        router_id: Uuid::nil(),
        revision: Uuid::from_u128(1),
        endpoint: NativeEndpoint {
            hostname: "lab.invalid".into(),
            ssh_port: 22,
            username: "tester".into(),
        },
    }
}

pub fn record(value: Value) -> NativeRecord {
    serde_json::from_value(value).unwrap()
}

pub fn documented_inventory() -> NativeInventory {
    // Synthetic documentation-derived, not device captures. Normalized bool
    // flags are intentional fixtures, not claims about unobserved wire keys.
    NativeInventory {
        version: "7.24.7".into(),
        instances: vec![record(json!({".id":"*1", "name":"blue", "as":65000,
            "router-id":"192.0.2.1", "routing-table":"main", "vrf":"main"}))],
        connections: vec![
            record(json!({".id":"*2", "name":"peer-a", "instance":"blue",
                "local.address":"192.0.2.1", "remote.address":"192.0.2.2",
                "remote.as":65001, "local.role":"ebgp", "afi":"ip",
                "input.filter":"blue-in", "output.filter-chain":"blue-out", "disabled":false})),
            record(json!({".id":"*3", "name":"peer-b", "instance":"blue",
                "local.address":"192.0.2.1", "remote.address":"192.0.2.3",
                "remote.as":65001, "local.role":"ebgp", "afi":"ip",
                "input.filter":"blue-in", "output.filter-chain":"blue-out", "disabled":true})),
        ],
        templates: vec![],
        sessions: vec![record(
            json!({".id":"*4", "name":"peer-a-1", "instance":"blue",
            "local.address":"192.0.2.1", "remote.address":"192.0.2.2",
            "remote.as":65001, "established":true}),
        )],
        rules: vec![
            record(json!({".id":"*5", "chain":"blue-in", "rule":"reject;", "disabled":false})),
            record(json!({".id":"*6", "chain":"blue-out", "rule":"reject;", "disabled":false})),
        ],
        bgp_reference_inventory_complete: true,
        // Positively known information only; NOT a complete dependency audit.
        known_other_protocol_chains: BTreeSet::new(),
    }
}
