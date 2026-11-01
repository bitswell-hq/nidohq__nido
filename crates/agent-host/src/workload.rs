//! Scripted workloads: a sequence of admin steps and agent tool calls,
//! replayed through a [`Host`].
//!
//! ```json
//! {
//!   "keys": {"key-a": "<Ed25519 seed, 64 hex digits>"},
//!   "steps": [
//!     {"admin": {"issue": {"name": "root", "grants": {"files": [{"path_under": "/srv/work"}]}}}},
//!     {"agent": {"name": "root", "call": {"read_file": {"path": "/srv/work/notes.txt"}}}},
//!     {"agent": {"name": "root", "call": {"delegate": {"add": {"files": [{"mode_in": ["read"]}]}}}, "as": "reader"}},
//!     {"agent": {"name": "reader", "call": {"write_file": {"path": "/srv/work/x", "contents": "hi"}}}},
//!     {"admin": {"revoke": "reader"}}
//!   ]
//! }
//! ```
//!
//! Agents are named by the workload; a `delegate` step's `as` names the
//! sub-agent it starts. Each step yields one [`StepResult`]. Keys go to a
//! [`MemoryKeyKeeper`]; the agents never see them.

use std::collections::BTreeMap;
use std::time::Instant;

use nido_key_keeper::{KeyId, KeyKeeper, MemoryKeyKeeper};
use serde::{Deserialize, Serialize};

use crate::grant::Grants;
use crate::host::{AgentId, CallError, Host, Output, ToolCall};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    /// Key id to Ed25519 seed (hex), for the in-process keeper.
    #[serde(default)]
    pub keys: BTreeMap<String, String>,
    pub steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    Admin(AdminStep),
    Agent(AgentStep),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminStep {
    Issue { name: String, grants: Grants },
    Revoke(String),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStep {
    pub name: String,
    pub call: ToolCall,
    /// For `delegate`: the name the sub-agent gets.
    #[serde(default, rename = "as")]
    pub as_name: Option<String>,
}

/// One step's outcome, as the CLI prints it (one JSON object per line).
#[derive(Debug, Serialize)]
pub struct StepResult {
    pub step: usize,
    /// `allowed`, `denied` or `failed`; admin steps are `allowed` or `failed`.
    pub outcome: &'static str,
    pub detail: String,
    /// Wall time of the step, in microseconds.
    pub micros: u128,
}

/// Build the keeper `workload` names.
///
/// # Errors
///
/// If a seed is not 32 bytes of hex.
pub fn keeper(workload: &Workload) -> Result<MemoryKeyKeeper, String> {
    let mut keeper = MemoryKeyKeeper::new();
    for (id, seed) in &workload.keys {
        let bytes = hex::decode(seed).map_err(|e| format!("key {id}: {e}"))?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("key {id}: a seed is 32 bytes"))?;
        keeper.insert(KeyId::new(id.clone()), seed);
    }
    Ok(keeper)
}

/// Replay `workload`'s steps through `host`, in order. A step never stops
/// the replay; its result says what happened.
pub fn run<K: KeyKeeper>(host: &mut Host<K>, workload: &Workload) -> Vec<StepResult> {
    let mut names: BTreeMap<String, AgentId> = BTreeMap::new();
    let mut results = Vec::with_capacity(workload.steps.len());
    for (step, s) in workload.steps.iter().enumerate() {
        let start = Instant::now();
        let (outcome, detail) = match s {
            Step::Admin(AdminStep::Issue { name, grants }) => match host.issue(grants) {
                Ok(id) => {
                    names.insert(name.clone(), id);
                    ("allowed", format!("issued {name}"))
                }
                Err(e) => ("failed", e),
            },
            Step::Admin(AdminStep::Revoke(name)) => match names.get(name) {
                Some(id) => {
                    host.revoke(*id);
                    ("allowed", format!("revoked {name}"))
                }
                None => ("failed", format!("no agent {name}")),
            },
            Step::Agent(a) => match names.get(&a.name) {
                None => ("failed", format!("no agent {}", a.name)),
                Some(id) => match host.call(*id, &a.call) {
                    Ok(Output::Agent(child)) => {
                        let child_name = a
                            .as_name
                            .clone()
                            .unwrap_or_else(|| format!("{}.{}", a.name, child.0));
                        names.insert(child_name.clone(), child);
                        ("allowed", format!("started {child_name}"))
                    }
                    Ok(output) => ("allowed", describe(&output)),
                    Err(e @ (CallError::Denied { .. } | CallError::Revoked)) => {
                        ("denied", e.to_string())
                    }
                    Err(e) => ("failed", e.to_string()),
                },
            },
        };
        results.push(StepResult {
            step,
            outcome,
            detail,
            micros: start.elapsed().as_micros(),
        });
    }
    results
}

fn describe(output: &Output) -> String {
    match output {
        Output::File(data) => format!("read {} bytes", data.len()),
        Output::Written => "written".into(),
        Output::Response(r) => format!("{} from {} ({} bytes)", r.status, r.url, r.body.len()),
        Output::Signature(s) => format!("signature {}", hex::encode(s)),
        Output::Agent(id) => format!("agent {}", id.0),
    }
}
