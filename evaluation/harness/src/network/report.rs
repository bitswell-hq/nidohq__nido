//! The local-network stage's part of the README's result tables, from the
//! `network-*.json` files `nido-eval network` writes.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

use crate::record;

/// The stage's result files, when the stage has run.
pub struct Results {
    pub attacks: Value,
    pub workloads: Value,
    pub race: Value,
    pub throughput: Value,
    pub conditions: Value,
}

impl Results {
    /// The stage's results in `dir`, or `None` when it has not run there.
    ///
    /// # Errors
    ///
    /// If some but not all of the files are there, or one does not parse.
    pub fn read(dir: &Path) -> Result<Option<Self>, String> {
        if !dir.join("network.json").exists() {
            return Ok(None);
        }
        Ok(Some(Self {
            attacks: record::read(dir, "network-attacks.json")?,
            workloads: record::read(dir, "network-workloads.json")?,
            race: record::read(dir, "network-race.json")?,
            throughput: record::read(dir, "network-throughput.json")?,
            conditions: record::read(dir, "network.json")?,
        }))
    }

    /// The attack rows of the run in `mode`.
    #[must_use]
    pub fn attacks(&self, mode: &str) -> Value {
        by_mode(&self.attacks, mode)
    }

    #[must_use]
    pub fn workloads(&self, mode: &str) -> Value {
        by_mode(&self.workloads, mode)
    }
}

fn by_mode(runs: &Value, mode: &str) -> Value {
    runs.as_array()
        .and_then(|a| a.iter().find(|r| r["mode"] == mode))
        .map_or(Value::Array(Vec::new()), |r| r["rows"].clone())
}

/// The relay modes, as the results name them and the tables label them.
pub const MODES: [(&str, &str); 2] = [
    ("mirrored", "Local network, relay grant mirroring the grant"),
    (
        "pass-through",
        "Local network, relay grant allowing every call",
    ),
];

/// `1234567` as `1,234,567`.
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_owned()
}

fn table(out: &mut String, header: &[&str], rows: &[Vec<String>]) {
    let _ = writeln!(out, "| {} |", header.join(" | "));
    let _ = writeln!(
        out,
        "|{}|",
        header.iter().map(|_| " - ").collect::<Vec<_>>().join("|")
    );
    for r in rows {
        let _ = writeln!(out, "| {} |", r.join(" | "));
    }
    out.push('\n');
}

/// Who refused a row and with what, as one cell.
fn verdict(r: &Value) -> String {
    match s(r, "outcome").as_str() {
        "allowed" if r["control"].as_bool().unwrap_or(false) => "allowed (control)".into(),
        "allowed" if r.get("control").is_some() => "**ALLOWED**".into(),
        "allowed" => "allowed".into(),
        "not_run" => "not run".into(),
        _ => format!(
            "{}: {}",
            s(r, "component"),
            s(r, "error").replace('|', "\\|")
        ),
    }
}

/// Where in the relay's pipeline a row's call stopped.
fn stage(r: &Value) -> &'static str {
    let relay = &r["relay"];
    match (relay["code"].as_str(), relay["settled"].as_str()) {
        (Some("SIMULATION_FAILED"), _) => match relay["details"]["authMode"].as_str() {
            Some("record") => "the relay's recording simulation",
            _ => "the relay's enforcing simulation",
        },
        (Some(_), _) => "the relay's checks",
        (None, Some("confirmed")) => "confirmed on chain",
        (None, Some(_)) => "failed on chain",
        (None, None) => "–",
    }
}

/// The summary lines.
#[allow(clippy::cast_precision_loss)]
pub fn headline(out: &mut String, n: &Results, sim_workloads: &Value) {
    for (mode, label) in MODES {
        let rows = n.attacks(mode);
        let rows = rows.as_array().cloned().unwrap_or_default();
        let attacks: Vec<&Value> = rows
            .iter()
            .filter(|r| !r["control"].as_bool().unwrap_or(false) && s(r, "outcome") != "not_run")
            .collect();
        let refused = attacks
            .iter()
            .filter(|r| s(r, "outcome") == "refused")
            .count();
        let by_relay = attacks
            .iter()
            .filter(|r| s(r, "component") == "relay")
            .count();
        let clean = attacks
            .iter()
            .filter(|r| r["state_unchanged"].as_bool().unwrap_or(false))
            .count();
        let controls = rows
            .iter()
            .filter(|r| r["control"].as_bool().unwrap_or(false))
            .filter(|r| s(r, "outcome") != "not_run")
            .count();
        let not_run = rows.iter().filter(|r| s(r, "outcome") == "not_run").count();
        let _ = writeln!(
            out,
            "- {label}: {} attacks, {refused} refused ({by_relay} by the relay's own checks, the rest in its simulation), {clean} with state unchanged, channel sequence numbers included; {controls} controls confirmed on chain; {not_run} rows not run.",
            attacks.len()
        );
    }
    let mut ratios = Vec::new();
    for (mode, _) in MODES {
        for r in n.workloads(mode).as_array().cloned().unwrap_or_default() {
            let sim = sim_workloads.as_array().and_then(|a| {
                a.iter()
                    .find(|x| x["workload"] == r["workload"] && x["step"] == r["step"])
                    .and_then(|x| x["cpu_instructions"].as_u64())
            });
            if let (Some(chain), Some(sim)) = (r["relay"]["cpu_instructions"].as_u64(), sim) {
                ratios.push(chain as f64 / sim as f64);
            }
        }
    }
    let lo = ratios.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = ratios.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let _ = writeln!(
        out,
        "- On chain, the workloads' {} confirmed transactions cost {:.2}–{:.2} times the CPU instructions the simulation measures for the same calls.",
        ratios.len(),
        lo,
        hi
    );
    let points = n.throughput["points"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let rate = |c: u64| {
        points
            .iter()
            .find(|p| p["channels"].as_u64() == Some(c))
            .and_then(|p| p["confirmed_per_second"].as_f64())
            .unwrap_or_default()
    };
    let _ = writeln!(
        out,
        "- Relay throughput: {:.2} confirmed transactions per second with 1 channel, {:.2} with 8, ledgers closing every {:.1} s.",
        rate(1),
        rate(8),
        n.throughput["ledger_interval_seconds"].as_f64().unwrap_or_default()
    );
    let rounds = n.race["rounds"].as_array().cloned().unwrap_or_default();
    let within = rounds
        .iter()
        .filter(|r| r["within_allowance"].as_bool() == Some(true))
        .count();
    let matched = rounds
        .iter()
        .filter(|r| r["charges_match_transfers"].as_bool() == Some(true))
        .count();
    let _ = writeln!(
        out,
        "- Concurrent siblings: in {} rounds, the root's budget node was charged within its allowance in {within} and charges matched the confirmed transfers in {matched}.",
        rounds.len()
    );
}

/// The network's rows of the attack summary table.
#[must_use]
pub fn summary_sets(n: &Results) -> Vec<(&'static str, Value)> {
    MODES
        .iter()
        .map(|(mode, label)| (*label, n.attacks(mode)))
        .collect()
}

/// How long the relay took to answer a submission, by where the call
/// stopped, over every attack and workload call of both runs.
fn answer_times(out: &mut String, n: &Results) {
    let mut by: Vec<(&'static str, Vec<f64>)> = [
        "the relay's checks",
        "the relay's recording simulation",
        "the relay's enforcing simulation",
        "confirmed on chain",
        "failed on chain",
    ]
    .into_iter()
    .map(|s| (s, Vec::new()))
    .collect();
    for (mode, _) in MODES {
        for set in [n.attacks(mode), n.workloads(mode)] {
            for r in set.as_array().cloned().unwrap_or_default() {
                let Some(ms) = r["relay"]["submit_ms"].as_f64() else {
                    continue;
                };
                if let Some((_, v)) = by.iter_mut().find(|(s, _)| *s == stage(&r)) {
                    v.push(ms);
                }
            }
        }
    }
    let rows: Vec<Vec<String>> = by
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(stage, mut v)| {
            v.sort_by(f64::total_cmp);
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let q = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
            vec![
                stage.to_owned(),
                v.len().to_string(),
                format!("{:.1}", q(0.5)),
                format!("{:.1}", q(0.9)),
                format!("{:.1}", v[v.len() - 1]),
            ]
        })
        .collect();
    let _ = writeln!(
        out,
        "**Relay answer time** (ms from posting a call to the relay's answer: a refusal, or `submitted` once the transaction is signed and sent; every attack and workload call of both runs)\n"
    );
    table(
        out,
        &[
            "Stopped at",
            "Calls",
            "Median",
            "90th percentile",
            "Largest",
        ],
        &rows,
    );
}

/// Run conditions, the attack table, the workloads, the concurrent siblings
/// and throughput.
#[allow(clippy::too_many_lines)]
pub fn section(out: &mut String, n: &Results, sim_attacks: &Value, sim_workloads: &Value) {
    let _ = writeln!(out, "### Local network through the relay\n");
    let c = &n.conditions;
    let cell = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_owned);
    table(
        out,
        &["", ""],
        &[
            vec!["machine".into(), cell(&c["machine_cpu"])],
            vec!["Docker".into(), cell(&c["docker"])],
            vec!["image".into(), cell(&c["quickstart"])],
            vec!["network".into(), cell(&c["network_passphrase"])],
            vec!["protocol".into(), cell(&c["protocol_version"])],
            vec!["stellar-core".into(), cell(&c["core_version"])],
            vec!["Soroban RPC".into(), cell(&c["rpc_version"])],
            vec!["channel accounts".into(), cell(&c["channels"])],
            vec![
                "mean ledger interval (s)".into(),
                format!(
                    "{:.2}",
                    n.throughput["ledger_interval_seconds"]
                        .as_f64()
                        .unwrap_or_default()
                ),
            ],
        ],
    );

    let _ = writeln!(
        out,
        "**Attack suite through the relay.** The same attempts as the simulation's, by the same agents. *Stopped at*: where the call ended, in the mirrored run / the pass-through run. *As in the simulation*: the pass-through run's refusal is the simulation's, component and error.\n"
    );
    let mirrored = n.attacks("mirrored");
    let pass = n.attacks("pass-through");
    let sim = sim_attacks.as_array().cloned().unwrap_or_default();
    let rows: Vec<Vec<String>> = mirrored
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|m| {
            let id = s(m, "id");
            let p = pass
                .as_array()
                .and_then(|a| a.iter().find(|r| s(r, "id") == id))
                .cloned()
                .unwrap_or_default();
            let same = sim.iter().find(|r| s(r, "id") == id).is_some_and(|r| {
                s(r, "outcome") == s(&p, "outcome")
                    && s(r, "component") == s(&p, "component")
                    && s(r, "error") == s(&p, "error")
            });
            let unchanged = |r: &Value| {
                if s(r, "outcome") == "refused" {
                    if r["state_unchanged"].as_bool().unwrap_or(false) {
                        "yes".to_owned()
                    } else {
                        format!("**no**: {}", r["changes"])
                    }
                } else {
                    "–".to_owned()
                }
            };
            vec![
                format!("`{id}`"),
                verdict(m),
                verdict(&p),
                format!("{} / {}", stage(m), stage(&p)),
                if s(&p, "outcome") == "not_run" {
                    "–".into()
                } else if same {
                    "yes".into()
                } else {
                    "**no**".into()
                },
                format!("{} / {}", unchanged(m), unchanged(&p)),
            ]
        })
        .collect();
    table(
        out,
        &[
            "Attempt",
            "Relay grant mirroring the grant",
            "Relay grant allowing every call",
            "Stopped at",
            "As in the simulation",
            "State unchanged",
        ],
        &rows,
    );

    let _ = writeln!(
        out,
        "**Workloads through the relay** (each call one transaction from a channel account; *CPU instructions*: the transaction's host function as the network metered it, in the run with the mirrored grant, and the same call in the simulation)\n"
    );
    let sim_cpu = |m: &Value| {
        sim_workloads
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|r| r["workload"] == m["workload"] && r["step"] == m["step"])
            })
            .and_then(|r| r["cpu_instructions"].as_u64())
    };
    let wm = n.workloads("mirrored");
    let wp = n.workloads("pass-through");
    let rows: Vec<Vec<String>> = wm
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .zip(wp.as_array().cloned().unwrap_or_default().iter())
        .map(|(m, p)| {
            let unchanged = |r: &Value| match r["state_unchanged_if_refused"].as_bool() {
                Some(true) => "yes",
                Some(false) => "**no**",
                None => "–",
            };
            let cpu = |v: Option<u64>| v.map_or_else(|| "–".to_owned(), thousands);
            vec![
                s(m, "workload"),
                s(m, "agent"),
                s(m, "action"),
                s(m, "expected"),
                verdict(m),
                verdict(p),
                format!("{} / {}", unchanged(m), unchanged(p)),
                cpu(m["relay"]["cpu_instructions"].as_u64()),
                cpu(sim_cpu(m)),
            ]
        })
        .collect();
    table(
        out,
        &[
            "Workload",
            "Agent",
            "Call",
            "Expected",
            "Relay grant mirroring the grant",
            "Relay grant allowing every call",
            "Unchanged if refused",
            "CPU instructions on chain",
            "In the simulation",
        ],
        &rows,
    );

    answer_times(out, n);

    let rounds = n.race["rounds"].as_array().cloned().unwrap_or_default();
    if let Some(r0) = rounds.first() {
        let _ = writeln!(
            out,
            "**Concurrent siblings** ({} siblings delegated {} each from a root grant of {}, each sending a transfer of {} at the same instant through the relay, one channel each)\n",
            r0["siblings"], r0["sibling_allowance"], r0["root_allowance"], r0["amount"]
        );
    }
    let rows: Vec<Vec<String>> = rounds
        .iter()
        .map(|r| {
            let sent = r["sent"].as_array().cloned().unwrap_or_default();
            let count = |f: &dyn Fn(&Value) -> bool| sent.iter().filter(|x| f(x)).count();
            let confirmed = count(&|x| x["reply"]["settled"] == "confirmed");
            let failed = count(&|x| x["reply"]["settled"] == "failed");
            let refused = count(&|x| x["reply"]["code"].is_string());
            let mut errors: Vec<String> = sent
                .iter()
                .filter_map(|x| {
                    x["reply"]["chain_failure"]
                        .as_str()
                        .and_then(|e| e.split("grant signer: ").nth(1))
                        .map(str::to_owned)
                })
                .collect();
            errors.sort();
            errors.dedup();
            let mut ledgers: Vec<u64> = sent
                .iter()
                .filter_map(|x| x["reply"]["ledger"].as_u64())
                .collect();
            ledgers.sort_unstable();
            ledgers.dedup();
            vec![
                r["number"].to_string(),
                confirmed.to_string(),
                format!("{failed} ({})", errors.join(", ")),
                refused.to_string(),
                ledgers
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                format!("{} of {}", r["root_spent"], r["root_allowance"]),
                r["account_paid"].to_string(),
                if r["within_allowance"].as_bool() == Some(true)
                    && r["charges_match_transfers"].as_bool() == Some(true)
                    && r["siblings_charged_as_confirmed"].as_bool() == Some(true)
                {
                    "yes".into()
                } else {
                    "**no**".into()
                },
            ]
        })
        .collect();
    table(
        out,
        &[
            "Round",
            "Confirmed",
            "Failed on chain (grant signer)",
            "Refused by the relay",
            "Ledgers",
            "Root charged",
            "Account paid",
            "Within allowance; charges match transfers",
        ],
        &rows,
    );

    let t = &n.throughput;
    let _ = writeln!(
        out,
        "**Relay throughput** (one agent's budget-asset transfers through the grant signer, {} per channel; twice as many clients as channels, each sending its next call when the last settles, retrying after {} ms on `CHANNELS_BUSY`; the relay polls RPC every {} ms, clients poll the relay every {} ms)\n",
        t["per_channel"],
        t["relay"]["busy_retry_ms"],
        t["relay"]["poll_interval_ms"],
        t["relay"]["client_poll_interval_ms"]
    );
    let rows: Vec<Vec<String>> = t["points"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|p| {
            let per_ledger = p["per_ledger"].as_array().cloned().unwrap_or_default();
            let max = per_ledger
                .iter()
                .filter_map(|x| x[1].as_u64())
                .max()
                .unwrap_or(0);
            vec![
                p["channels"].to_string(),
                p["clients"].to_string(),
                format!("{} / {}", p["confirmed"], p["transactions"]),
                p["busy_answers"].to_string(),
                format!("{:.1}", p["wall_seconds"].as_f64().unwrap_or_default()),
                format!(
                    "{:.2}",
                    p["confirmed_per_second"].as_f64().unwrap_or_default()
                ),
                per_ledger.len().to_string(),
                max.to_string(),
                format!(
                    "{:.2} / {:.2}",
                    p["latency_median"].as_f64().unwrap_or_default(),
                    p["latency_p90"].as_f64().unwrap_or_default()
                ),
            ]
        })
        .collect();
    table(
        out,
        &[
            "Channels",
            "Clients",
            "Confirmed",
            "`CHANNELS_BUSY` answers",
            "Wall s",
            "Confirmed per second",
            "Ledgers with one",
            "Most in one ledger",
            "Submit to settled, median / p90 s",
        ],
        &rows,
    );
}
