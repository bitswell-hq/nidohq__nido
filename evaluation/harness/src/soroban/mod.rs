//! The Soroban boundary in simulation: the factory-minted Perch account and
//! its grant signer in `soroban-env-host` under enforcing authorization, every
//! contract from its wasm.

pub mod attacks;
pub mod costs;
pub mod fixture;
pub mod workloads;

use std::path::Path;

use serde_json::json;

use crate::record;

/// Run the cost sweeps, the attack suite and the workloads, writing
/// `soroban-costs.json`, `lean-cases.json`, `soroban-attacks.json` and
/// `soroban-workloads.json` to `out`.
///
/// # Errors
///
/// If a result file cannot be written.
pub fn run(dapp_wasm: &[u8], out: &Path) -> Result<(), String> {
    let f = fixture::Fixture::new("costs", dapp_wasm, 2, None);
    let (points, cases) = costs::run(&f);
    record::write(out, "soroban-costs.json", &points)?;
    record::write_csv(out, "soroban-costs.csv", &points)?;
    record::write(out, "lean-cases.json", &json!({ "cases": cases }))?;
    eprintln!("soroban: {} cost points", points.len());

    let rows = attacks::run(dapp_wasm);
    eprintln!("soroban: {} attack rows", rows.len());
    record::write(out, "soroban-attacks.json", &rows)?;

    let mut all = Vec::new();
    for w in crate::workloads::all() {
        all.extend(workloads::run(dapp_wasm, &w));
    }
    eprintln!("soroban: {} workload calls", all.len());
    record::write(out, "soroban-workloads.json", &all)?;
    Ok(())
}
