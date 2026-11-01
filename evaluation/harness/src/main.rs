//! `nido-eval`: the attenuating-grants evaluation. `evaluation/README.md`
//! describes what each command measures and how `just eval` runs them.
//!
//! ```text
//! nido-eval soroban --dapp <wasm> --out <dir>
//! nido-eval report --results <dir> --readme <README.md>
//! nido-eval local-registry
//! nido-eval network --fixtures <dir> --local-stack <dir> --out <dir> [--quick]
//! ```

mod chain;
mod local_stack;
mod network;
mod outcome;
mod record;
mod report;
mod soroban;
mod workloads;

use std::path::PathBuf;
use std::process::ExitCode;

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn required(args: &[String], name: &str) -> Result<String, String> {
    flag(args, name).ok_or_else(|| format!("{name} is required"))
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("soroban") => {
            let dapp = required(args, "--dapp")?;
            let wasm = std::fs::read(&dapp).map_err(|e| format!("{dapp}: {e}"))?;
            soroban::run(&wasm, &PathBuf::from(required(args, "--out")?))
        }
        Some("report") => report::run(
            &PathBuf::from(required(args, "--results")?),
            &PathBuf::from(required(args, "--readme")?),
        ),
        Some("local-registry") => {
            println!("{}", local_stack::registry());
            Ok(())
        }
        Some("network") => {
            let wasm = network::Wasm::load(
                &PathBuf::from(required(args, "--fixtures")?),
                &PathBuf::from(required(args, "--local-stack")?),
            )?;
            network::run(
                &wasm,
                &PathBuf::from(required(args, "--out")?),
                args.iter().any(|a| a == "--quick"),
            )
        }
        _ => Err("usage: nido-eval soroban --dapp <wasm> --out <dir> | report --results <dir> --readme <README.md> | local-registry | network --fixtures <dir> --local-stack <dir> --out <dir> [--quick]".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("soroban") {
        // A refused call unwinds out of the Soroban host; the outcome is read
        // from the panic payload, so the default hook's report would only be
        // noise.
        std::panic::set_hook(Box::new(|_| {}));
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nido-eval: {e}");
            ExitCode::FAILURE
        }
    }
}
