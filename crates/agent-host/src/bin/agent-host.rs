//! `agent-host run <workload.json>`: replay a workload, one JSON result per
//! step on stdout.
//!
//! `agent-host bench [iterations]`: time one check through the evaluator
//! component against the same check made natively, as JSON.

use std::process::ExitCode;

use agent_host::{bench, workload, Host};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["run", path] => run(path),
        ["bench"] => bench(100_000),
        ["bench", n] => match n.parse() {
            Ok(n) => bench(n),
            Err(e) => Err(format!("iterations {n:?}: {e}")),
        },
        _ => Err("usage: agent-host run <workload.json> | agent-host bench [iterations]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("agent-host: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let workload: workload::Workload =
        serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    let keeper = workload::keeper(&workload)?;
    let mut host = Host::new(keeper).map_err(|e| e.to_string())?;
    for result in workload::run(&mut host, &workload) {
        println!(
            "{}",
            serde_json::to_string(&result).map_err(|e| e.to_string())?
        );
    }
    Ok(())
}

fn bench(iterations: u32) -> Result<(), String> {
    let report = bench::run(iterations).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(())
}
