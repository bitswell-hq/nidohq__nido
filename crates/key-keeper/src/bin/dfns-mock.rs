//! `dfns-mock --config <file.json> [--listen <addr>]`
//!
//! Serves the local Dfns mock (`nido_key_keeper::dfns::mock`) until killed.
//! The config file is a `MockConfig` in JSON; see the crate README.

use std::process::ExitCode;

use nido_key_keeper::dfns::mock::{key_addresses, MockConfig, MockServer};

const USAGE: &str = "usage: dfns-mock --config <file.json> [--listen <addr>]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dfns-mock: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut config_path = None;
    let mut listen = "127.0.0.1:8787".to_owned();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next(),
            "--listen" => listen = args.next().ok_or(USAGE)?,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unexpected argument {other}\n{USAGE}")),
        }
    }
    let config_path = config_path.ok_or(USAGE)?;
    let text = std::fs::read_to_string(&config_path).map_err(|e| format!("{config_path}: {e}"))?;
    let config: MockConfig =
        serde_json::from_str(&text).map_err(|e| format!("{config_path}: {e}"))?;
    let server = MockServer::start(&config, &listen).map_err(|e| e.to_string())?;
    println!("dfns-mock listening on {}", server.url());
    for (key_id, address) in key_addresses(&config)? {
        println!("  {key_id}  {address}");
    }
    server.wait();
    Ok(())
}
