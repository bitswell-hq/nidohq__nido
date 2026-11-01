//! `grant-relay --config <file.json> [--listen <addr>] [--workers <n>]`
//!
//! Serves `/relay` until killed, signing through the Dfns keeper the config
//! names. Before serving it checks that every channel account has master
//! weight 0 and the custody key as its only signer. See the crate README for
//! the config file.

use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use grant_relay::config::KeeperFile;
use grant_relay::rpc::HttpRpc;
use grant_relay::{Config, ConfigFile, Relay, Server};
use nido_key_keeper::dfns::{DfnsConfig, DfnsKeyKeeper, KeyCredential};

const USAGE: &str = "usage: grant-relay --config <file.json> [--listen <addr>] [--workers <n>]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("grant-relay: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut config_path = None;
    let mut listen = "127.0.0.1:8090".to_owned();
    let mut workers = 16;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next(),
            "--listen" => listen = args.next().ok_or(USAGE)?,
            "--workers" => {
                workers = args.next().and_then(|n| n.parse().ok()).ok_or(USAGE)?;
            }
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => return Err(format!("unexpected argument {other}\n{USAGE}")),
        }
    }
    let config_path = config_path.ok_or(USAGE)?;
    let text = std::fs::read_to_string(&config_path).map_err(|e| format!("{config_path}: {e}"))?;
    let file: ConfigFile =
        serde_json::from_str(&text).map_err(|e| format!("{config_path}: {e}"))?;
    let keeper = match &file.keeper {
        Some(KeeperFile::Dfns {
            base_url,
            token_env,
            credential_id,
            credential_seed_env,
        }) => {
            let token = env(token_env)?;
            let seed: [u8; 32] = hex::decode(env(credential_seed_env)?.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| format!("{credential_seed_env} must hold 32 bytes of hex"))?;
            DfnsKeyKeeper::new(DfnsConfig::new(
                base_url.trim_end_matches('/'),
                token,
                KeyCredential {
                    cred_id: credential_id.clone(),
                    signing_key: SigningKey::from_bytes(&seed),
                },
            ))
        }
        None => return Err(format!("{config_path}: keeper is required")),
    };
    let config = Config::from_file(&file).map_err(|e| format!("{config_path}: {e}"))?;
    let rpc = HttpRpc::new(&config.rpc_url);
    let agents = config.agents.len();
    let channels = config.channels.len();
    let relay = Relay::new(config, keeper, rpc);
    relay.check_channels()?;
    let server = Server::start(&relay, &listen, workers).map_err(|e| e.to_string())?;
    println!(
        "grant-relay listening on {} ({agents} agents, {channels} channels)",
        server.url()
    );
    server.wait();
    Ok(())
}

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("environment variable {name} is not set"))
}
