//! The relay agents call through on the local network: `grant_relay::Relay`
//! behind its HTTP server, signing with the custody key through the Dfns
//! client against the local Dfns mock, and the client side of `/relay` as
//! Nido's browser client speaks it.

use std::time::{Duration, Instant};

use grant_relay::config::api_key_sha256;
use grant_relay::rpc::HttpRpc;
use grant_relay::{Config, ConfigFile, Server};
use nido_key_keeper::dfns::{DfnsConfig, DfnsKeyKeeper, KeyCredential};
use nido_key_keeper::stellar;
use serde::Serialize;
use serde_json::{json, Value};
use soroban_sdk::xdr::{
    ContractEventBody, DiagnosticEvent, HostFunction, Limits, ReadXdr, ScError, ScVal,
    SorobanAuthorizationEntry, TransactionResult, TransactionResultResult, WriteXdr,
};

use super::{Net, CUSTODY_KEY, DFNS_CRED, DFNS_TOKEN};
use crate::outcome::{classify, grant_error, Outcome};

/// One relay agent: its API key and its chain grant, as the relay's
/// configuration file writes caveats (`chain` in `crates/grant-relay`'s
/// README).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AgentSpec {
    pub api_key: String,
    pub chain: Vec<Value>,
}

/// A relay and its server, serving until dropped.
pub struct Running {
    pub agents: Vec<AgentSpec>,
    server: Server,
}

/// Where to send requests.
#[derive(Clone, Debug)]
pub struct Handle {
    pub url: String,
}

impl Running {
    /// A relay over `channels` with `agents`, each with the signing grant
    /// that allows the custody key to sign transactions on this network,
    /// served by `workers` request threads.
    ///
    /// # Errors
    ///
    /// If the configuration does not load, a channel is not the custody
    /// key's, or the server does not start.
    pub fn start(
        net: &Net,
        agents: &[AgentSpec],
        channels: &[[u8; 32]],
        workers: usize,
    ) -> Result<Self, String> {
        let file: ConfigFile = serde_json::from_value(json!({
            "network_passphrase": grant_relay::local::PASSPHRASE,
            "rpc_url": net.quickstart.rpc_url(),
            "custody": {
                "key_id": CUSTODY_KEY,
                "public_key": stellar::account_strkey(&net.custody.key.verifying_key().to_bytes()),
            },
            "channels": channels.iter().map(stellar::account_strkey).collect::<Vec<_>>(),
            "poll_interval_ms": 250,
            "agents": agents.iter().map(|a| json!({
                "name": a.api_key,
                "api_key_sha256": api_key_sha256(&a.api_key),
                "chain": a.chain,
                "signing": [
                    { "key_in": [CUSTODY_KEY] },
                    { "network_in": [grant_relay::local::PASSPHRASE] },
                    { "payload_in": ["transaction"] }
                ]
            })).collect::<Vec<_>>(),
        }))
        .map_err(|e| e.to_string())?;
        let config = Config::from_file(&file)?;
        let keeper = DfnsKeyKeeper::new(DfnsConfig::new(
            net.custody.mock.url(),
            DFNS_TOKEN,
            KeyCredential {
                cred_id: DFNS_CRED.into(),
                signing_key: net.custody.credential.clone(),
            },
        ));
        let relay = grant_relay::Relay::new(config, keeper, HttpRpc::new(net.quickstart.rpc_url()));
        // The channel check reads the channel accounts, which the local
        // network's RPC server at times answers with an error while its core
        // catches up; it is retried.
        let mut tries = 0;
        while let Err(e) = relay.check_channels() {
            tries += 1;
            if tries > 10 {
                return Err(e);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let server = Server::start(&relay, "127.0.0.1:0", workers).map_err(|e| e.to_string())?;
        Ok(Self {
            agents: agents.to_vec(),
            server,
        })
    }

    #[must_use]
    pub fn handle(&self) -> Handle {
        Handle {
            url: self.server.url().to_owned(),
        }
    }
}

/// The relay's answer to one call, as the results record it.
#[derive(Clone, Debug, Serialize)]
pub struct Reply {
    /// The submit response's HTTP status.
    pub status: u16,
    /// Milliseconds from sending the submit request to its response.
    pub submit_ms: f64,
    /// Submissions sent again because the relay's RPC server did not answer
    /// (`RPC_UNAVAILABLE`, or a simulation failed for a transient reason).
    pub rpc_retries: u32,
    /// `success: false`'s code.
    pub code: Option<String>,
    /// The settled status of a submitted transaction.
    pub settled: Option<String>,
    /// The transaction's hash, when one was submitted.
    pub hash: Option<String>,
    /// The ledger that included the transaction.
    pub ledger: Option<u32>,
    /// For a transaction that failed on chain: its result, and the grant
    /// signer's error or the first error event of its diagnostic events.
    pub chain_failure: Option<String>,
    /// CPU instructions and memory bytes of the transaction's host function
    /// as the network metered them (core's `core_metrics` diagnostic events).
    pub cpu_instructions: Option<u64>,
    pub mem_bytes: Option<u64>,
    /// The response's error message (a simulation's host error is in
    /// `details`).
    pub error: Option<String>,
    pub details: Value,
}

impl Handle {
    fn post(&self, api_key: &str, body: &Value) -> Result<(u16, Value), String> {
        let mut response = grant_relay::local::http()
            .post(format!("{}/agents/{api_key}/relay", self.url))
            .header("Content-Type", "application/json")
            .send(body.to_string())
            .map_err(|e| format!("the relay: {e}"))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| e.to_string())?;
        Ok((
            status,
            serde_json::from_str(&text).map_err(|e| format!("{e}: {text}"))?,
        ))
    }

    /// Submit `func` with `auth` as the holder of `api_key`, as the browser
    /// does (`skipWait: true`), then poll `getTransaction` until the
    /// transaction settles.
    ///
    /// # Errors
    ///
    /// If the relay does not answer or never settles the transaction.
    pub fn call(
        &self,
        api_key: &str,
        func: &HostFunction,
        auth: &[SorobanAuthorizationEntry],
    ) -> Result<Reply, String> {
        let b64 = |x: Result<String, _>| x.map_err(|e: soroban_sdk::xdr::Error| e.to_string());
        let body = json!({ "params": {
            "func": b64(func.to_xdr_base64(Limits::none()))?,
            "auth": auth
                .iter()
                .map(|e| b64(e.to_xdr_base64(Limits::none())))
                .collect::<Result<Vec<_>, _>>()?,
            "skipWait": true,
        }});
        // `RPC_UNAVAILABLE`, or a simulation that failed for a
        // `grant_relay::local::transient` reason, is the relay's RPC server
        // failing to answer, not a decision about the call; the relay frees
        // the channel and uses no sequence number on it, so the call is sent
        // again.
        let mut rpc_retries = 0;
        let (status, response, submit_ms) = loop {
            let started = Instant::now();
            let (status, response) = self.post(api_key, &body)?;
            let submit_ms = started.elapsed().as_secs_f64() * 1000.0;
            let code = response.pointer("/data/code").and_then(Value::as_str);
            let unanswered = code == Some("RPC_UNAVAILABLE")
                || (code == Some("SIMULATION_FAILED")
                    && response
                        .pointer("/data/details/error")
                        .and_then(Value::as_str)
                        .is_some_and(grant_relay::local::transient));
            if unanswered && rpc_retries < 5 {
                rpc_retries += 1;
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
            break (status, response, submit_ms);
        };
        let mut reply = Reply {
            status,
            submit_ms,
            rpc_retries,
            code: response
                .pointer("/data/code")
                .and_then(Value::as_str)
                .map(str::to_owned),
            settled: None,
            hash: None,
            ledger: None,
            chain_failure: None,
            cpu_instructions: None,
            mem_bytes: None,
            error: response
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned),
            details: response
                .pointer("/data/details")
                .cloned()
                .unwrap_or(Value::Null),
        };
        if status != 200 {
            return Ok(reply);
        }
        let id = response
            .pointer("/data/transactionId")
            .and_then(Value::as_str)
            .ok_or("no transactionId")?
            .to_owned();
        let deadline = Instant::now() + Duration::from_mins(2);
        loop {
            let (_, r) = self.post(
                api_key,
                &json!({ "params": { "getTransaction": { "transactionId": id } } }),
            )?;
            let s = r
                .pointer("/data/status")
                .and_then(Value::as_str)
                .unwrap_or("submitted");
            if s != "submitted" {
                reply.settled = Some(s.to_owned());
                reply.hash = r
                    .pointer("/data/hash")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                return Ok(reply);
            }
            if Instant::now() > deadline {
                return Err(format!("transaction {id} never settled"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The outcome a relay reply records: allowed when the transaction was
/// confirmed; a refusal by the relay's own checks named by its code; a
/// refusal in the relay's enforcing simulation read from the host's error
/// as the simulation reads it (`outcome::classify`); a transaction that
/// failed on chain as `chain`, with its result.
#[must_use]
pub fn outcome(reply: &Reply, signer: &str, account: &str) -> Outcome {
    match (reply.code.as_deref(), reply.settled.as_deref()) {
        (None, Some("confirmed")) => Outcome::Allowed,
        (None, Some(s)) => Outcome::refused(
            "chain",
            reply
                .chain_failure
                .clone()
                .unwrap_or_else(|| format!("transaction {s}")),
        ),
        (Some("SIMULATION_FAILED"), _) => classify(
            reply
                .details
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            signer,
            account,
        ),
        (Some("GRANT_DENIED"), _) => {
            let d = &reply.details;
            let what = match d.get("grant").and_then(Value::as_str) {
                Some("chain") => format!(
                    "chain grant, {} tree, action {}",
                    d.get("tree").and_then(Value::as_str).unwrap_or("?"),
                    d.get("actionIndex").and_then(Value::as_u64).unwrap_or(0)
                ),
                Some(g) => format!("{g} grant"),
                None => String::new(),
            };
            Outcome::refused("relay", format!("GRANT_DENIED ({what})"))
        }
        (Some(code), _) => Outcome::refused(
            "relay",
            format!("{code}: {}", reply.error.as_deref().unwrap_or_default()),
        ),
        (None, None) => Outcome::refused("relay", format!("HTTP {}", reply.status)),
    }
}

/// Fill in `reply`'s including ledger and, when the transaction failed on
/// chain, its failure, from `getTransaction`.
pub fn settle(rpc: &HttpRpc, reply: &mut Reply, signer: &str) {
    let Some(hash) = &reply.hash else { return };
    let Ok(r) = rpc.call("getTransaction", &json!({ "hash": hash })) else {
        return;
    };
    reply.ledger = r
        .get("ledger")
        .and_then(Value::as_u64)
        .and_then(|l| u32::try_from(l).ok());
    if reply.settled.as_deref() == Some("failed") {
        reply.chain_failure = Some(chain_failure(&r, signer));
    }
    reply.cpu_instructions = core_metric(&r, b"cpu_insn");
    reply.mem_bytes = core_metric(&r, b"mem_byte");
}

/// The `core_metrics` diagnostic event named `name`.
fn core_metric(r: &Value, name: &[u8]) -> Option<u64> {
    r.get("diagnosticEventsXdr")?
        .as_array()?
        .iter()
        .filter_map(|e| {
            e.as_str()
                .and_then(|x| DiagnosticEvent::from_xdr_base64(x, Limits::none()).ok())
        })
        .find_map(|e| {
            let ContractEventBody::V0(body) = &e.event.body;
            match (body.topics.first(), body.topics.get(1), &body.data) {
                (Some(ScVal::Symbol(a)), Some(ScVal::Symbol(b)), ScVal::U64(n))
                    if a.0.as_slice() == b"core_metrics" && b.0.as_slice() == name =>
                {
                    Some(*n)
                }
                _ => None,
            }
        })
}

/// A failed transaction's result, with the grant signer's error when its
/// diagnostic events record one, or else the first error event.
fn chain_failure(r: &Value, signer: &str) -> String {
    let code = r
        .get("resultXdr")
        .and_then(Value::as_str)
        .and_then(|x| TransactionResult::from_xdr_base64(x, Limits::none()).ok())
        .map_or_else(
            || "no result".into(),
            |t| match t.result {
                TransactionResultResult::TxFailed(ops) => ops
                    .iter()
                    .map(|o| format!("{o:?}"))
                    .collect::<Vec<_>>()
                    .join(", "),
                other => format!("{other:?}"),
            },
        );
    let events: Vec<DiagnosticEvent> = r
        .get("diagnosticEventsXdr")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|e| {
            e.as_str()
                .and_then(|x| DiagnosticEvent::from_xdr_base64(x, Limits::none()).ok())
        })
        .collect();
    let errors = events.iter().filter_map(|e| {
        let ContractEventBody::V0(body) = &e.event.body;
        matches!(body.topics.first(), Some(ScVal::Symbol(s)) if s.0.as_slice() == b"error")
            .then_some((e, body))
    });
    let mut first = None;
    for (e, body) in errors {
        let contract = e
            .event
            .contract_id
            .as_ref()
            .map(|c| stellar_strkey::Contract(c.0 .0).to_string());
        if contract.as_deref() == Some(signer) {
            if let Some(ScVal::Error(ScError::Contract(n))) = body.topics.get(1) {
                return format!("{code}; grant signer: {}", grant_error(*n));
            }
        }
        if first.is_none() {
            let text: String = format!("{:?} {:?}", body.topics.get(1), body.data)
                .chars()
                .take(300)
                .collect();
            first = Some(format!(
                "{}: {text}",
                contract.unwrap_or_else(|| "host".into())
            ));
        }
    }
    match first {
        Some(f) => format!("{code}; {f}"),
        None => code,
    }
}
