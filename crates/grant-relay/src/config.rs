//! The relay's configuration file (JSON) and the grants it names.
//!
//! The file names the network, the Soroban RPC endpoint, the custody key and
//! its channel accounts, and each agent with the hash of its API key and its
//! two grants. Who issues those grants (the admin document) is outside the
//! relay: it only reads the result.
//!
//! An agent's chain grant is written as chain caveats and checked as the
//! `rule_eval` rule set they lower to ([`chain_rules`]): one rule per
//! contract every `contract_in` caveat names, matching the functions every
//! `function_in` caveat names (every function when there is none), with
//! every argument caveat as a condition. So a chain grant allows a context
//! exactly when every caveat holds for it, and names the contracts it
//! allows: `rule_eval` has no rule that matches every contract.

use std::collections::BTreeMap;
use std::time::Duration;

use grant_eval::signing;
use rule_eval::{Cond, Functions, Rule, Val};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use stellar_xdr::ReadXdr;

use crate::RelayError;

/// The configuration file, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    /// The network passphrase, which also names the network in signing
    /// actions.
    pub network_passphrase: String,
    /// The Soroban RPC endpoint (JSON-RPC over HTTP POST).
    pub rpc_url: String,
    pub custody: CustodyFile,
    /// The channel accounts (`G…`), each with master weight 0 and the custody
    /// key as its only signer.
    pub channels: Vec<String>,
    /// The inclusion fee bid per transaction, in stroops, added to the
    /// simulated resource fee.
    #[serde(default = "default_inclusion_fee")]
    pub inclusion_fee: u32,
    /// The highest total fee the relay pays for one transaction, in stroops.
    #[serde(default = "default_max_fee")]
    pub max_fee: u32,
    /// The resource fee a transaction declares, as a percentage added to the
    /// simulated minimum; the refundable part not used is refunded.
    #[serde(default = "default_resource_fee_margin_percent")]
    pub resource_fee_margin_percent: u32,
    /// How long a submitted transaction stays valid (its `maxTime` offset).
    #[serde(default = "default_validity_seconds")]
    pub validity_seconds: u64,
    /// Ledgers an authorization entry must stay valid past the latest ledger.
    #[serde(default = "default_min_auth_expiry_ledgers")]
    pub min_auth_expiry_ledgers: u32,
    /// How often submitted transactions are looked up.
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    pub agents: Vec<AgentFile>,
    /// The key keeper the binary signs through. Library callers pass their
    /// own keeper and may omit it.
    #[serde(default)]
    pub keeper: Option<KeeperFile>,
}

fn default_inclusion_fee() -> u32 {
    100
}
fn default_max_fee() -> u32 {
    10_000_000
}
fn default_resource_fee_margin_percent() -> u32 {
    20
}
fn default_validity_seconds() -> u64 {
    60
}
fn default_min_auth_expiry_ledgers() -> u32 {
    2
}
fn default_poll_interval_ms() -> u64 {
    1000
}

/// The custody key: the key keeper's id for it and its public key.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyFile {
    pub key_id: String,
    /// The key's `G…` address.
    pub public_key: String,
}

/// One agent.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFile {
    pub name: String,
    /// Hex SHA-256 of the agent's API key. The key itself is not stored.
    pub api_key_sha256: String,
    /// The chain grant: caveats every context of the authorization tree must
    /// pass, at least one of them `contract_in`.
    pub chain: Vec<ChainCaveatFile>,
    /// The signing grant: caveats the custody signature must pass.
    pub signing: Vec<SigningCaveatFile>,
}

/// A chain caveat, one key per caveat:
/// `{"contract_in": ["C…"]}`, `{"function_in": ["transfer"]}`,
/// `{"arg_i128_at_most": [2, "1000"]}`, `{"arg_eq": [0, {"address": "G…"}]}`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ChainCaveatFile {
    ContractIn(Vec<String>),
    FunctionIn(Vec<String>),
    ArgI128AtMost(u32, I128Text),
    ArgEq(u32, ValFile),
}

/// An `i128` as a JSON integer or a decimal string (JSON numbers lose
/// precision past 2^53 in many readers).
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum I128Text {
    Number(i64),
    Text(String),
}

/// An argument value: `{"i128": "5"}`, `{"u64": 5}`, `{"bool": true}`,
/// `{"bytes": "<hex>"}`, `{"address": "G…"}`, `{"symbol": "name"}`, or
/// `{"other": "<hex>"}`: the `ScVal` XDR of an argument whose type has no
/// variant of its own (`u32`, `string`, `vec`, …), which matches the
/// argument the relay reads from exactly that XDR.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ValFile {
    I128(I128Text),
    U64(u64),
    Bool(bool),
    Bytes(String),
    Address(String),
    Symbol(String),
    Other(String),
}

/// A signing caveat: `{"key_in": ["key-…"]}`,
/// `{"network_in": ["Test SDF Network ; September 2015"]}`,
/// `{"payload_in": ["transaction"]}`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningCaveatFile {
    KeyIn(Vec<String>),
    NetworkIn(Vec<String>),
    PayloadIn(Vec<PayloadFile>),
}

#[derive(Debug, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum PayloadFile {
    Transaction,
    AuthEntry,
    Message,
}

/// The key keeper the binary signs through.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum KeeperFile {
    /// Dfns Generate Signature (or the local `dfns-mock`). Secrets come from
    /// the environment variables named here.
    Dfns {
        base_url: String,
        /// The variable holding the bearer token.
        token_env: String,
        /// The `Key` credential id that signs user action challenges.
        credential_id: String,
        /// The variable holding that credential's Ed25519 seed, in hex.
        credential_seed_env: String,
    },
}

/// One agent, with its chain grant lowered to a `rule_eval` rule set and its
/// signing grant parsed into evaluator caveats.
pub struct Agent {
    pub name: String,
    pub chain: Vec<Rule>,
    pub signing: Vec<signing::Caveat>,
}

/// The settings a relay runs with, checked and parsed.
pub struct Config {
    pub network_passphrase: String,
    pub rpc_url: String,
    pub custody_key_id: String,
    pub custody_public_key: [u8; 32],
    pub channels: Vec<[u8; 32]>,
    pub inclusion_fee: u32,
    pub max_fee: u32,
    pub resource_fee_margin_percent: u32,
    pub validity: Duration,
    pub min_auth_expiry_ledgers: u32,
    pub poll_interval: Duration,
    /// Agents by the SHA-256 of their API key.
    pub agents: BTreeMap<[u8; 32], Agent>,
}

impl Config {
    /// Parse and check a configuration file.
    ///
    /// # Errors
    ///
    /// A message naming the first field that is malformed.
    pub fn from_file(file: &ConfigFile) -> Result<Self, String> {
        let custody_public_key = account_key(&file.custody.public_key)
            .map_err(|e| format!("custody.public_key: {e}"))?;
        if file.channels.is_empty() {
            return Err("channels: at least one channel account is required".into());
        }
        let mut channels = Vec::new();
        for (i, c) in file.channels.iter().enumerate() {
            let key = account_key(c).map_err(|e| format!("channels[{i}]: {e}"))?;
            if channels.contains(&key) {
                return Err(format!("channels[{i}]: {c} is listed twice"));
            }
            channels.push(key);
        }
        let mut agents = BTreeMap::new();
        for (i, a) in file.agents.iter().enumerate() {
            let at = |e: String| format!("agents[{i}] ({}): {e}", a.name);
            let hash: [u8; 32] = hex::decode(&a.api_key_sha256)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| at("api_key_sha256 must be 32 bytes of hex".into()))?;
            let chain = chain_rules(&a.chain).map_err(at)?;
            let signing = a.signing.iter().map(signing_caveat).collect();
            let agent = Agent {
                name: a.name.clone(),
                chain,
                signing,
            };
            if agents.insert(hash, agent).is_some() {
                return Err(at("another agent has the same API key".into()));
            }
        }
        Ok(Self {
            network_passphrase: file.network_passphrase.clone(),
            rpc_url: file.rpc_url.clone(),
            custody_key_id: file.custody.key_id.clone(),
            custody_public_key,
            channels,
            inclusion_fee: file.inclusion_fee,
            max_fee: file.max_fee,
            resource_fee_margin_percent: file.resource_fee_margin_percent,
            validity: Duration::from_secs(file.validity_seconds),
            min_auth_expiry_ledgers: file.min_auth_expiry_ledgers,
            poll_interval: Duration::from_millis(file.poll_interval_ms),
            agents,
        })
    }

    /// The agent `api_key` belongs to.
    ///
    /// # Errors
    ///
    /// `UNAUTHORIZED` when no agent has this key.
    pub fn agent(&self, api_key: &str) -> Result<&Agent, RelayError> {
        let hash: [u8; 32] = Sha256::digest(api_key.as_bytes()).into();
        self.agents
            .get(&hash)
            .ok_or_else(|| RelayError::unauthorized("Unknown API key"))
    }
}

/// The hex SHA-256 of an API key, as `api_key_sha256` expects it.
#[must_use]
pub fn api_key_sha256(api_key: &str) -> String {
    hex::encode(Sha256::digest(api_key.as_bytes()))
}

fn account_key(strkey: &str) -> Result<[u8; 32], String> {
    nido_key_keeper::stellar::account_public_key(strkey)
        .map_err(|_| format!("{strkey} is not a G… account address"))
}

/// The `rule_eval` rule set a chain grant lowers to (module docs): one rule
/// per contract in every `contract_in` list, in the first list's order, each
/// with no signers and a threshold of 0.
///
/// # Errors
///
/// A grant with no `contract_in` caveat, a `contract_in` entry that is not a
/// `C…` address, or a malformed value.
pub fn chain_rules(grant: &[ChainCaveatFile]) -> Result<Vec<Rule>, String> {
    let mut contracts: Option<Vec<Vec<u8>>> = None;
    let mut functions: Option<Vec<Vec<u8>>> = None;
    for c in grant {
        match c {
            ChainCaveatFile::ContractIn(list) => {
                let list = list.iter().map(|c| contract(c)).collect::<Result<_, _>>()?;
                contracts = Some(within(contracts.as_deref(), list));
            }
            ChainCaveatFile::FunctionIn(list) => {
                functions = Some(within(functions.as_deref(), bytes_list(list)));
            }
            ChainCaveatFile::ArgI128AtMost(..) | ChainCaveatFile::ArgEq(..) => {
                cond(c)?;
            }
        }
    }
    let contracts = contracts.ok_or_else(|| {
        "chain: no contract_in caveat; a chain grant names the contracts it allows".to_owned()
    })?;
    let mut rules = Vec::new();
    for contract in contracts {
        rules.push(Rule {
            contract,
            functions: match &functions {
                Some(list) => Functions::Only(list.clone()),
                None => Functions::AnyExcept(Vec::new()),
            },
            conds: grant
                .iter()
                .filter_map(|c| cond(c).ok().flatten())
                .collect(),
            signers: Vec::new(),
            threshold: 0,
            cap: None,
            valid_until: None,
            generation: None,
        });
    }
    Ok(rules)
}

/// `list` restricted to the entries of `before`, when there is one, without
/// repeats.
fn within(before: Option<&[Vec<u8>]>, list: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for x in list {
        if before.is_none_or(|b| b.contains(&x)) && !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

/// A `contract_in` entry's `ScAddress` XDR.
fn contract(c: &str) -> Result<Vec<u8>, String> {
    if stellar_strkey::Contract::from_string(c).is_err() {
        return Err(format!("contract_in: {c} is not a C… contract address"));
    }
    let a = c
        .parse::<stellar_xdr::ScAddress>()
        .map_err(|_| format!("contract_in: {c} is not a C… contract address"))?;
    crate::actions::address(&a).ok_or_else(|| format!("contract_in: {c} is not a contract"))
}

/// The condition an argument caveat stands for; `None` for a caveat on the
/// contract or function.
fn cond(c: &ChainCaveatFile) -> Result<Option<Cond>, String> {
    Ok(match c {
        ChainCaveatFile::ContractIn(_) | ChainCaveatFile::FunctionIn(_) => None,
        ChainCaveatFile::ArgI128AtMost(index, bound) => {
            Some(Cond::ArgI128AtMost(*index, i128_value(bound)?))
        }
        ChainCaveatFile::ArgEq(index, v) => Some(Cond::ArgEq(*index, val(v)?)),
    })
}

fn val(v: &ValFile) -> Result<Val, String> {
    Ok(match v {
        ValFile::I128(n) => Val::I128(i128_value(n)?),
        ValFile::U64(n) => Val::U64(*n),
        ValFile::Bool(b) => Val::Bool(*b),
        ValFile::Bytes(h) => Val::Bytes(hex::decode(h).map_err(|e| format!("bytes {h:?}: {e}"))?),
        ValFile::Address(a) => {
            let address = a
                .parse::<stellar_xdr::ScAddress>()
                .map_err(|_| format!("{a} is not an address strkey"))?;
            Val::Address(
                crate::actions::address(&address)
                    .ok_or_else(|| format!("{a} is not an address an argument holds"))?,
            )
        }
        ValFile::Symbol(s) => Val::Symbol(s.clone().into_bytes()),
        ValFile::Other(h) => {
            // Through `actions::val`, so the value is exactly what an argument
            // with this XDR maps to; a type with its own variant is refused.
            let bytes = hex::decode(h).map_err(|e| format!("other {h:?}: {e}"))?;
            let arg = stellar_xdr::ScVal::from_xdr(bytes, stellar_xdr::Limits::none())
                .map_err(|e| format!("other {h:?}: not ScVal XDR: {e}"))?;
            match crate::actions::val(&arg) {
                Some(v @ (Val::Other(_) | Val::String(_))) => v,
                Some(_) => return Err(format!("other {h:?}: this type has its own value form")),
                None => return Err(format!("other {h:?}: not a value an argument holds")),
            }
        }
    })
}

fn i128_value(n: &I128Text) -> Result<i128, String> {
    match n {
        I128Text::Number(n) => Ok(i128::from(*n)),
        I128Text::Text(t) => t.parse().map_err(|_| format!("{t:?} is not an i128")),
    }
}

fn signing_caveat(c: &SigningCaveatFile) -> signing::Caveat {
    match c {
        SigningCaveatFile::KeyIn(list) => signing::Caveat::KeyIn(bytes_list(list)),
        SigningCaveatFile::NetworkIn(list) => signing::Caveat::NetworkIn(bytes_list(list)),
        SigningCaveatFile::PayloadIn(list) => signing::Caveat::PayloadIn(
            list.iter()
                .map(|p| match p {
                    PayloadFile::Transaction => signing::Payload::Transaction,
                    PayloadFile::AuthEntry => signing::Payload::AuthEntry,
                    PayloadFile::Message => signing::Payload::Message,
                })
                .collect(),
        ),
    }
}

fn bytes_list(list: &[String]) -> Vec<Vec<u8>> {
    list.iter().map(|s| s.clone().into_bytes()).collect()
}
