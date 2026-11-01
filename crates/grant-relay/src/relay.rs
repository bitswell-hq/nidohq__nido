//! The relay pipeline: grant check, channel lease, simulation, signing,
//! submission and status tracking.
//!
//! A request is checked in this order, and the first failure answers it:
//!
//! 1. The API key names an agent.
//! 2. No authorization entry uses `SourceAccount` credentials. The
//!    transaction source is a channel account; such an entry would be
//!    authorized by the custody signature on the transaction.
//! 3. The chain grant allows the host function and every context of every
//!    supplied authorization tree (`grant_eval::chain::allows_all`).
//! 4. The signing grant allows the custody signature: the custody key id,
//!    the network passphrase, payload kind `Transaction`.
//! 5. A channel is free; it is leased.
//! 6. A recording simulation of the bare host function succeeds, asks for no
//!    authorization from the channel account, and the chain grant allows
//!    every context of every tree it records.
//! 7. An enforcing simulation with the supplied entries succeeds (this runs
//!    each account's `__check_auth`), and every entry stays valid long
//!    enough.
//! 8. The fee (inclusion fee plus simulated resource fee) is within the cap.
//!
//! Only then does the key keeper sign the transaction hash. The signature is
//! verified against the custody key before the transaction is sent.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use grant_eval::chain::{self, Action};
use grant_eval::signing;
use nido_key_keeper::{stellar, KeyId, KeyKeeper, Payload};
use serde_json::json;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountEntry, HostFunction, InvokeHostFunctionOp, Memo, MuxedAccount, Operation, OperationBody,
    Preconditions, SequenceNumber, SignerKey, SorobanAuthorizationEntry, SorobanCredentials,
    TimeBounds, TimePoint, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    Uint256,
};

use crate::actions;
use crate::channels::{ChannelPool, Lease};
use crate::config::{Agent, Config};
use crate::protocol::{Request, Status, TxResponse};
use crate::rpc::{AuthMode, Lookup, Send, SorobanRpc};
use crate::RelayError;

/// How long a settled transaction's status stays readable.
const RETENTION: Duration = Duration::from_hours(1);

/// A relay: the configuration, a key keeper for the custody key, and a
/// Soroban RPC server.
pub struct Relay<K, R> {
    inner: Arc<Inner<K, R>>,
}

impl<K, R> Clone for Relay<K, R> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

struct Inner<K, R> {
    config: Config,
    keeper: K,
    rpc: R,
    pool: Arc<ChannelPool>,
    network_id: [u8; 32],
    records: Mutex<HashMap<String, Record>>,
}

struct Record {
    /// The submitting agent's API key hash: only it can read the record.
    agent: [u8; 32],
    hash: [u8; 32],
    status: Status,
    settled: Option<Instant>,
}

impl<K, R> Relay<K, R>
where
    K: KeyKeeper + std::marker::Send + Sync + 'static,
    R: SorobanRpc + 'static,
{
    #[must_use]
    pub fn new(config: Config, keeper: K, rpc: R) -> Self {
        let pool = ChannelPool::new(config.channels.clone());
        let network_id = Sha256::digest(config.network_passphrase.as_bytes()).into();
        Self {
            inner: Arc::new(Inner {
                config,
                keeper,
                rpc,
                pool,
                network_id,
                records: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The channel pool, for observing leases.
    #[must_use]
    pub fn pool(&self) -> &ChannelPool {
        &self.inner.pool
    }

    /// Check that every channel account exists, has master weight 0, and has
    /// the custody key as its only signer, with a weight that meets the
    /// account's low and medium thresholds.
    ///
    /// # Errors
    ///
    /// A message naming the first channel that does not.
    pub fn check_channels(&self) -> Result<(), String> {
        let custody = self.inner.config.custody_public_key;
        for channel in self.inner.pool.channels() {
            let name = stellar::account_strkey(channel);
            let account = self
                .inner
                .rpc
                .account(channel)
                .map_err(|e| format!("channel {name}: {e}"))?
                .ok_or_else(|| format!("channel {name}: account does not exist"))?;
            check_channel(&account, &custody).map_err(|e| format!("channel {name}: {e}"))?;
        }
        Ok(())
    }

    /// Answer one `/relay` request from the holder of `api_key`.
    ///
    /// # Errors
    ///
    /// The [`RelayError`] the response carries.
    pub fn handle(
        &self,
        api_key: Option<&str>,
        request: Request,
    ) -> Result<TxResponse, RelayError> {
        let api_key = api_key.ok_or_else(|| RelayError::unauthorized("API key required"))?;
        let agent_id: [u8; 32] = Sha256::digest(api_key.as_bytes()).into();
        let agent = self.inner.config.agent(api_key)?;
        match request {
            Request::Submit {
                func,
                auth,
                skip_wait,
            } => self.submit(agent_id, agent, &func, auth, skip_wait),
            Request::GetTransaction { transaction_id } => {
                self.inner.status(&agent_id, &transaction_id)
            }
        }
    }

    fn submit(
        &self,
        agent_id: [u8; 32],
        agent: &Agent,
        func: &HostFunction,
        auth: Vec<SorobanAuthorizationEntry>,
        skip_wait: bool,
    ) -> Result<TxResponse, RelayError> {
        check_request(agent, &self.inner.config, func, &auth)?;
        let lease = self.inner.pool.lease().ok_or_else(|| {
            RelayError::new(
                503,
                "CHANNELS_BUSY",
                "Every channel account is in use; retry shortly",
            )
        })?;
        let signed = self.inner.build_and_sign(agent, &lease, func, auth)?;
        self.inner.send(agent_id, &signed, lease, skip_wait)
    }
}

/// A signed transaction ready to send.
struct Signed {
    envelope: TransactionEnvelope,
    hash: [u8; 32],
    max_time: u64,
}

/// Steps 2 to 4: the checks that need no network.
fn check_request(
    agent: &Agent,
    config: &Config,
    func: &HostFunction,
    auth: &[SorobanAuthorizationEntry],
) -> Result<(), RelayError> {
    for (i, entry) in auth.iter().enumerate() {
        if matches!(entry.credentials, SorobanCredentials::SourceAccount) {
            return Err(RelayError::invalid(
                "Source-account credentials are not accepted: the transaction source is a relay channel account",
            )
            .with_details(json!({ "authIndex": i })));
        }
    }
    let mut supplied = vec![actions::host_function(func).map_err(|e| {
        RelayError::new(
            400,
            "UNSUPPORTED_HOST_FUNCTION",
            format!("The relay does not submit {} host functions", e.0),
        )
    })?];
    for entry in auth {
        actions::authorization_tree(entry, &mut supplied);
    }
    check_chain(agent, &supplied, "supplied")?;
    check_signing(agent, config)
}

impl<K, R> Inner<K, R>
where
    K: KeyKeeper + std::marker::Send + Sync + 'static,
    R: SorobanRpc + 'static,
{
    /// Steps 6 to 8 and the signature, on the leased channel.
    fn build_and_sign(
        &self,
        agent: &Agent,
        lease: &Lease,
        func: &HostFunction,
        auth: Vec<SorobanAuthorizationEntry>,
    ) -> Result<Signed, RelayError> {
        let config = &self.config;
        let channel = lease.account();
        let account = self
            .rpc
            .account(&channel)
            .map_err(|e| RelayError::rpc(&e))?
            .ok_or_else(|| {
                RelayError::new(
                    502,
                    "CHANNEL_MISSING",
                    format!(
                        "Channel account {} does not exist",
                        stellar::account_strkey(&channel)
                    ),
                )
            })?;
        let seq = account.seq_num.0.checked_add(1).ok_or_else(|| {
            RelayError::new(
                502,
                "CHANNEL_SEQUENCE",
                "Channel sequence number is exhausted",
            )
        })?;
        let max_time = unix_now().saturating_add(config.validity.as_secs());
        let draft = |auth: Vec<SorobanAuthorizationEntry>, fee: u32, ext: TransactionExt| {
            envelope(&channel, seq, fee, max_time, func.clone(), auth, ext)
        };

        let recorded = self
            .rpc
            .simulate(
                &draft(Vec::new(), config.inclusion_fee, TransactionExt::V0)?,
                AuthMode::Record,
            )
            .map_err(|e| RelayError::rpc(&e))?
            .outcome
            .map_err(|e| simulation_failed(&e))?;
        let mut recorded_actions = Vec::new();
        for entry in &recorded.auth {
            if matches!(entry.credentials, SorobanCredentials::SourceAccount) {
                return Err(RelayError::new(
                    403,
                    "CHANNEL_AUTH_REQUIRED",
                    "The invocation asks for the channel account's authorization",
                ));
            }
            actions::authorization_tree(entry, &mut recorded_actions);
        }
        check_chain(agent, &recorded_actions, "recorded")?;

        let simulation = self
            .rpc
            .simulate(
                &draft(auth.clone(), config.inclusion_fee, TransactionExt::V0)?,
                AuthMode::Enforce,
            )
            .map_err(|e| RelayError::rpc(&e))?;
        let simulated = simulation.outcome.map_err(|e| simulation_failed(&e))?;
        check_expiry(
            &auth,
            simulation.latest_ledger,
            config.min_auth_expiry_ledgers,
        )?;
        let fee = i64::from(config.inclusion_fee)
            .checked_add(simulated.min_resource_fee)
            .and_then(|f| u32::try_from(f).ok())
            .filter(|f| *f <= config.max_fee)
            .ok_or_else(|| {
                RelayError::new(
                    400,
                    "FEE_TOO_HIGH",
                    format!(
                        "The transaction needs a resource fee of {} stroops; the relay pays at most {} in total",
                        simulated.min_resource_fee, config.max_fee
                    ),
                )
            })?;
        let mut data = simulated.transaction_data;
        data.resource_fee = simulated.min_resource_fee;
        let mut envelope = draft(auth, fee, TransactionExt::V1(data))?;

        let hash = self.sign(&mut envelope)?;
        Ok(Signed {
            envelope,
            hash,
            max_time,
        })
    }

    /// Have the key keeper sign `envelope`'s hash with the custody key, check
    /// the signature, and attach it. Returns the hash.
    fn sign(&self, envelope: &mut TransactionEnvelope) -> Result<[u8; 32], RelayError> {
        let config = &self.config;
        let hash = envelope
            .hash(self.network_id)
            .map_err(|e| RelayError::internal(format!("hashing the transaction: {e}")))?;
        let signature = self
            .keeper
            .sign(&KeyId::new(&config.custody_key_id), &Payload::Hash(hash))
            .map_err(|e| {
                RelayError::new(
                    502,
                    "SIGNING_FAILED",
                    format!("The key keeper did not sign: {e}"),
                )
            })?;
        let signature = signature
            .to_ed25519()
            .filter(|s| verifies(&config.custody_public_key, &hash, s))
            .ok_or_else(|| {
                RelayError::new(
                    502,
                    "SIGNING_FAILED",
                    "The key keeper's signature does not verify against the custody key",
                )
            })?;
        let TransactionEnvelope::Tx(v1) = envelope else {
            unreachable!("envelope() builds a v1 envelope");
        };
        v1.signatures = vec![stellar::decorated_signature(
            &config.custody_public_key,
            &signature,
        )]
        .try_into()
        .expect("one signature fits");
        Ok(hash)
    }

    /// Send, then track the transaction until it settles, holding `lease`
    /// until then.
    fn send(
        self: &Arc<Self>,
        agent_id: [u8; 32],
        signed: &Signed,
        lease: Lease,
        skip_wait: bool,
    ) -> Result<TxResponse, RelayError> {
        match self.rpc.send(&signed.envelope) {
            Ok(Send::TryAgainLater) => {
                return Err(RelayError::new(
                    503,
                    "TRY_AGAIN_LATER",
                    "The network did not accept the transaction now; retry shortly",
                ))
            }
            Ok(Send::Error(result)) => {
                return Err(RelayError::new(
                    400,
                    "SUBMIT_FAILED",
                    "The network refused the transaction",
                )
                .with_details(json!({ "errorResultXdr": result })))
            }
            // Accepted, or an unanswered send that may have reached the
            // network: either way the channel stays leased until the
            // transaction is included or its validity window closes.
            Ok(Send::Pending | Send::Duplicate) | Err(_) => {}
        }

        let id = transaction_id();
        self.insert(
            id.clone(),
            Record {
                agent: agent_id,
                hash: signed.hash,
                status: Status::Submitted,
                settled: None,
            },
        );
        Self::track(
            Arc::clone(self),
            id.clone(),
            signed.hash,
            signed.max_time,
            lease,
        );

        if !skip_wait {
            let deadline = Instant::now() + self.config.validity + Duration::from_mins(1);
            while Instant::now() < deadline {
                let response = self.status(&agent_id, &id)?;
                if response.status.is_terminal() {
                    return Ok(response);
                }
                thread::sleep(self.config.poll_interval);
            }
        }
        self.status(&agent_id, &id)
    }
}

impl<K, R> Inner<K, R>
where
    K: std::marker::Send + Sync + 'static,
    R: SorobanRpc + 'static,
{
    /// Look the transaction up until it settles, then record its status and
    /// free its channel.
    fn track(inner: Arc<Self>, id: String, hash: [u8; 32], max_time: u64, lease: Lease) {
        thread::spawn(move || {
            let status = loop {
                thread::sleep(inner.config.poll_interval);
                match inner.rpc.transaction(&hash) {
                    Ok(Lookup::Success) => break Status::Confirmed,
                    Ok(Lookup::Failed) => break Status::Failed,
                    Ok(Lookup::NotFound {
                        latest_ledger_close_time,
                    }) if latest_ledger_close_time > max_time => break Status::Expired,
                    Ok(Lookup::NotFound { .. }) | Err(_) => {}
                }
            };
            drop(lease);
            let mut records = inner.records.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(record) = records.get_mut(&id) {
                record.status = status;
                record.settled = Some(Instant::now());
            }
        });
    }

    fn insert(&self, id: String, record: Record) {
        let mut records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        records.retain(|_, r| r.settled.is_none_or(|t| t.elapsed() < RETENTION));
        records.insert(id, record);
    }

    fn status(&self, agent: &[u8; 32], id: &str) -> Result<TxResponse, RelayError> {
        let records = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let record = records
            .get(id)
            .filter(|r| r.agent == *agent)
            .ok_or_else(|| {
                RelayError::new(404, "NOT_FOUND", format!("Unknown transaction {id}"))
            })?;
        Ok(TxResponse {
            transaction_id: id.to_owned(),
            hash: hex::encode(record.hash),
            status: record.status,
        })
    }
}

/// Deny unless the chain grant allows every action.
fn check_chain(agent: &Agent, actions: &[Action], tree: &str) -> Result<(), RelayError> {
    if chain::allows_all(&agent.chain, actions) {
        return Ok(());
    }
    let (index, denied) = actions
        .iter()
        .enumerate()
        .find(|(_, a)| !chain::allows(&agent.chain, a))
        .expect("allows_all is false only when some action is denied");
    Err(RelayError::new(
        403,
        "GRANT_DENIED",
        format!(
            "Agent {}'s chain grant does not allow {}",
            agent.name,
            describe(denied)
        ),
    )
    .with_details(json!({ "grant": "chain", "tree": tree, "actionIndex": index })))
}

/// Deny unless the signing grant allows the custody signature.
fn check_signing(agent: &Agent, config: &Config) -> Result<(), RelayError> {
    let action = signing::Action {
        key: config.custody_key_id.clone().into_bytes(),
        network: config.network_passphrase.clone().into_bytes(),
        payload: signing::Payload::Transaction,
    };
    if signing::allows(&agent.signing, &action) {
        Ok(())
    } else {
        Err(RelayError::new(
            403,
            "GRANT_DENIED",
            format!(
                "Agent {}'s signing grant does not allow a transaction signature by {} on {:?}",
                agent.name, config.custody_key_id, config.network_passphrase
            ),
        )
        .with_details(json!({ "grant": "signing" })))
    }
}

fn describe(action: &Action) -> String {
    match action {
        Action::Invoke {
            contract, function, ..
        } => format!(
            "{}.{}",
            String::from_utf8_lossy(contract),
            String::from_utf8_lossy(function)
        ),
        Action::CreateContract { wasm_hash } if wasm_hash.is_empty() => {
            "deploying a Stellar Asset Contract".to_owned()
        }
        Action::CreateContract { wasm_hash } => {
            format!("deploying wasm {}", hex::encode(wasm_hash))
        }
    }
}

fn check_channel(account: &AccountEntry, custody: &[u8; 32]) -> Result<(), String> {
    let [master, low, medium, _high] = account.thresholds.0;
    if master != 0 {
        return Err(format!("master weight is {master}, not 0"));
    }
    let signers: Vec<_> = account.signers.iter().collect();
    match signers.as_slice() {
        [signer] if signer.key == SignerKey::Ed25519(Uint256(*custody)) => {
            if signer.weight == 0
                || signer.weight < u32::from(low)
                || signer.weight < u32::from(medium)
            {
                Err(format!(
                    "custody signer weight {} does not meet thresholds low {low} / medium {medium}",
                    signer.weight
                ))
            } else {
                Ok(())
            }
        }
        _ => Err("the custody key must be the only signer".to_owned()),
    }
}

/// Deny when an entry expires before `latest_ledger + margin`.
fn check_expiry(
    auth: &[SorobanAuthorizationEntry],
    latest_ledger: u32,
    margin: u32,
) -> Result<(), RelayError> {
    let min_expiry = latest_ledger.saturating_add(margin);
    for (i, entry) in auth.iter().enumerate() {
        if let Some(expiry) = signature_expiration(entry) {
            if expiry < min_expiry {
                return Err(RelayError::new(
                    400,
                    "AUTH_EXPIRY_TOO_SHORT",
                    format!(
                        "Authorization entry {i} expires at ledger {expiry}; the relay needs at least {min_expiry}"
                    ),
                )
                .with_details(json!({
                    "authIndex": i,
                    "signatureExpirationLedger": expiry,
                    "latestLedger": latest_ledger,
                })));
            }
        }
    }
    Ok(())
}

fn signature_expiration(entry: &SorobanAuthorizationEntry) -> Option<u32> {
    match &entry.credentials {
        SorobanCredentials::SourceAccount => None,
        SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => {
            Some(c.signature_expiration_ledger)
        }
        SorobanCredentials::AddressWithDelegates(c) => {
            Some(c.address_credentials.signature_expiration_ledger)
        }
    }
}

fn simulation_failed(error: &str) -> RelayError {
    RelayError::new(400, "SIMULATION_FAILED", "Simulation failed")
        .with_details(json!({ "error": error }))
}

/// An unsigned single-operation `InvokeHostFunction` transaction from
/// `channel`, valid until `max_time`.
fn envelope(
    channel: &[u8; 32],
    seq: i64,
    fee: u32,
    max_time: u64,
    func: HostFunction,
    auth: Vec<SorobanAuthorizationEntry>,
    ext: TransactionExt,
) -> Result<TransactionEnvelope, RelayError> {
    let auth = auth
        .try_into()
        .map_err(|_| RelayError::invalid("Too many authorization entries"))?;
    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: func,
            auth,
        }),
    };
    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(*channel)),
            fee,
            seq_num: SequenceNumber(seq),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(max_time),
            }),
            memo: Memo::None,
            operations: vec![operation].try_into().expect("one operation fits"),
            ext,
        },
        signatures: Vec::new().try_into().expect("no signatures"),
    }))
}

fn verifies(public_key: &[u8; 32], hash: &[u8; 32], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|k| {
        k.verify_strict(hash, &EdSignature::from_bytes(signature))
            .is_ok()
    })
}

fn transaction_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("the OS random source is available");
    hex::encode(bytes)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
