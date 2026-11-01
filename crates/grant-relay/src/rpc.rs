//! The Soroban RPC methods the relay uses, behind a trait so tests can
//! substitute an in-process network.
//!
//! [`HttpRpc`] calls a Soroban RPC server over JSON-RPC: `getLedgerEntries`
//! (channel accounts), `simulateTransaction`, `sendTransaction` and
//! `getTransaction`.

use std::time::Duration;

use serde_json::{json, Value};
use stellar_xdr::{
    AccountEntry, AccountId, LedgerEntryData, LedgerKey, LedgerKeyAccount, Limits, PublicKey,
    ReadXdr, SorobanAuthorizationEntry, SorobanTransactionData, TransactionEnvelope, Uint256,
    WriteXdr,
};

/// A failure to get an answer from the RPC server: unreachable, an RPC
/// error, or a response that does not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError(pub String);

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// `simulateTransaction`'s `authMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Record the authorization every `require_auth` asks for, ignoring the
    /// transaction's own entries (which must be absent).
    Record,
    /// Check the transaction's entries, running each account's
    /// `__check_auth`.
    Enforce,
}

impl AuthMode {
    fn name(self) -> &'static str {
        match self {
            AuthMode::Record => "record",
            AuthMode::Enforce => "enforce",
        }
    }
}

/// A simulation's outcome.
#[derive(Debug, Clone)]
pub struct Simulation {
    /// The latest ledger the simulation ran against.
    pub latest_ledger: u32,
    /// The simulated invocation, or the host's error.
    pub outcome: Result<Simulated, String>,
}

/// A successful simulation.
#[derive(Debug, Clone)]
pub struct Simulated {
    pub transaction_data: SorobanTransactionData,
    pub min_resource_fee: i64,
    /// The authorization entries of the invocation: recorded ones in
    /// [`AuthMode::Record`].
    pub auth: Vec<SorobanAuthorizationEntry>,
}

/// `sendTransaction`'s status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Send {
    /// Accepted into the pending set.
    Pending,
    /// Already in the pending set.
    Duplicate,
    /// Not accepted now; nothing was queued.
    TryAgainLater,
    /// Refused at validation; nothing was queued. Carries the
    /// `TransactionResult` XDR, base64, when the server gave one.
    Error(Option<String>),
}

/// `getTransaction`'s answer for one hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// Included and successful.
    Success,
    /// Included and failed.
    Failed,
    /// Not in any ledger the server has, up to its latest ledger, which
    /// closed at `latest_ledger_close_time` (Unix seconds).
    NotFound { latest_ledger_close_time: u64 },
}

/// The Soroban RPC methods the relay calls.
pub trait SorobanRpc: std::marker::Send + Sync {
    /// The account entry of `account` (an Ed25519 public key), if it exists.
    ///
    /// # Errors
    ///
    /// [`RpcError`] when the server gives no usable answer.
    fn account(&self, account: &[u8; 32]) -> Result<Option<AccountEntry>, RpcError>;

    /// Simulate `envelope`.
    ///
    /// # Errors
    ///
    /// [`RpcError`] when the server gives no usable answer. A simulation that
    /// ran and failed is an `Ok` with an `Err` outcome.
    fn simulate(
        &self,
        envelope: &TransactionEnvelope,
        mode: AuthMode,
    ) -> Result<Simulation, RpcError>;

    /// Submit `envelope`.
    ///
    /// # Errors
    ///
    /// [`RpcError`] when the server gives no usable answer, in which case the
    /// transaction may or may not have reached the network.
    fn send(&self, envelope: &TransactionEnvelope) -> Result<Send, RpcError>;

    /// Look up the transaction with hash `hash`.
    ///
    /// # Errors
    ///
    /// [`RpcError`] when the server gives no usable answer.
    fn transaction(&self, hash: &[u8; 32]) -> Result<Lookup, RpcError>;
}

/// A Soroban RPC server reached over HTTP.
pub struct HttpRpc {
    url: String,
    agent: ureq::Agent,
}

impl HttpRpc {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Self {
            url: url.into(),
            agent,
        }
    }

    /// Call JSON-RPC `method` with `params`, returning its `result`.
    ///
    /// # Errors
    ///
    /// [`RpcError`] when the server gives no usable answer or answers with
    /// an error.
    pub fn call(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let mut response = self
            .agent
            .post(&self.url)
            .content_type("application/json")
            .send(body.to_string())
            .map_err(|e| RpcError(format!("{method}: {e}")))?;
        let status = response.status();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| RpcError(format!("{method}: {e}")))?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|_| RpcError(format!("{method}: HTTP {status}, not JSON")))?;
        if let Some(error) = value.get("error") {
            return Err(RpcError(format!("{method}: {error}")));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError(format!("{method}: response has no result")))
    }
}

fn envelope_b64(envelope: &TransactionEnvelope) -> Result<String, RpcError> {
    envelope
        .to_xdr_base64(Limits::none())
        .map_err(|e| RpcError(format!("encoding the transaction: {e}")))
}

fn field<'a>(v: &'a Value, name: &str, method: &str) -> Result<&'a Value, RpcError> {
    v.get(name)
        .ok_or_else(|| RpcError(format!("{method}: result has no {name}")))
}

fn str_field<'a>(v: &'a Value, name: &str, method: &str) -> Result<&'a str, RpcError> {
    field(v, name, method)?
        .as_str()
        .ok_or_else(|| RpcError(format!("{method}: {name} is not a string")))
}

fn u64_field(v: &Value, name: &str, method: &str) -> Result<u64, RpcError> {
    let f = field(v, name, method)?;
    f.as_u64()
        .or_else(|| f.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| RpcError(format!("{method}: {name} is not an unsigned integer")))
}

fn decode<T: ReadXdr>(b64: &str, what: &str) -> Result<T, RpcError> {
    T::from_xdr_base64(b64, Limits::none()).map_err(|e| RpcError(format!("decoding {what}: {e}")))
}

impl SorobanRpc for HttpRpc {
    fn account(&self, account: &[u8; 32]) -> Result<Option<AccountEntry>, RpcError> {
        const M: &str = "getLedgerEntries";
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(*account))),
        });
        let key = key
            .to_xdr_base64(Limits::none())
            .map_err(|e| RpcError(format!("encoding the ledger key: {e}")))?;
        let result = self.call(M, &json!({ "keys": [key] }))?;
        let entries = field(&result, "entries", M)?
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        let Some(entry) = entries.first() else {
            return Ok(None);
        };
        match decode::<LedgerEntryData>(str_field(entry, "xdr", M)?, "the account entry")? {
            LedgerEntryData::Account(a) => Ok(Some(a)),
            _ => Err(RpcError(format!("{M}: the entry is not an account"))),
        }
    }

    fn simulate(
        &self,
        envelope: &TransactionEnvelope,
        mode: AuthMode,
    ) -> Result<Simulation, RpcError> {
        const M: &str = "simulateTransaction";
        let params = json!({ "transaction": envelope_b64(envelope)?, "authMode": mode.name() });
        let result = self.call(M, &params)?;
        let latest_ledger = u32::try_from(u64_field(&result, "latestLedger", M)?)
            .map_err(|_| RpcError(format!("{M}: latestLedger out of range")))?;
        if let Some(error) = result.get("error").and_then(Value::as_str) {
            return Ok(Simulation {
                latest_ledger,
                outcome: Err(error.to_owned()),
            });
        }
        let transaction_data =
            decode(str_field(&result, "transactionData", M)?, "transactionData")?;
        let min_resource_fee = i64::try_from(u64_field(&result, "minResourceFee", M)?)
            .map_err(|_| RpcError(format!("{M}: minResourceFee out of range")))?;
        let mut auth = Vec::new();
        if let Some(first) = result
            .get("results")
            .and_then(Value::as_array)
            .and_then(|r| r.first())
        {
            for a in first
                .get("auth")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                let a = a
                    .as_str()
                    .ok_or_else(|| RpcError(format!("{M}: an auth entry is not a string")))?;
                auth.push(decode(a, "an authorization entry")?);
            }
        }
        Ok(Simulation {
            latest_ledger,
            outcome: Ok(Simulated {
                transaction_data,
                min_resource_fee,
                auth,
            }),
        })
    }

    fn send(&self, envelope: &TransactionEnvelope) -> Result<Send, RpcError> {
        const M: &str = "sendTransaction";
        let result = self.call(M, &json!({ "transaction": envelope_b64(envelope)? }))?;
        match str_field(&result, "status", M)? {
            "PENDING" => Ok(Send::Pending),
            "DUPLICATE" => Ok(Send::Duplicate),
            "TRY_AGAIN_LATER" => Ok(Send::TryAgainLater),
            "ERROR" => Ok(Send::Error(
                result
                    .get("errorResultXdr")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )),
            other => Err(RpcError(format!("{M}: unknown status {other}"))),
        }
    }

    fn transaction(&self, hash: &[u8; 32]) -> Result<Lookup, RpcError> {
        const M: &str = "getTransaction";
        let result = self.call(M, &json!({ "hash": hex::encode(hash) }))?;
        match str_field(&result, "status", M)? {
            "SUCCESS" => Ok(Lookup::Success),
            "FAILED" => Ok(Lookup::Failed),
            "NOT_FOUND" => Ok(Lookup::NotFound {
                latest_ledger_close_time: u64_field(&result, "latestLedgerCloseTime", M)?,
            }),
            other => Err(RpcError(format!("{M}: unknown status {other}"))),
        }
    }
}
