//! A local Stellar network for end-to-end runs: `stellar/quickstart` in local
//! mode with Soroban RPC, and the setup transactions that prepare it, each
//! sent and signed by its source account's own key.
//!
//! The relay's end-to-end test (`tests/local_network.rs`) and the evaluation
//! (`evaluation/harness`, `nido-eval network`) run on it. Starting the
//! network needs Docker.

use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use stellar_xdr::{
    ContractIdPreimage, Hash, HashIdPreimage, HashIdPreimageContractId, HostFunction,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions,
    SequenceNumber, SetOptionsOp, Signer, SignerKey, SorobanAuthorizationEntry, Transaction,
    TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};

use nido_key_keeper::stellar;

use crate::rpc::{AuthMode, HttpRpc, Lookup, Send, SorobanRpc};

/// `stellar/quickstart` (core v29.0.0, RPC v29.0.1, protocol 28), pinned by
/// its multi-platform index digest.
pub const QUICKSTART: &str =
    "stellar/quickstart@sha256:487fe637ba48c972d5be0ed8965f8df1dcbc3e8e1ee53d24d915b25b6f2b6d99";

/// `stellar/quickstart --local`.
pub const PASSPHRASE: &str = "Standalone Network ; February 2017";

/// The network id: `SHA-256(PASSPHRASE)`.
#[must_use]
pub fn network_id() -> [u8; 32] {
    Sha256::digest(PASSPHRASE.as_bytes()).into()
}

/// Whether `error`, an RPC error or a simulation's error, is the local
/// network's RPC server failing to answer from a consistent ledger rather
/// than an answer about the transaction: it reads a ledger entry or setting
/// its own snapshot or core does not have yet. Such a request is retried.
#[must_use]
pub fn transient(error: &str) -> bool {
    error.contains("is not present in the snapshot")
        || error.contains("could not query captive core")
}

/// An ed25519 key's public key.
#[must_use]
pub fn pk(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

/// A local network: a quickstart container this process started (removed
/// on drop), or one already running at `base`.
pub struct Quickstart {
    container: Option<String>,
    base: String,
}

impl Quickstart {
    /// Start the pinned quickstart image in local mode as container `name`,
    /// with its port 8000 on a free loopback port, and wait until it is
    /// ready.
    ///
    /// # Errors
    ///
    /// If Docker does not start it or it never becomes ready.
    pub fn start(name: &str) -> Result<Self, String> {
        let status = Command::new("docker")
            .args(["run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::8000"])
            .args([QUICKSTART, "--local", "--enable", "rpc"])
            .stdout(std::process::Stdio::null())
            .status()
            .map_err(|e| format!("docker: {e}"))?;
        if !status.success() {
            return Err("docker run failed".into());
        }
        // Removes the container on drop if anything below fails.
        let mut q = Self {
            container: Some(name.to_owned()),
            base: String::new(),
        };
        let port = Command::new("docker")
            .args(["port", name, "8000"])
            .output()
            .map_err(|e| format!("docker port: {e}"))?;
        let mapping = String::from_utf8_lossy(&port.stdout).into_owned();
        let port = mapping
            .lines()
            .next()
            .and_then(|l| l.rsplit(':').next())
            .ok_or("docker port: no mapped port")?
            .trim()
            .to_owned();
        q.base = format!("http://127.0.0.1:{port}");
        q.wait_ready()?;
        Ok(q)
    }

    /// A quickstart already running at `base` (for example
    /// `http://localhost:8000`), once it is ready.
    ///
    /// # Errors
    ///
    /// If it never becomes ready.
    pub fn existing(base: &str) -> Result<Self, String> {
        let q = Self {
            container: None,
            base: base.trim_end_matches('/').to_owned(),
        };
        q.wait_ready()?;
        Ok(q)
    }

    /// The container this process started, if any.
    #[must_use]
    pub fn container(&self) -> Option<&str> {
        self.container.as_deref()
    }

    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    #[must_use]
    pub fn rpc_url(&self) -> String {
        format!("{}/rpc", self.base)
    }

    /// Wait for RPC health, the Soroban settings upgrade (when this process
    /// started the container), and friendbot.
    fn wait_ready(&self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_mins(5);
        let agent = http();
        let mut probe_seed = [250u8; 32];
        getrandom::getrandom(&mut probe_seed[..16]).map_err(|e| e.to_string())?;
        let probe = stellar::account_strkey(&pk(&SigningKey::from_bytes(&probe_seed)));
        loop {
            if Instant::now() >= deadline {
                return Err("the local network never became ready".into());
            }
            std::thread::sleep(Duration::from_secs(2));
            let healthy = agent
                .post(&self.rpc_url())
                .content_type("application/json")
                .send(json!({"jsonrpc": "2.0", "id": 1, "method": "getHealth"}).to_string())
                .ok()
                .and_then(|mut r| r.body_mut().read_to_string().ok())
                .is_some_and(|b| b.contains("healthy"));
            let upgraded = self.container.as_deref().is_none_or(|c| {
                Command::new("docker")
                    .args(["logs", c])
                    .output()
                    .is_ok_and(|o| {
                        String::from_utf8_lossy(&o.stdout).contains("soroban config done")
                    })
            });
            if healthy && upgraded && self.fund(&probe).is_ok() {
                return Ok(());
            }
        }
    }

    /// Create and fund `account` (a `G…` strkey) through friendbot.
    ///
    /// # Errors
    ///
    /// Friendbot's answer when it does not.
    pub fn fund(&self, account: &str) -> Result<(), String> {
        let mut response = http()
            .get(format!("{}/friendbot?addr={account}", self.base))
            .call()
            .map_err(|e| e.to_string())?;
        let body = response.body_mut().read_to_string().unwrap_or_default();
        if response.status().is_success() {
            Ok(())
        } else {
            Err(body)
        }
    }
}

impl Drop for Quickstart {
    fn drop(&mut self) {
        if let Some(name) = &self.container {
            let _ = Command::new("docker")
                .args(["rm", "-f", name])
                .stdout(std::process::Stdio::null())
                .status();
        }
    }
}

/// An HTTP agent that returns non-2xx responses instead of failing on them.
#[must_use]
pub fn http() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_mins(1)))
        .build()
        .into()
}

/// A one-operation transaction from `source`.
///
/// # Panics
///
/// Never: one operation fits.
#[must_use]
pub fn tx(
    source: &[u8; 32],
    seq: i64,
    fee: u32,
    body: OperationBody,
    ext: TransactionExt,
) -> Transaction {
    Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*source)),
        fee,
        seq_num: SequenceNumber(seq),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body,
        }]
        .try_into()
        .expect("one operation"),
        ext,
    }
}

/// Sign `tx` with `key`, send it and wait until it is included. Returns its
/// hash.
///
/// # Errors
///
/// If it is refused, fails, or is not included within a minute.
///
/// # Panics
///
/// Never: one signature fits.
pub fn sign_and_send(rpc: &HttpRpc, key: &SigningKey, tx: Transaction) -> Result<[u8; 32], String> {
    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: Vec::new().try_into().expect("empty"),
    });
    let hash = envelope.hash(network_id()).map_err(|e| e.to_string())?;
    let sig = key.sign(&hash).to_bytes();
    let TransactionEnvelope::Tx(v1) = &mut envelope else {
        unreachable!("a v1 envelope")
    };
    v1.signatures = vec![stellar::decorated_signature(&pk(key), &sig)]
        .try_into()
        .expect("one signature");
    let sent = rpc.send(&envelope).map_err(|e| e.to_string())?;
    if !matches!(sent, Send::Pending) {
        return Err(format!("transaction refused: {sent:?}"));
    }
    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        if Instant::now() >= deadline {
            return Err("transaction never landed".into());
        }
        std::thread::sleep(Duration::from_millis(250));
        match rpc.transaction(&hash).map_err(|e| e.to_string())? {
            Lookup::Success => return Ok(hash),
            Lookup::Failed => return Err(format!("transaction {} failed", hex::encode(hash))),
            Lookup::NotFound { .. } => {}
        }
    }
}

/// `account`'s sequence number. A [`transient`] RPC error is retried.
///
/// # Errors
///
/// If RPC does not answer or the account does not exist.
pub fn sequence(rpc: &HttpRpc, account: &[u8; 32]) -> Result<i64, String> {
    let mut tries = 0;
    let entry = loop {
        match rpc.account(account) {
            Ok(entry) => break entry,
            Err(e) if tries >= 10 || !transient(&e.0) => return Err(e.to_string()),
            Err(_) => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    };
    Ok(entry
        .ok_or_else(|| format!("{} does not exist", stellar::account_strkey(account)))?
        .seq_num
        .0)
}

/// Make `channel` a relay channel: master weight 0, `custody` the only
/// signer.
///
/// # Errors
///
/// If the transaction does not land.
pub fn hand_to_custody(
    rpc: &HttpRpc,
    channel: &SigningKey,
    custody: &[u8; 32],
) -> Result<(), String> {
    let op = OperationBody::SetOptions(SetOptionsOp {
        inflation_dest: None,
        clear_flags: None,
        set_flags: None,
        master_weight: Some(0),
        low_threshold: None,
        med_threshold: None,
        high_threshold: None,
        home_domain: None,
        signer: Some(Signer {
            key: SignerKey::Ed25519(Uint256(*custody)),
            weight: 1,
        }),
    });
    let seq = sequence(rpc, &pk(channel))? + 1;
    sign_and_send(
        rpc,
        channel,
        tx(&pk(channel), seq, 100, op, TransactionExt::V0),
    )
    .map(|_| ())
}

/// Run `func` with `key`'s account as source. With `auth`, the transaction
/// carries exactly those entries and the simulation enforces them; without,
/// it carries the authorization the simulation records (source-account
/// credentials for `key`'s account). An `Err` is the simulation's error or
/// the transaction's failure.
///
/// # Errors
///
/// As above.
///
/// # Panics
///
/// If there are more authorization entries than a transaction holds.
pub fn invoke(
    rpc: &HttpRpc,
    key: &SigningKey,
    func: &HostFunction,
    auth: Option<Vec<SorobanAuthorizationEntry>>,
) -> Result<[u8; 32], String> {
    let seq = sequence(rpc, &pk(key))? + 1;
    let body = |auth: Vec<SorobanAuthorizationEntry>| {
        OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: func.clone(),
            auth: auth.try_into().expect("authorization entries fit"),
        })
    };
    let (mode, supplied) = match auth {
        Some(entries) => (AuthMode::Enforce, entries),
        None => (AuthMode::Record, Vec::new()),
    };
    let draft = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx(
            &pk(key),
            seq,
            100,
            body(supplied.clone()),
            TransactionExt::V0,
        ),
        signatures: Vec::new().try_into().expect("empty"),
    });
    let mut tries = 0;
    let sim = loop {
        match rpc
            .simulate(&draft, mode)
            .map_err(|e| e.to_string())
            .and_then(|s| s.outcome)
        {
            Err(e) if transient(&e) && tries < 10 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(250));
            }
            other => break other?,
        }
    };
    let auth = match mode {
        AuthMode::Enforce => supplied,
        AuthMode::Record => sim.auth,
    };
    let mut data = sim.transaction_data;
    data.resource_fee = sim.min_resource_fee;
    let fee = u32::try_from(sim.min_resource_fee)
        .ok()
        .and_then(|f| f.checked_add(100))
        .ok_or("resource fee out of range")?;
    sign_and_send(
        rpc,
        key,
        tx(&pk(key), seq, fee, body(auth), TransactionExt::V1(data)),
    )
}

/// The address of the contract `preimage` creates on the local network.
///
/// # Panics
///
/// Never: the preimage encodes.
#[must_use]
pub fn contract_id(preimage: ContractIdPreimage) -> String {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(network_id()),
        contract_id_preimage: preimage,
    });
    let id: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).expect("XDR")).into();
    stellar_strkey::Contract(id).to_string()
}
