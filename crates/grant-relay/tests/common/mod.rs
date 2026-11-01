//! Fixtures for the relay tests: an in-process network behind the
//! `SorobanRpc` trait, a custody key in a `MemoryKeyKeeper`, a configuration
//! with three agents, and builders for host functions and authorization
//! entries.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use grant_relay::rpc::{AuthMode, Lookup, RpcError, Send, Simulated, Simulation, SorobanRpc};
use grant_relay::{Config, ConfigFile, Relay};
use nido_key_keeper::{stellar, KeyId, MemoryKeyKeeper};
use stellar_xdr::{
    AccountEntry, AccountEntryExt, AccountId, ContractExecutable, ContractIdPreimage,
    ContractIdPreimageFromAddress, CreateContractArgs, Hash, HostFunction, Int128Parts,
    InvokeContractArgs, LedgerFootprint, Limits, MuxedAccount, OperationBody, PublicKey, ScAddress,
    ScSymbol, ScVal, SequenceNumber, Signer, SignerKey, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, SorobanResources, SorobanTransactionData, SorobanTransactionDataExt,
    Thresholds, TransactionEnvelope, TransactionExt, Uint256, WriteXdr,
};

pub const PASSPHRASE: &str = "Test SDF Network ; September 2015";
pub const CUSTODY_KEY: &str = "key-01snl-t56gb-j8tsok0vn802p80i";
pub const CUSTODY_SEED: [u8; 32] = [7; 32];
pub const CHANNEL_SEEDS: [[u8; 32]; 2] = [[11; 32], [12; 32]];
pub const USER_SEED: [u8; 32] = [21; 32];

/// API keys of the three configured agents.
pub const PAYER: &str = "payer-api-key";
pub const FORWARDER_ONLY: &str = "forwarder-only-api-key";
pub const OTHER_NETWORK: &str = "other-network-api-key";

pub fn public(seed: [u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

pub fn custody_public() -> [u8; 32] {
    public(CUSTODY_SEED)
}

pub fn channels() -> Vec<[u8; 32]> {
    CHANNEL_SEEDS.iter().map(|s| public(*s)).collect()
}

/// A contract address from a one-byte seed.
pub fn contract(seed: u8) -> String {
    stellar_strkey::Contract([seed; 32]).to_string()
}

pub fn token() -> String {
    contract(1)
}

pub fn forwarder() -> String {
    contract(2)
}

pub fn user() -> String {
    stellar::account_strkey(&public(USER_SEED))
}

pub fn bob() -> String {
    stellar::account_strkey(&[33; 32])
}

/// The configuration: `payer` may call `token.transfer` with an amount of
/// at most 1000; `forwarder-only` may call `forwarder.forward` and nothing
/// else; `other-network` may call anything but may only have the custody key
/// sign on mainnet.
pub fn config_json() -> serde_json::Value {
    serde_json::json!({
        "network_passphrase": PASSPHRASE,
        "rpc_url": "http://unused.invalid",
        "custody": { "key_id": CUSTODY_KEY, "public_key": stellar::account_strkey(&custody_public()) },
        "channels": channels().iter().map(stellar::account_strkey).collect::<Vec<_>>(),
        "poll_interval_ms": 5,
        "agents": [
            {
                "name": "payer",
                "api_key_sha256": grant_relay::config::api_key_sha256(PAYER),
                "chain": [
                    { "contract_in": [token()] },
                    { "function_in": ["transfer"] },
                    { "arg_i128_at_most": [2, "1000"] }
                ],
                "signing": [
                    { "key_in": [CUSTODY_KEY] },
                    { "network_in": [PASSPHRASE] },
                    { "payload_in": ["transaction"] }
                ]
            },
            {
                "name": "forwarder-only",
                "api_key_sha256": grant_relay::config::api_key_sha256(FORWARDER_ONLY),
                "chain": [
                    { "contract_in": [forwarder()] },
                    { "function_in": ["forward"] }
                ],
                "signing": []
            },
            {
                "name": "other-network",
                "api_key_sha256": grant_relay::config::api_key_sha256(OTHER_NETWORK),
                "chain": [],
                "signing": [{ "network_in": [stellar::MAINNET_PASSPHRASE] }]
            }
        ]
    })
}

pub fn config() -> Config {
    config_from(&config_json())
}

pub fn config_from(json: &serde_json::Value) -> Config {
    let file: ConfigFile = serde_json::from_value(json.clone()).expect("config parses");
    Config::from_file(&file).expect("config is valid")
}

pub fn keeper() -> MemoryKeyKeeper {
    let mut keeper = MemoryKeyKeeper::new();
    keeper.insert(KeyId::new(CUSTODY_KEY), CUSTODY_SEED);
    keeper
}

/// A relay over `net` and a fresh keeper; the keeper is shared so tests can
/// read its request log.
pub fn relay(net: &FakeNetwork) -> (Relay<SharedKeeper, FakeNetwork>, SharedKeeper) {
    relay_with(config(), net)
}

pub fn relay_with(
    config: Config,
    net: &FakeNetwork,
) -> (Relay<SharedKeeper, FakeNetwork>, SharedKeeper) {
    let keeper = SharedKeeper(Arc::new(keeper()));
    (Relay::new(config, keeper.clone(), net.clone()), keeper)
}

/// A `MemoryKeyKeeper` behind an `Arc`, so a test keeps a handle on the one
/// the relay signs with.
#[derive(Clone)]
pub struct SharedKeeper(pub Arc<MemoryKeyKeeper>);

impl nido_key_keeper::KeyKeeper for SharedKeeper {
    fn sign(
        &self,
        key: &KeyId,
        payload: &nido_key_keeper::Payload,
    ) -> Result<nido_key_keeper::Signature, nido_key_keeper::SignError> {
        self.0.sign(key, payload)
    }
}

impl SharedKeeper {
    pub fn requests(&self) -> usize {
        self.0.requests().len()
    }
}

// ---------------------------------------------------------------------------
// Host functions and authorization entries

pub fn address(strkey: &str) -> ScAddress {
    strkey.parse().expect("address strkey")
}

pub fn i128_val(n: i128) -> ScVal {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    ScVal::I128(Int128Parts {
        hi: (n >> 64) as i64,
        lo: n as u64,
    })
}

pub fn invoke_args(contract: &str, function: &str, args: Vec<ScVal>) -> InvokeContractArgs {
    InvokeContractArgs {
        contract_address: address(contract),
        function_name: ScSymbol(function.try_into().expect("symbol")),
        args: args.try_into().expect("args"),
    }
}

/// `token.transfer(user, bob, amount)`.
pub fn transfer_args(amount: i128) -> InvokeContractArgs {
    invoke_args(
        &token(),
        "transfer",
        vec![
            ScVal::Address(address(&user())),
            ScVal::Address(address(&bob())),
            i128_val(amount),
        ],
    )
}

/// `forwarder.forward(token, user, bob, amount)`.
pub fn forward_args(amount: i128) -> InvokeContractArgs {
    invoke_args(
        &forwarder(),
        "forward",
        vec![
            ScVal::Address(address(&token())),
            ScVal::Address(address(&user())),
            ScVal::Address(address(&bob())),
            i128_val(amount),
        ],
    )
}

pub fn node(
    function: SorobanAuthorizedFunction,
    subs: Vec<SorobanAuthorizedInvocation>,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function,
        sub_invocations: subs.try_into().expect("subs"),
    }
}

pub fn call(args: InvokeContractArgs) -> SorobanAuthorizedInvocation {
    node(SorobanAuthorizedFunction::ContractFn(args), Vec::new())
}

/// A user-credentialed entry for `root`, expiring at ledger 10 000. The
/// signature is a placeholder: the fake network does not run `__check_auth`.
pub fn entry(root: SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: address(&user()),
            nonce: 1,
            signature_expiration_ledger: 10_000,
            signature: ScVal::Void,
        }),
        root_invocation: root,
    }
}

pub fn source_entry(root: SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: root,
    }
}

/// A transfer the payer is allowed: the host function and its entry.
pub fn transfer(amount: i128) -> (HostFunction, Vec<SorobanAuthorizationEntry>) {
    (
        HostFunction::InvokeContract(transfer_args(amount)),
        vec![entry(call(transfer_args(amount)))],
    )
}

/// `forward`, whose tree nests the token transfer.
pub fn forward(amount: i128) -> (HostFunction, Vec<SorobanAuthorizationEntry>) {
    (
        HostFunction::InvokeContract(forward_args(amount)),
        vec![entry(node(
            SorobanAuthorizedFunction::ContractFn(forward_args(amount)),
            vec![call(transfer_args(amount))],
        ))],
    )
}

pub fn create_contract_fn() -> SorobanAuthorizedFunction {
    SorobanAuthorizedFunction::CreateContractHostFn(create_contract_args())
}

pub fn create_contract_args() -> CreateContractArgs {
    CreateContractArgs {
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: address(&user()),
            salt: Uint256([5; 32]),
        }),
        executable: ContractExecutable::Wasm(Hash([6; 32])),
    }
}

pub fn submit(
    func: HostFunction,
    auth: Vec<SorobanAuthorizationEntry>,
    skip_wait: bool,
) -> grant_relay::protocol::Request {
    grant_relay::protocol::Request::Submit {
        func,
        auth,
        skip_wait,
    }
}

pub fn get(id: &str) -> grant_relay::protocol::Request {
    grant_relay::protocol::Request::GetTransaction {
        transaction_id: id.to_owned(),
    }
}

pub fn b64(v: &impl WriteXdr) -> String {
    v.to_xdr_base64(Limits::none()).expect("encodes")
}

// ---------------------------------------------------------------------------
// The fake network

/// What `sendTransaction` does with the next transaction.
#[derive(Clone, Debug)]
pub enum SendMode {
    /// Accept it; it is included (successfully) once released.
    Accept,
    /// Accept it and include it as failed once released (the sequence
    /// number is used).
    AcceptThenFail,
    /// Refuse it at validation.
    Error,
    TryAgainLater,
    /// Accept it but answer with a transport error.
    AcceptButNoAnswer,
    /// Never reach the network and answer with a transport error.
    Lost,
}

/// An in-process stand-in for a Soroban RPC server. It does not execute
/// contracts: simulations return configured results.
#[derive(Clone, Default)]
pub struct FakeNetwork {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    accounts: HashMap<[u8; 32], AccountEntry>,
    /// What a recording simulation reports; `None` echoes the request's
    /// shape (no entries).
    recorded: Option<Vec<SorobanAuthorizationEntry>>,
    enforce_error: Option<String>,
    record_error: Option<String>,
    min_resource_fee: i64,
    latest_ledger: u32,
    close_time: u64,
    send_mode: Option<SendMode>,
    /// Hold accepted transactions in the pending set until released.
    hold: bool,
    pending: Vec<([u8; 32], TransactionEnvelope, bool)>,
    included: HashMap<[u8; 32], bool>,
    sent: Vec<TransactionEnvelope>,
    simulations: Vec<AuthMode>,
    rpc_down: bool,
}

impl FakeNetwork {
    /// Channels exist with sequence number 100, master weight 0 and the
    /// custody key as only signer.
    pub fn new() -> Self {
        let net = Self::default();
        {
            let mut s = net.lock();
            for c in channels() {
                s.accounts
                    .insert(c, channel_account(&c, &custody_public(), 100));
            }
            s.min_resource_fee = 5_000;
            s.latest_ledger = 1_000;
            s.close_time = now();
        }
        net
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("fake network state")
    }

    pub fn set_account(&self, account: AccountEntry) {
        let AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(key))) = account.account_id.clone();
        self.lock().accounts.insert(key, account);
    }

    pub fn record(&self, entries: Vec<SorobanAuthorizationEntry>) {
        self.lock().recorded = Some(entries);
    }

    pub fn fail_enforce(&self, error: &str) {
        self.lock().enforce_error = Some(error.to_owned());
    }

    pub fn fail_record(&self, error: &str) {
        self.lock().record_error = Some(error.to_owned());
    }

    pub fn set_min_resource_fee(&self, fee: i64) {
        self.lock().min_resource_fee = fee;
    }

    pub fn set_latest_ledger(&self, ledger: u32) {
        self.lock().latest_ledger = ledger;
    }

    pub fn send_mode(&self, mode: SendMode) {
        self.lock().send_mode = Some(mode);
    }

    pub fn hold(&self) {
        self.lock().hold = true;
    }

    pub fn set_rpc_down(&self, down: bool) {
        self.lock().rpc_down = down;
    }

    /// Include every held transaction.
    pub fn release(&self) {
        let mut s = self.lock();
        s.hold = false;
        let pending = std::mem::take(&mut s.pending);
        for (hash, envelope, ok) in pending {
            s.include(hash, &envelope, ok);
        }
    }

    /// Close a ledger `seconds` after now without including anything held.
    pub fn advance_close_time(&self, seconds: u64) {
        let mut s = self.lock();
        s.close_time = now() + seconds;
        s.pending.clear();
    }

    pub fn sent(&self) -> Vec<TransactionEnvelope> {
        self.lock().sent.clone()
    }

    pub fn simulations(&self) -> Vec<AuthMode> {
        self.lock().simulations.clone()
    }

    pub fn sequence(&self, account: &[u8; 32]) -> i64 {
        self.lock().accounts[account].seq_num.0
    }
}

impl State {
    fn include(&mut self, hash: [u8; 32], envelope: &TransactionEnvelope, ok: bool) {
        let TransactionEnvelope::Tx(v1) = envelope else {
            panic!("v1 envelope")
        };
        let MuxedAccount::Ed25519(Uint256(source)) = v1.tx.source_account else {
            panic!("ed25519 source")
        };
        if let Some(account) = self.accounts.get_mut(&source) {
            account.seq_num = v1.tx.seq_num.clone();
        }
        self.included.insert(hash, ok);
    }
}

fn hash_of(envelope: &TransactionEnvelope) -> [u8; 32] {
    envelope.hash(sha256(PASSPHRASE.as_bytes())).expect("hash")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

impl SorobanRpc for FakeNetwork {
    fn account(&self, account: &[u8; 32]) -> Result<Option<AccountEntry>, RpcError> {
        let s = self.lock();
        if s.rpc_down {
            return Err(RpcError("connection refused".into()));
        }
        Ok(s.accounts.get(account).cloned())
    }

    fn simulate(
        &self,
        envelope: &TransactionEnvelope,
        mode: AuthMode,
    ) -> Result<Simulation, RpcError> {
        let mut s = self.lock();
        if s.rpc_down {
            return Err(RpcError("connection refused".into()));
        }
        s.simulations.push(mode);
        let TransactionEnvelope::Tx(v1) = envelope else {
            panic!("v1 envelope")
        };
        let OperationBody::InvokeHostFunction(op) = &v1.tx.operations[0].body else {
            panic!("invoke host function")
        };
        let (error, auth) = match mode {
            AuthMode::Record => {
                assert!(
                    op.auth.is_empty(),
                    "a recording simulation carries no entries"
                );
                (
                    s.record_error.clone(),
                    s.recorded.clone().unwrap_or_default(),
                )
            }
            AuthMode::Enforce => (s.enforce_error.clone(), op.auth.to_vec()),
        };
        Ok(Simulation {
            latest_ledger: s.latest_ledger,
            outcome: match error {
                Some(e) => Err(e),
                None => Ok(Simulated {
                    transaction_data: SorobanTransactionData {
                        ext: SorobanTransactionDataExt::V0,
                        resources: SorobanResources {
                            footprint: LedgerFootprint {
                                read_only: Vec::new().try_into().unwrap(),
                                read_write: Vec::new().try_into().unwrap(),
                            },
                            instructions: 1_000,
                            disk_read_bytes: 0,
                            write_bytes: 0,
                        },
                        resource_fee: s.min_resource_fee,
                    },
                    min_resource_fee: s.min_resource_fee,
                    auth,
                }),
            },
        })
    }

    fn send(&self, envelope: &TransactionEnvelope) -> Result<Send, RpcError> {
        let mut s = self.lock();
        if s.rpc_down {
            return Err(RpcError("connection refused".into()));
        }
        s.sent.push(envelope.clone());
        let hash = hash_of(envelope);
        let ok = match s.send_mode.clone().unwrap_or(SendMode::Accept) {
            SendMode::Error => return Ok(Send::Error(Some("AAAAAAAAAGT////7AAAAAA==".into()))),
            SendMode::TryAgainLater => return Ok(Send::TryAgainLater),
            SendMode::Lost => return Err(RpcError("connection reset".into())),
            SendMode::Accept | SendMode::AcceptButNoAnswer => true,
            SendMode::AcceptThenFail => false,
        };
        if s.hold {
            s.pending.push((hash, envelope.clone(), ok));
        } else {
            s.include(hash, envelope, ok);
        }
        match s.send_mode {
            Some(SendMode::AcceptButNoAnswer) => Err(RpcError("timed out".into())),
            _ => Ok(Send::Pending),
        }
    }

    fn transaction(&self, hash: &[u8; 32]) -> Result<Lookup, RpcError> {
        let s = self.lock();
        if s.rpc_down {
            return Err(RpcError("connection refused".into()));
        }
        Ok(match s.included.get(hash) {
            Some(true) => Lookup::Success,
            Some(false) => Lookup::Failed,
            None => Lookup::NotFound {
                latest_ledger_close_time: s.close_time,
            },
        })
    }
}

pub fn channel_account(key: &[u8; 32], custody: &[u8; 32], seq: i64) -> AccountEntry {
    AccountEntry {
        account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(*key))),
        balance: 100_000_000,
        seq_num: SequenceNumber(seq),
        num_sub_entries: 1,
        inflation_dest: None,
        flags: 0,
        home_domain: stellar_xdr::String32::default(),
        thresholds: Thresholds([0, 0, 0, 0]),
        signers: vec![Signer {
            key: SignerKey::Ed25519(Uint256(*custody)),
            weight: 1,
        }]
        .try_into()
        .unwrap(),
        ext: AccountEntryExt::V0,
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The envelope's source account and sequence number.
pub fn source_and_seq(envelope: &TransactionEnvelope) -> ([u8; 32], i64) {
    let TransactionEnvelope::Tx(v1) = envelope else {
        panic!("v1 envelope")
    };
    let MuxedAccount::Ed25519(Uint256(source)) = v1.tx.source_account else {
        panic!("ed25519 source")
    };
    (source, v1.tx.seq_num.0)
}

/// Whether the envelope carries one valid custody signature.
pub fn custody_signed(envelope: &TransactionEnvelope) -> bool {
    let TransactionEnvelope::Tx(v1) = envelope else {
        return false;
    };
    let hash = hash_of(envelope);
    v1.signatures.len() == 1
        && stellar::verify_decorated_signature(&custody_public(), &hash, &v1.signatures[0])
}

pub fn fee(envelope: &TransactionEnvelope) -> u32 {
    let TransactionEnvelope::Tx(v1) = envelope else {
        panic!("v1 envelope")
    };
    assert!(matches!(v1.tx.ext, TransactionExt::V1(_)));
    v1.tx.fee
}

/// The resource fee the transaction declares.
pub fn resource_fee(envelope: &TransactionEnvelope) -> i64 {
    let TransactionEnvelope::Tx(v1) = envelope else {
        panic!("v1 envelope")
    };
    let TransactionExt::V1(data) = &v1.tx.ext else {
        panic!("Soroban transaction data")
    };
    data.resource_fee
}

/// Read the transaction's status until it is terminal or `timeout` passes.
pub fn settle<K, R>(
    relay: &Relay<K, R>,
    api_key: &str,
    id: &str,
    timeout: Duration,
) -> grant_relay::protocol::TxResponse
where
    K: nido_key_keeper::KeyKeeper + std::marker::Send + Sync + 'static,
    R: SorobanRpc + 'static,
{
    let deadline = Instant::now() + timeout;
    loop {
        let response = relay.handle(Some(api_key), get(id)).expect("status reads");
        if response.status.is_terminal() || Instant::now() > deadline {
            return response;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Wait until no channel is leased.
pub fn wait_idle<K, R>(relay: &Relay<K, R>)
where
    K: nido_key_keeper::KeyKeeper + std::marker::Send + Sync + 'static,
    R: SorobanRpc + 'static,
{
    let deadline = Instant::now() + Duration::from_secs(5);
    while relay.pool().in_use() != 0 {
        assert!(Instant::now() < deadline, "channels still leased");
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub fn distinct<T: std::hash::Hash + Eq>(items: impl IntoIterator<Item = T>) -> usize {
    items.into_iter().collect::<HashSet<_>>().len()
}
