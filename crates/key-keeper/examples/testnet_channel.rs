//! Testnet check: does Stellar accept a transaction whose source is a channel
//! account, when the only signature on it comes from a custody key the agent
//! never holds?
//!
//! ```sh
//! cargo run -p nido-key-keeper --example testnet_channel -- --out run.json
//! ```
//!
//! The run, on Stellar testnet:
//!
//! 1. Start the Dfns mock in process with one bearer token and its `Key`
//!    credential, and no keys. Through [`DfnsKeyKeeper`], ask the mock to
//!    create two Ed25519 keys (Dfns Create Key): `custody`, and `unrelated`
//!    for the negative cases. Their seeds never leave the mock.
//! 2. Create three fresh accounts with friendbot: `fund` (the fee-bump fee
//!    source) and `channel-1`, `channel-2` (transaction sources). Each one's
//!    throwaway master key signs a single `SetOptions`: custody key as signer
//!    with weight 1, master weight 0, low/medium/high thresholds 1. The
//!    accounts' signers and thresholds are then read back from Horizon.
//! 3. For each Dfns payload kind that signs a Stellar transaction (`Hash`
//!    over the transaction hash, `Transaction` over the envelope XDR), submit
//!    with a channel as source and the custody key as the only signer:
//!    (a) a classic payment, (b) a Soroban `InvokeHostFunction` (a
//!    native-asset contract `transfer` from the channel), and (c) a fee bump
//!    of (b) with `fund` as fee source, inner and outer both signed by the
//!    custody key.
//! 4. Submit the negative cases, each expected to be refused: signed by a
//!    channel's zeroed master key, signed by the unrelated key (payment and
//!    Soroban), and a fee bump whose outer signature is `fund`'s zeroed
//!    master key.
//!
//! Every transaction goes through Stellar RPC `sendTransaction` and, when
//! admitted, `getTransaction`. Afterwards each case is read back from
//! Horizon: an accepted case must be recorded as successful with the channel
//! as source and every signature, outer and inner, verifying under the
//! custody key; a refused case must have no record. The program prints a
//! Markdown report, writes the same data as JSON to `--out` when given, and
//! exits non-zero if any case differs from its expectation.
//!
//! The mock lives only for the run, so the custody key and with it the
//! accounts are unusable afterwards.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use nido_key_keeper::dfns::api::CreateKeyRequest;
use nido_key_keeper::dfns::mock::{MockConfig, MockServer};
use nido_key_keeper::dfns::{DfnsConfig, DfnsKeyKeeper, KeyCredential};
use nido_key_keeper::{stellar, KeyId, KeyKeeper, Payload, StellarNetwork};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, Asset, ContractId, ContractIdPreimage, FeeBumpTransaction,
    FeeBumpTransactionEnvelope, FeeBumpTransactionExt, FeeBumpTransactionInnerTx, Hash,
    HashIdPreimage, HashIdPreimageContractId, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp,
    Preconditions, PublicKey, ReadXdr, ScAddress, ScSymbol, ScVal, SequenceNumber, SetOptionsOp,
    Signer, SignerKey, SorobanAuthorizationEntry, SorobanTransactionData, Transaction,
    TransactionEnvelope, TransactionExt, TransactionResult, TransactionResultResult,
    TransactionV1Envelope, Uint256, WriteXdr,
};

const HORIZON: &str = "https://horizon-testnet.stellar.org";
const RPC: &str = "https://soroban-testnet.stellar.org";
const FRIENDBOT: &str = "https://friendbot.stellar.org";
const EXPLORER_TX: &str = "https://stellar.expert/explorer/testnet/tx/";
const EXPLORER_ACCOUNT: &str = "https://stellar.expert/explorer/testnet/account/";
const NETWORK: StellarNetwork = StellarNetwork::Testnet;

/// Inclusion fee per operation, in stroops.
const BASE_FEE: u32 = 100;
/// 1 XLM, in stroops.
const AMOUNT: i64 = 10_000_000;

const TOKEN: &str = "testnet-channel-check";
const USER_ID: &str = "us-chk01-chk01-chk0000000000001";
const CRED_ID: &str = "cr-chk01-chk01-chk0000000000001";

type Res<T> = Result<T, String>;

const PAYMENT: &str = "classic payment, 1 XLM to fund";
const INVOKE: &str = "Soroban InvokeHostFunction: native contract `transfer`, 1 XLM to fund";
const FEE_BUMP: &str = "fee bump (fee source fund) of a Soroban native `transfer`, 1 XLM to fund";

fn main() -> ExitCode {
    let mut out = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--out" {
            out = args.next();
        } else {
            eprintln!("usage: testnet_channel [--out <report.json>]");
            return ExitCode::FAILURE;
        }
    }
    match run(out.as_deref()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("testnet_channel: a case differed from its expectation");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("testnet_channel: {e}");
            ExitCode::FAILURE
        }
    }
}

/// How a mock key is asked to sign a transaction.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// Dfns `Hash`: the 32-byte transaction hash.
    Hash,
    /// Dfns `Transaction`: the envelope XDR and its network.
    Transaction,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Hash => "Hash",
            Self::Transaction => "Transaction",
        }
    }
}

/// Who signs a transaction.
#[derive(Clone, Copy)]
enum By<'a> {
    /// A key in the Dfns mock, through [`DfnsKeyKeeper`].
    Keeper(&'a MockKey, Kind),
    /// An account's throwaway master key, held here.
    Master(&'static str, &'a SigningKey),
}

impl By<'_> {
    fn describe(self) -> String {
        match self {
            Self::Keeper(key, kind) => format!("{} via Dfns `{}`", key.name, kind.name()),
            Self::Master(account, _) => format!("{account} master key (weight 0)"),
        }
    }
}

/// A key created in the mock: its Dfns id and public key.
struct MockKey {
    name: &'static str,
    id: KeyId,
    public: [u8; 32],
}

/// A fresh testnet account: its throwaway master key and next sequence
/// number.
struct Account {
    name: &'static str,
    master: SigningKey,
    next_seq: i64,
}

impl Account {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            master: SigningKey::from_bytes(&random_seed()),
            next_seq: 0,
        }
    }

    fn public(&self) -> [u8; 32] {
        self.master.verifying_key().to_bytes()
    }

    fn address(&self) -> String {
        stellar::account_strkey(&self.public())
    }
}

/// What the network said about one submitted transaction.
#[derive(Debug)]
struct Outcome {
    hash: String,
    /// `sendTransaction` status, then `getTransaction` status when admitted.
    rpc_status: String,
    /// The `TransactionResult` code (and the inner code for a fee bump).
    result: String,
    ledger: Option<u64>,
}

impl Outcome {
    fn in_ledger_successfully(&self) -> bool {
        self.rpc_status.ends_with("SUCCESS")
    }

    fn admitted(&self) -> bool {
        self.ledger.is_some()
    }
}

/// A transaction as Horizon records it.
#[derive(Debug)]
struct LedgerRecord {
    successful: bool,
    source_account: String,
    fee_account: String,
    /// Signatures on the transaction (the outer one, for a fee bump).
    signatures: usize,
    /// Signatures on a fee bump's inner transaction.
    inner_signatures: Option<usize>,
    /// Whether every signature, outer and inner, verifies under the custody
    /// key over the hash Horizon reports for it.
    all_by_custody: bool,
}

struct Case {
    id: &'static str,
    what: &'static str,
    source: &'static str,
    source_address: String,
    signed_by: String,
    expect_success: bool,
    outcome: Outcome,
    /// Filled in from Horizon once every case has run.
    record: Option<LedgerRecord>,
}

impl Case {
    fn as_expected(&self) -> bool {
        if self.expect_success {
            self.outcome.in_ledger_successfully()
                && self.record.as_ref().is_some_and(|r| {
                    r.successful && r.all_by_custody && r.source_account == self.source_address
                })
        } else {
            !self.outcome.admitted() && self.record.is_none()
        }
    }
}

fn run(out: Option<&str>) -> Res<bool> {
    let net = Net::new();
    let network = net.rpc("getNetwork", &json!({}))?;
    if network["passphrase"] != NETWORK.passphrase() {
        return Err(format!("{RPC} is not testnet: {network}"));
    }

    // 1. The mock, and the keys it creates.
    let credential = SigningKey::from_bytes(&random_seed());
    let mock = MockServer::start(
        &MockConfig::default().with_token(TOKEN, USER_ID, CRED_ID, &credential.verifying_key()),
        "127.0.0.1:0",
    )
    .map_err(|e| format!("dfns mock: {e}"))?;
    let keeper = DfnsKeyKeeper::new(DfnsConfig::new(
        mock.url(),
        TOKEN,
        KeyCredential {
            cred_id: CRED_ID.to_owned(),
            signing_key: credential,
        },
    ));
    let custody = create_key(&keeper, "custody")?;
    let unrelated = create_key(&keeper, "unrelated")?;

    // 2. Fresh accounts, each configured by its own master key.
    let mut run = Run {
        net: &net,
        keeper: &keeper,
        setup: Vec::new(),
        cases: Vec::new(),
    };
    let mut accounts = [
        Account::new("fund"),
        Account::new("channel-1"),
        Account::new("channel-2"),
    ];
    for account in &mut accounts {
        run.configure(account, &custody)?;
    }
    let configured = read_back(&net, &accounts)?;

    // 3 and 4.
    let [fund, ch1, ch2] = &mut accounts;
    for kind in [Kind::Hash, Kind::Transaction] {
        run.custody_signed(kind, &custody, fund, ch1, ch2)?;
    }
    run.refused(&custody, &unrelated, fund, ch1, ch2)?;
    for case in &mut run.cases {
        case.record =
            net.transaction(&case.outcome.hash, case.outcome.admitted(), &custody.public)?;
    }
    let after = read_back(&net, &accounts)?;

    let ok = run.cases.iter().all(Case::as_expected);
    let report = Report {
        protocol: network["protocolVersion"].clone(),
        custody: &custody,
        unrelated: &unrelated,
        setup: &run.setup,
        configured: &configured,
        after: &after,
        cases: &run.cases,
        ok,
    };
    print!("{}", report.markdown());
    if let Some(path) = out {
        let text = serde_json::to_string_pretty(&report.json()).expect("report serializes");
        std::fs::write(path, text + "\n").map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(ok)
}

/// Each account as Horizon reports it.
fn read_back(net: &Net, accounts: &[Account]) -> Res<Vec<(String, Value)>> {
    accounts
        .iter()
        .map(|a| Ok((a.name.to_owned(), net.account(&a.address())?)))
        .collect()
}

struct Run<'a> {
    net: &'a Net,
    keeper: &'a DfnsKeyKeeper,
    setup: Vec<(&'static str, String, Outcome)>,
    cases: Vec<Case>,
}

impl Run<'_> {
    /// Fund `account` with friendbot, then make the custody key its sole
    /// signer with a `SetOptions` its master key signs.
    fn configure(&mut self, account: &mut Account, custody: &MockKey) -> Res<()> {
        self.net.friendbot(&account.address())?;
        account.next_seq = self.net.sequence(&account.address())? + 1;
        let env = tx(
            account,
            BASE_FEE,
            vec![set_custody_signer(&custody.public)],
            TransactionExt::V0,
        );
        let env = self.signed(env, By::Master(account.name, &account.master))?;
        let outcome = self.net.submit(&env)?;
        if !outcome.in_ledger_successfully() {
            return Err(format!("{}: SetOptions failed: {outcome:?}", account.name));
        }
        account.next_seq += 1;
        self.setup.push((account.name, account.address(), outcome));
        Ok(())
    }

    /// (a), (b) and (c): channel-sourced, signed only by the custody key
    /// through Dfns payload `kind`.
    fn custody_signed(
        &mut self,
        kind: Kind,
        custody: &MockKey,
        fund: &Account,
        ch1: &mut Account,
        ch2: &mut Account,
    ) -> Res<()> {
        let by = By::Keeper(custody, kind);
        let [a, b, c] = match kind {
            Kind::Hash => ["a-hash", "b-hash", "c-hash"],
            Kind::Transaction => ["a-transaction", "b-transaction", "c-transaction"],
        };

        let env = tx(
            ch1,
            BASE_FEE,
            vec![payment(&fund.public())],
            TransactionExt::V0,
        );
        let env = self.signed(env, by)?;
        self.submit(a, PAYMENT, by.describe(), &env, ch1, true)?;

        let env = self.signed(soroban_transfer(self.net, ch2, &fund.public())?, by)?;
        self.submit(b, INVOKE, by.describe(), &env, ch2, true)?;

        let inner = self.signed(soroban_transfer(self.net, ch1, &fund.public())?, by)?;
        let env = self.signed(fee_bump(inner, &fund.public())?, by)?;
        let signed_by = format!("inner and outer: {}", by.describe());
        self.submit(c, FEE_BUMP, signed_by, &env, ch1, true)
    }

    /// Signatures the accounts' configuration must refuse.
    fn refused(
        &mut self,
        custody: &MockKey,
        unrelated: &MockKey,
        fund: &Account,
        ch1: &mut Account,
        ch2: &mut Account,
    ) -> Res<()> {
        let by = By::Master(ch1.name, &ch1.master).describe();
        let env = tx(
            ch1,
            BASE_FEE,
            vec![payment(&fund.public())],
            TransactionExt::V0,
        );
        let env = self.signed(env, By::Master(ch1.name, &ch1.master))?;
        self.submit("n1", PAYMENT, by, &env, ch1, false)?;

        let by = By::Keeper(unrelated, Kind::Hash);
        let env = tx(
            ch1,
            BASE_FEE,
            vec![payment(&fund.public())],
            TransactionExt::V0,
        );
        let env = self.signed(env, by)?;
        self.submit("n2", PAYMENT, by.describe(), &env, ch1, false)?;

        let by = By::Keeper(unrelated, Kind::Transaction);
        let env = self.signed(soroban_transfer(self.net, ch2, &fund.public())?, by)?;
        self.submit("n3", INVOKE, by.describe(), &env, ch2, false)?;

        let inner_by = By::Keeper(custody, Kind::Hash);
        let outer_by = By::Master(fund.name, &fund.master);
        let inner = self.signed(soroban_transfer(self.net, ch1, &fund.public())?, inner_by)?;
        let env = self.signed(fee_bump(inner, &fund.public())?, outer_by)?;
        let signed_by = format!(
            "inner: {}; outer: {}",
            inner_by.describe(),
            outer_by.describe()
        );
        self.submit("n4", FEE_BUMP, signed_by, &env, ch1, false)
    }

    /// Submit `env` as one case, advancing the source's sequence number if
    /// the transaction reached a ledger.
    fn submit(
        &mut self,
        id: &'static str,
        what: &'static str,
        signed_by: String,
        env: &TransactionEnvelope,
        source: &mut Account,
        expect_success: bool,
    ) -> Res<()> {
        let outcome = self.net.submit(env)?;
        eprintln!(
            "{id}: {} {} {}",
            outcome.hash, outcome.rpc_status, outcome.result
        );
        if outcome.admitted() {
            source.next_seq += 1;
        }
        self.cases.push(Case {
            id,
            what,
            source: source.name,
            source_address: source.address(),
            signed_by,
            expect_success,
            outcome,
            record: None,
        });
        Ok(())
    }

    /// `env` with `by`'s signature added.
    fn signed(&self, mut env: TransactionEnvelope, by: By) -> Res<TransactionEnvelope> {
        let hash = tx_hash(&env)?;
        let (public, signature) = match by {
            By::Keeper(key, kind) => {
                let payload = match kind {
                    Kind::Hash => Payload::Hash(hash),
                    Kind::Transaction => Payload::StellarTransaction {
                        network: NETWORK,
                        envelope_xdr: env.to_xdr(Limits::none()).map_err(|e| e.to_string())?,
                    },
                };
                let signature = self
                    .keeper
                    .sign(&key.id, &payload)
                    .map_err(|e| format!("{} ({}): {e}", key.name, kind.name()))?
                    .to_ed25519()
                    .ok_or("not an Ed25519 signature")?;
                (key.public, signature)
            }
            By::Master(_, master) => (
                master.verifying_key().to_bytes(),
                master.sign(&hash).to_bytes(),
            ),
        };
        let signatures = match &mut env {
            TransactionEnvelope::Tx(v1) => &mut v1.signatures,
            TransactionEnvelope::TxFeeBump(fb) => &mut fb.signatures,
            TransactionEnvelope::TxV0(v0) => &mut v0.signatures,
        };
        let mut all = signatures.to_vec();
        all.push(stellar::decorated_signature(&public, &signature));
        *signatures = all.try_into().expect("at most 20 signatures");
        Ok(env)
    }
}

fn tx_hash(env: &TransactionEnvelope) -> Res<[u8; 32]> {
    stellar::transaction_hash(NETWORK, env).map_err(|e| e.to_string())
}

fn create_key(keeper: &DfnsKeyKeeper, name: &'static str) -> Res<MockKey> {
    let key = keeper
        .create_key(&CreateKeyRequest::ed25519(Some(name)))
        .map_err(|e| format!("create key {name}: {e}"))?;
    let public = hex::decode(key.public_key.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            format!(
                "create key {name}: public key {} is not 32 bytes",
                key.public_key
            )
        })?;
    Ok(MockKey {
        name,
        id: KeyId::new(key.id),
        public,
    })
}

fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS randomness");
    seed
}

// Transactions.

fn account_id(public: &[u8; 32]) -> AccountId {
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(*public)))
}

fn tx(source: &Account, fee: u32, ops: Vec<Operation>, ext: TransactionExt) -> TransactionEnvelope {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source.public())),
            fee,
            seq_num: SequenceNumber(source.next_seq),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: ops.try_into().expect("at most 100 operations"),
            ext,
        },
        signatures: Vec::new().try_into().expect("no signatures"),
    })
}

/// Custody key as sole signer: signer weight 1, master weight 0, every
/// threshold 1.
fn set_custody_signer(custody: &[u8; 32]) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::SetOptions(SetOptionsOp {
            inflation_dest: None,
            clear_flags: None,
            set_flags: None,
            master_weight: Some(0),
            low_threshold: Some(1),
            med_threshold: Some(1),
            high_threshold: Some(1),
            home_domain: None,
            signer: Some(Signer {
                key: SignerKey::Ed25519(Uint256(*custody)),
                weight: 1,
            }),
        }),
    }
}

fn payment(to: &[u8; 32]) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::Payment(PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256(*to)),
            asset: Asset::Native,
            amount: AMOUNT,
        }),
    }
}

/// The native asset's Stellar Asset Contract on testnet.
fn native_contract() -> Res<ContractId> {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(NETWORK.network_id()),
        contract_id_preimage: ContractIdPreimage::Asset(Asset::Native),
    });
    let bytes = preimage.to_xdr(Limits::none()).map_err(|e| e.to_string())?;
    Ok(ContractId(Hash(Sha256::digest(bytes).into())))
}

/// `transfer(from = source, to, 1 XLM)` on the native contract, simulated
/// and assembled (resources, resource fee, authorization entries).
fn soroban_transfer(net: &Net, source: &Account, to: &[u8; 32]) -> Res<TransactionEnvelope> {
    let args = vec![
        ScVal::Address(ScAddress::Account(account_id(&source.public()))),
        ScVal::Address(ScAddress::Account(account_id(to))),
        ScVal::I128(Int128Parts {
            hi: 0,
            lo: AMOUNT.unsigned_abs(),
        }),
    ];
    let invoke = |auth: Vec<SorobanAuthorizationEntry>| Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(InvokeContractArgs {
                contract_address: ScAddress::Contract(native_contract().expect("encodes")),
                function_name: ScSymbol("transfer".try_into().expect("short symbol")),
                args: args.clone().try_into().expect("three arguments"),
            }),
            auth: auth.try_into().expect("few entries"),
        }),
    };
    let unsigned = tx(
        source,
        BASE_FEE,
        vec![invoke(Vec::new())],
        TransactionExt::V0,
    );
    let (data, resource_fee, auth) = net.simulate(&unsigned)?;
    let fee = u32::try_from(i64::from(BASE_FEE) + resource_fee).map_err(|e| e.to_string())?;
    Ok(tx(
        source,
        fee,
        vec![invoke(auth)],
        TransactionExt::V1(data),
    ))
}

/// A fee bump of `inner` paid by `fee_source`: the inner resource fee plus
/// the inclusion fee for the inner operation and the bump itself.
fn fee_bump(inner: TransactionEnvelope, fee_source: &[u8; 32]) -> Res<TransactionEnvelope> {
    let TransactionEnvelope::Tx(inner) = inner else {
        return Err("only v1 envelopes are fee-bumped".to_owned());
    };
    let fee = i64::from(inner.tx.fee) + 2 * i64::from(BASE_FEE);
    Ok(TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256(*fee_source)),
            fee,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
            ext: FeeBumpTransactionExt::V0,
        },
        signatures: Vec::new().try_into().expect("no signatures"),
    }))
}

// Horizon, friendbot and Stellar RPC.

struct Net {
    agent: ureq::Agent,
}

impl Net {
    fn new() -> Self {
        Self {
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(90)))
                .build()
                .into(),
        }
    }

    fn get(&self, url: &str) -> Res<(u16, Value)> {
        let mut response = self
            .agent
            .get(url)
            .call()
            .map_err(|e| format!("{url}: {e}"))?;
        let status = response.status().as_u16();
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("{url}: {e}"))?;
        Ok((
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        ))
    }

    fn friendbot(&self, address: &str) -> Res<()> {
        let (status, body) = self.get(&format!("{FRIENDBOT}/?addr={address}"))?;
        if status == 200 {
            Ok(())
        } else {
            Err(format!("friendbot {address}: {status} {body}"))
        }
    }

    /// The account as Horizon reports it.
    fn account(&self, address: &str) -> Res<Value> {
        let (status, body) = self.get(&format!("{HORIZON}/accounts/{address}"))?;
        if status == 200 {
            Ok(body)
        } else {
            Err(format!("horizon account {address}: {status} {body}"))
        }
    }

    /// The transaction with `hash` as Horizon records it, or `None` if
    /// Horizon has no record. When `expected`, waits for Horizon to ingest it.
    fn transaction(
        &self,
        hash: &str,
        expected: bool,
        custody: &[u8; 32],
    ) -> Res<Option<LedgerRecord>> {
        let deadline = Instant::now() + Duration::from_mins(1);
        let record = loop {
            let (status, body) = self.get(&format!("{HORIZON}/transactions/{hash}"))?;
            match status {
                200 => break body,
                404 if !expected => return Ok(None),
                404 if Instant::now() < deadline => std::thread::sleep(Duration::from_secs(3)),
                _ => return Err(format!("horizon transaction {hash}: {status} {body}")),
            }
        };
        let signatures = |v: &Value| -> Vec<String> {
            v.as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        };
        let by_custody = |tx_hash: &Value, sigs: &[String]| {
            let Some(tx_hash) = tx_hash
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|h| <[u8; 32]>::try_from(h).ok())
            else {
                return false;
            };
            sigs.iter().all(|sig| {
                STANDARD
                    .decode(sig)
                    .ok()
                    .and_then(|s| <[u8; 64]>::try_from(s).ok())
                    .is_some_and(|s| {
                        stellar::verify_decorated_signature(
                            custody,
                            &tx_hash,
                            &stellar::decorated_signature(custody, &s),
                        )
                    })
            })
        };
        let outer = signatures(&record["signatures"]);
        let inner = record
            .get("inner_transaction")
            .map(|inner| (signatures(&inner["signatures"]), &inner["hash"]));
        let all_by_custody = !outer.is_empty()
            && by_custody(&record["hash"], &outer)
            && inner
                .as_ref()
                .is_none_or(|(sigs, h)| !sigs.is_empty() && by_custody(h, sigs));
        Ok(Some(LedgerRecord {
            successful: record["successful"] == true,
            source_account: record["source_account"].as_str().unwrap_or("?").to_owned(),
            fee_account: record["fee_account"].as_str().unwrap_or("?").to_owned(),
            signatures: outer.len(),
            inner_signatures: inner.map(|(sigs, _)| sigs.len()),
            all_by_custody,
        }))
    }

    fn sequence(&self, address: &str) -> Res<i64> {
        self.account(address)?["sequence"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("horizon account {address}: no sequence"))
    }

    fn rpc(&self, method: &str, params: &Value) -> Res<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut response = self
            .agent
            .post(RPC)
            .content_type("application/json")
            .send(&body.to_string())
            .map_err(|e| format!("rpc {method}: {e}"))?;
        let text = response
            .body_mut()
            .read_to_string()
            .map_err(|e| format!("rpc {method}: {e}"))?;
        let mut reply: Value =
            serde_json::from_str(&text).map_err(|e| format!("rpc {method}: {e}: {text}"))?;
        if let Some(error) = reply.get("error") {
            return Err(format!("rpc {method}: {error}"));
        }
        Ok(reply["result"].take())
    }

    /// `simulateTransaction`: the resources, resource fee and authorization
    /// entries the transaction needs.
    fn simulate(
        &self,
        env: &TransactionEnvelope,
    ) -> Res<(SorobanTransactionData, i64, Vec<SorobanAuthorizationEntry>)> {
        let result = self.rpc("simulateTransaction", &json!({ "transaction": b64(env)? }))?;
        if let Some(error) = result.get("error") {
            return Err(format!("simulation failed: {error}"));
        }
        let data = result["transactionData"]
            .as_str()
            .ok_or("simulation: no transactionData")?;
        let data = SorobanTransactionData::from_xdr(
            STANDARD.decode(data).map_err(|e| e.to_string())?,
            Limits::none(),
        )
        .map_err(|e| e.to_string())?;
        let fee = result["minResourceFee"]
            .as_str()
            .and_then(|f| f.parse().ok())
            .ok_or("simulation: no minResourceFee")?;
        let auth = result["results"][0]["auth"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .map(|a| {
                let bytes = STANDARD
                    .decode(a.as_str().unwrap_or_default())
                    .map_err(|e| e.to_string())?;
                SorobanAuthorizationEntry::from_xdr(bytes, Limits::none())
                    .map_err(|e| e.to_string())
            })
            .collect::<Res<_>>()?;
        Ok((data, fee, auth))
    }

    /// `sendTransaction`, then `getTransaction` until the transaction is in a
    /// ledger if it was admitted.
    fn submit(&self, env: &TransactionEnvelope) -> Res<Outcome> {
        let hash = hex::encode(tx_hash(env)?);
        let mut attempts = 0;
        let sent = loop {
            let sent = self.rpc("sendTransaction", &json!({ "transaction": b64(env)? }))?;
            if sent["status"] == "TRY_AGAIN_LATER" && attempts < 10 {
                attempts += 1;
                std::thread::sleep(Duration::from_secs(3));
                continue;
            }
            break sent;
        };
        let status = sent["status"].as_str().unwrap_or("?").to_owned();
        if status != "PENDING" && status != "DUPLICATE" {
            let result = sent["errorResultXdr"]
                .as_str()
                .map_or_else(|| "(no result)".to_owned(), result_code);
            return Ok(Outcome {
                hash,
                rpc_status: status,
                result,
                ledger: None,
            });
        }
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let got = self.rpc("getTransaction", &json!({ "hash": hash }))?;
            let got_status = got["status"].as_str().unwrap_or("?");
            if got_status != "NOT_FOUND" {
                return Ok(Outcome {
                    hash,
                    rpc_status: format!("{status} → {got_status}"),
                    result: got["resultXdr"]
                        .as_str()
                        .map_or_else(|| "(no result)".to_owned(), result_code),
                    ledger: got["ledger"].as_u64(),
                });
            }
            if Instant::now() > deadline {
                return Err(format!("{hash}: not in a ledger after 90 s"));
            }
        }
    }
}

fn b64(env: &TransactionEnvelope) -> Res<String> {
    Ok(STANDARD.encode(env.to_xdr(Limits::none()).map_err(|e| e.to_string())?))
}

/// The `TransactionResultCode` of a base64 `TransactionResult`, with the
/// inner code for a fee bump.
fn result_code(xdr: &str) -> String {
    let Ok(result) = STANDARD
        .decode(xdr)
        .map_err(|e| e.to_string())
        .and_then(|b| TransactionResult::from_xdr(b, Limits::none()).map_err(|e| e.to_string()))
    else {
        return format!("(undecoded {xdr})");
    };
    let outer = result.result.discriminant().name();
    match &result.result {
        TransactionResultResult::TxFeeBumpInnerSuccess(pair)
        | TransactionResultResult::TxFeeBumpInnerFailed(pair) => {
            format!(
                "{outer} (inner {})",
                pair.result.result.discriminant().name()
            )
        }
        _ => outer.to_owned(),
    }
}

// The report.

struct Report<'a> {
    protocol: Value,
    custody: &'a MockKey,
    unrelated: &'a MockKey,
    setup: &'a [(&'static str, String, Outcome)],
    configured: &'a [(String, Value)],
    after: &'a [(String, Value)],
    cases: &'a [Case],
    ok: bool,
}

/// The signer and threshold fields of a Horizon account record.
fn auth_view(account: &Value) -> Value {
    json!({
        "account_id": account["account_id"],
        "sequence": account["sequence"],
        "signers": account["signers"],
        "thresholds": account["thresholds"],
    })
}

impl Report<'_> {
    fn json(&self) -> Value {
        let accounts = |list: &[(String, Value)]| -> Value {
            list.iter()
                .map(|(name, a)| (name.clone(), auth_view(a)))
                .collect::<serde_json::Map<_, _>>()
                .into()
        };
        json!({
            "network": NETWORK.passphrase(),
            "protocolVersion": self.protocol,
            "rpc": RPC,
            "horizon": HORIZON,
            "custodyKey": {
                "dfnsKeyId": self.custody.id.as_str(),
                "address": stellar::account_strkey(&self.custody.public),
            },
            "unrelatedKey": {
                "dfnsKeyId": self.unrelated.id.as_str(),
                "address": stellar::account_strkey(&self.unrelated.public),
            },
            "setup": self.setup.iter().map(|(name, address, o)| json!({
                "account": name, "address": address, "hash": o.hash,
                "rpcStatus": o.rpc_status, "result": o.result, "ledger": o.ledger,
            })).collect::<Vec<_>>(),
            "accountsAfterSetup": accounts(self.configured),
            "accountsAfterRun": accounts(self.after),
            "cases": self.cases.iter().map(|c| json!({
                "id": c.id, "what": c.what, "source": c.source, "sourceAddress": c.source_address,
                "signedBy": c.signed_by,
                "expected": if c.expect_success { "in ledger, success" } else { "refused" },
                "hash": c.outcome.hash, "rpcStatus": c.outcome.rpc_status,
                "result": c.outcome.result, "ledger": c.outcome.ledger,
                "horizon": c.record.as_ref().map(|r| json!({
                    "successful": r.successful,
                    "sourceAccount": r.source_account,
                    "feeAccount": r.fee_account,
                    "signatures": r.signatures,
                    "innerSignatures": r.inner_signatures,
                    "allSignaturesByCustodyKey": r.all_by_custody,
                })),
                "asExpected": c.as_expected(),
            })).collect::<Vec<_>>(),
            "allAsExpected": self.ok,
        })
    }

    fn markdown(&self) -> String {
        let mut md = String::new();
        let custody = stellar::account_strkey(&self.custody.public);
        let _ = writeln!(
            md,
            "Network: `{}`, protocol {}.\n",
            NETWORK.passphrase(),
            self.protocol
        );
        let _ = writeln!(
            md,
            "Custody key: Dfns mock key `{}`, `{custody}`. Unrelated key: `{}`, `{}`.\n",
            self.custody.id,
            self.unrelated.id,
            stellar::account_strkey(&self.unrelated.public)
        );
        let _ = writeln!(
            md,
            "| Account | Address | SetOptions | Result |\n| - | - | - | - |"
        );
        for (name, address, o) in self.setup {
            let _ = writeln!(
                md,
                "| {name} | [`{address}`]({EXPLORER_ACCOUNT}{address}) | [`{}`]({EXPLORER_TX}{}) | `{}` |",
                short(&o.hash),
                o.hash,
                o.result
            );
        }
        let _ = writeln!(
            md,
            "\nSigners and thresholds read back from Horizon after setup:\n"
        );
        let _ = writeln!(
            md,
            "| Account | Signers (key: weight) | low / med / high |\n| - | - | - |"
        );
        for (name, account) in self.configured {
            let signers = account["signers"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .map(|s| {
                    let key = s["key"].as_str().unwrap_or("?");
                    let role = if key == custody {
                        " (custody)"
                    } else {
                        " (master)"
                    };
                    format!("`{key}`{role}: {}", s["weight"])
                })
                .collect::<Vec<_>>()
                .join("<br>");
            let t = &account["thresholds"];
            let _ = writeln!(
                md,
                "| {name} | {signers} | {} / {} / {} |",
                t["low_threshold"], t["med_threshold"], t["high_threshold"]
            );
        }
        self.cases_markdown(&mut md);
        md
    }

    fn cases_markdown(&self, md: &mut String) {
        let _ = writeln!(
            *md,
            "\n| Case | Transaction | Source | Signed by | Expected | Hash | RPC status | Result (`TransactionResultCode`) | As expected |\n| - | - | - | - | - | - | - | - | - |"
        );
        for c in self.cases {
            let hash = if c.outcome.admitted() {
                format!(
                    "[`{}`]({EXPLORER_TX}{})",
                    short(&c.outcome.hash),
                    c.outcome.hash
                )
            } else {
                format!("`{}` (not in a ledger)", short(&c.outcome.hash))
            };
            let _ = writeln!(
                *md,
                "| {} | {} | {} | {} | {} | {hash} | {} | `{}` | {} |",
                c.id,
                c.what,
                c.source,
                c.signed_by,
                if c.expect_success {
                    "success"
                } else {
                    "refused"
                },
                c.outcome.rpc_status,
                c.outcome.result,
                if c.as_expected() { "yes" } else { "**no**" }
            );
        }
        let name = |address: &str| {
            self.configured
                .iter()
                .find(|(_, a)| a["account_id"] == address)
                .map_or_else(|| format!("`{address}`"), |(n, _)| n.clone())
        };
        let _ = writeln!(
            *md,
            "\nEach case read back from Horizon (`/transactions/{{hash}}`):\n\n| Case | Recorded | Successful | Source account | Fee account | Signatures (outer / inner) | Every signature verifies under the custody key |\n| - | - | - | - | - | - | - |"
        );
        for c in self.cases {
            let line = match &c.record {
                Some(r) => format!(
                    "yes | {} | {} | {} | {} | {} |",
                    r.successful,
                    name(&r.source_account),
                    name(&r.fee_account),
                    r.inner_signatures.map_or_else(
                        || r.signatures.to_string(),
                        |inner| format!("{} / {inner}", r.signatures)
                    ),
                    if r.all_by_custody { "yes" } else { "no" }
                ),
                None => "no (404) | | | | | |".to_owned(),
            };
            let _ = writeln!(*md, "| {} | {line}", c.id);
        }
    }
}

fn short(hash: &str) -> String {
    format!("{}…", &hash[..12])
}
