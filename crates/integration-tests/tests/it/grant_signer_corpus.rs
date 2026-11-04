//! A recorded corpus of the grant signer's `__check_auth` outcomes,
//! replayed.
//!
//! `fixtures/grant-signer/check-auth-corpus.json` holds seeded, generated
//! scenarios. Each scenario is a run of operations on one fresh grant
//! signer: root grants issued with caveats that name their contracts,
//! delegations that add caveats, revocations, key rotations, refills, and
//! authorizations of batches of contexts, each checked by calling the grant
//! signer's `__check_auth` directly. Every operation is recorded with its
//! outcome and, after it, each grant's allowance, spent amount and
//! revocation. Contracts, functions and values are named abstractly, so the
//! corpus describes grants independently of how the contract stores them.
//!
//! The outcomes are those of a grant signer that stored each grant's caveats
//! and checked them with `grant_eval::chain::allows_all` (the commit that
//! adds the corpus). The test replays every operation on this grant signer,
//! with each root grant's caveats lowered to its rule set and each
//! delegation's to attenuation steps (`nido_integration_tests::grants`), and
//! requires the recorded outcome and grant state after each one.
//! `NIDO_RECORD_GRANT_CORPUS=1` regenerates the scenarios and writes the
//! outcomes of the contract under test instead.
//!
//! `cargo test -p nido-integration-tests --test it grant_signer_corpus`

use ed25519_dalek::{Signer as _, SigningKey};
use nido_grant_signer::{GrantError, GrantSignature, GrantSignerClient};
use nido_integration_tests::grants::{self, Arg, Caveat};
use nido_integration_tests::world::strkey;
use nido_integration_tests::GRANT_SIGNER_WASM;
use serde::{Deserialize, Serialize};
use soroban_sdk::auth::{
    Context, ContractContext, ContractExecutable, CreateContractHostFnContext,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::{AccountId, PublicKey, ScAddress, ScVal, ToXdr, Uint256};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, IntoVal, InvokeError, String as SorobanString, Symbol, TryFromVal,
    Val, Vec,
};
use std::collections::BTreeMap;
use std::format;
use std::path::PathBuf;
use std::string::{String, ToString};

const SEED: u64 = 0x6e32_636f_7270_7573;
const SCENARIOS: usize = 160;
const STEPS: usize = 14;

/// The contracts a scenario names: the account the grant signer serves, the
/// grant signer itself, the budget asset, and three other contracts.
const CONTRACTS: [&str; 6] = ["account", "me", "asset", "c1", "c2", "c3"];
/// Addresses that only appear as arguments.
const PEOPLE: [&str; 2] = ["alice", "bob"];
const FUNCTIONS: [&str; 6] = [
    "transfer",
    "approve",
    "swap",
    "protected",
    "delegate",
    "burn",
];

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// An argument or caveat value, abstractly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum V {
    I128(String),
    U64(u64),
    Bool(bool),
    /// Hex.
    Bytes(String),
    Symbol(String),
    /// A name of [`CONTRACTS`] or [`PEOPLE`].
    Address(String),
    U32(u32),
    String(String),
    VecU32(std::vec::Vec<u32>),
}

/// A chain caveat, abstractly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Cav {
    ContractIn(std::vec::Vec<String>),
    FunctionIn(std::vec::Vec<String>),
    ArgI128AtMost(u32, String),
    ArgEq(u32, V),
}

/// One context of an authorization.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Ctx {
    Call {
        contract: String,
        function: String,
        args: std::vec::Vec<V>,
    },
    Create,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    /// The owner issues a root grant to the holder of key `key`.
    Issue {
        key: u8,
        caveats: std::vec::Vec<Cav>,
        allowance: String,
    },
    /// The holder of `parent` delegates to the holder of key `key`, adding
    /// `caveats`.
    Delegate {
        parent: u32,
        key: u8,
        caveats: std::vec::Vec<Cav>,
        allowance: String,
    },
    Revoke {
        grant: u32,
    },
    Rotate {
        grant: u32,
        key: u8,
    },
    Refill {
        grant: u32,
        extra: String,
    },
    /// `__check_auth` of `contexts`, signed for `grant` with key `key`.
    Auth {
        grant: u32,
        key: u8,
        contexts: std::vec::Vec<Ctx>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Out {
    Ok,
    /// A new grant's id.
    Id(u32),
    /// The grant signer's error code.
    Refused(u32),
    /// The host failed the call (a signature that does not verify).
    Failed,
}

/// One grant's allowance, spent amount and revocation.
type GrantState = (String, String, bool);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Step {
    op: Op,
    out: Out,
    /// Every grant after the operation, by id.
    grants: std::vec::Vec<GrantState>,
}

#[derive(Serialize, Deserialize)]
struct Corpus {
    seed: u64,
    scenarios: std::vec::Vec<std::vec::Vec<Step>>,
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/grant-signer/check-auth-corpus.json")
}

// ---------------------------------------------------------------------------
// One grant signer
// ---------------------------------------------------------------------------

struct Signer {
    env: Env,
    me: Address,
    names: BTreeMap<String, Address>,
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

impl Signer {
    fn new() -> Self {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.cost_estimate().budget().reset_unlimited();
        let account = Address::generate(&env);
        let me = env.register(GRANT_SIGNER_WASM, (account.clone(),));
        let issuer = Address::generate(&env);
        let asset = env.register_stellar_asset_contract_v2(issuer).address();
        let alice = ScVal::Address(ScAddress::Account(AccountId(
            PublicKey::PublicKeyTypeEd25519(Uint256([7; 32])),
        )));
        let mut names = BTreeMap::new();
        names.insert("account".to_string(), account);
        names.insert("me".to_string(), me.clone());
        names.insert("asset".to_string(), asset);
        for c in ["c1", "c2", "c3", "bob"] {
            names.insert(c.to_string(), Address::generate(&env));
        }
        names.insert(
            "alice".to_string(),
            Address::try_from_val(&env, &Val::try_from_val(&env, &alice).unwrap()).unwrap(),
        );
        Self { env, me, names }
    }

    fn client(&self) -> GrantSignerClient<'_> {
        GrantSignerClient::new(&self.env, &self.me)
    }

    fn address(&self, name: &str) -> &Address {
        &self.names[name]
    }

    /// The host value of `v`.
    fn val(&self, v: &V) -> Val {
        let e = &self.env;
        match v {
            V::I128(n) => n.parse::<i128>().unwrap().into_val(e),
            V::U64(n) => n.into_val(e),
            V::Bool(b) => b.into_val(e),
            V::Bytes(h) => Bytes::from_slice(e, &hex::decode(h).unwrap()).into_val(e),
            V::Symbol(s) => Symbol::new(e, s).into_val(e),
            V::Address(name) => self.address(name).into_val(e),
            V::U32(n) => n.into_val(e),
            V::String(s) => SorobanString::from_str(e, s).into_val(e),
            V::VecU32(list) => Vec::<u32>::from_slice(e, list).into_val(e),
        }
    }

    fn context(&self, c: &Ctx) -> Context {
        let e = &self.env;
        match c {
            Ctx::Call {
                contract,
                function,
                args,
            } => Context::Contract(ContractContext {
                contract: self.address(contract).clone(),
                fn_name: Symbol::new(e, function),
                args: Vec::from_iter(e, args.iter().map(|v| self.val(v))),
            }),
            Ctx::Create => Context::CreateContractHostFn(CreateContractHostFnContext {
                executable: ContractExecutable::Wasm(BytesN::from_array(e, &[7; 32])),
                salt: BytesN::from_array(e, &[1; 32]),
            }),
        }
    }

    fn grants(&self) -> std::vec::Vec<GrantState> {
        let mut out = std::vec::Vec::new();
        for id in 0.. {
            let Some(g) = self.client().grant(&id) else {
                break;
            };
            out.push((g.allowance.to_string(), g.spent.to_string(), g.revoked));
        }
        out
    }

    fn apply(&self, op: &Op) -> Out {
        let e = &self.env;
        let c = self.client();
        e.mock_all_auths();
        let out = match op {
            Op::Issue {
                key: k,
                caveats,
                allowance,
            } => id_out(&c.try_issue(
                &public(e, *k),
                &grants::root(e, &self.me, &self.caveats(caveats)),
                self.address("asset"),
                &allowance.parse().unwrap(),
            )),
            Op::Delegate {
                parent,
                key: k,
                caveats,
                allowance,
            } => {
                let rules = match c.try_rules(parent) {
                    Ok(Ok(rules)) => rules,
                    _ => Vec::new(e),
                };
                id_out(&c.try_delegate(
                    parent,
                    &public(e, *k),
                    &grants::steps(e, &rules, &self.caveats(caveats)),
                    &allowance.parse().unwrap(),
                ))
            }
            Op::Revoke { grant } => unit_out(&c.try_revoke(grant)),
            Op::Rotate { grant, key: k } => unit_out(&c.try_rotate(grant, &public(e, *k))),
            Op::Refill { grant, extra } => unit_out(&c.try_refill(grant, &extra.parse().unwrap())),
            Op::Auth {
                grant,
                key: k,
                contexts,
            } => {
                e.set_auths(&[]);
                let payload = [0x5a; 32];
                let signature = GrantSignature {
                    grant: *grant,
                    signature: BytesN::from_array(e, &key(*k).sign(&payload).to_bytes()),
                };
                let contexts = Vec::from_iter(e, contexts.iter().map(|x| self.context(x)));
                match e.try_invoke_contract_check_auth::<GrantError>(
                    &self.me,
                    &BytesN::from_array(e, &payload),
                    signature.into_val(e),
                    &contexts,
                ) {
                    Ok(()) => Out::Ok,
                    Err(Ok(err)) => Out::Refused(err as u32),
                    Err(Err(_)) => Out::Failed,
                }
            }
        };
        e.set_auths(&[]);
        out
    }

    // --- the grant's form in the contract ----------------------------------

    fn caveats(&self, list: &[Cav]) -> std::vec::Vec<Caveat> {
        list.iter().map(|c| self.caveat(c)).collect()
    }

    fn caveat(&self, c: &Cav) -> Caveat {
        let e = &self.env;
        let ids = |list: &[String]| {
            Vec::from_iter(
                e,
                list.iter()
                    .map(|n| Bytes::from_slice(e, strkey(self.address(n)).as_bytes())),
            )
        };
        match c {
            Cav::ContractIn(list) => Caveat::ContractIn(ids(list)),
            Cav::FunctionIn(list) => Caveat::FunctionIn(Vec::from_iter(
                e,
                list.iter().map(|f| Bytes::from_slice(e, f.as_bytes())),
            )),
            Cav::ArgI128AtMost(i, bound) => Caveat::ArgI128AtMost(*i, bound.parse().unwrap()),
            Cav::ArgEq(i, v) => Caveat::ArgEq(*i, self.arg(v)),
        }
    }

    /// The caveat value an argument of value `v` matches.
    fn arg(&self, v: &V) -> Arg {
        let e = &self.env;
        match v {
            V::I128(n) => Arg::I128(n.parse().unwrap()),
            V::U64(n) => Arg::U64(*n),
            V::Bool(b) => Arg::Bool(*b),
            V::Bytes(h) => Arg::Bytes(Bytes::from_slice(e, &hex::decode(h).unwrap())),
            V::Symbol(s) => Arg::Symbol(Bytes::from_slice(e, s.as_bytes())),
            V::Address(name) => {
                Arg::Address(Bytes::from_slice(e, strkey(self.address(name)).as_bytes()))
            }
            V::U32(_) | V::String(_) | V::VecU32(_) => Arg::Other(self.val(v).to_xdr(e)),
        }
    }
}

fn public(e: &Env, k: u8) -> BytesN<32> {
    BytesN::from_array(e, &key(k).verifying_key().to_bytes())
}

fn id_out<E>(r: &Result<Result<u32, E>, Result<GrantError, InvokeError>>) -> Out {
    match r {
        Ok(Ok(id)) => Out::Id(*id),
        Err(Ok(err)) => Out::Refused(*err as u32),
        _ => Out::Failed,
    }
}

fn unit_out<E>(r: &Result<Result<(), E>, Result<GrantError, InvokeError>>) -> Out {
    match r {
        Ok(Ok(())) => Out::Ok,
        Err(Ok(err)) => Out::Refused(*err as u32),
        _ => Out::Failed,
    }
}

// ---------------------------------------------------------------------------
// Generating scenarios
// ---------------------------------------------------------------------------

/// The `SplitMix64` generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }

    /// An argument index below `n`.
    fn index(&mut self, n: usize) -> u32 {
        id(self.below(n))
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    fn pick<'a, T>(&mut self, list: &'a [T]) -> &'a T {
        &list[self.below(list.len())]
    }

    /// A non-empty sub-list of `list`, in its order.
    fn some(&mut self, list: &[&str]) -> std::vec::Vec<String> {
        loop {
            let out: std::vec::Vec<String> = list
                .iter()
                .filter(|_| self.chance(40))
                .map(ToString::to_string)
                .collect();
            if !out.is_empty() {
                return out;
            }
        }
    }

    fn amount(&mut self) -> i128 {
        *self.pick(&[0, 1, 5, 10, 40, 99, 100, 101, 250, 1_000, -5, i128::MAX])
    }

    fn allowance(&mut self) -> u128 {
        *self.pick(&[0, 10, 20, 50, 100, 1_000, i128::MAX as u128])
    }

    fn value(&mut self) -> V {
        match self.below(9) {
            0 => V::I128(self.amount().to_string()),
            1 => V::U64(*self.pick(&[0, 7, u64::MAX])),
            2 => V::Bool(self.chance(50)),
            3 => V::Bytes(self.pick(&["", "ab", "abcd"]).to_string()),
            4 => V::Symbol(self.pick(&["swap", "transfer", "x"]).to_string()),
            5 => {
                let all: std::vec::Vec<&str> = CONTRACTS.iter().chain(&PEOPLE).copied().collect();
                V::Address(self.pick(&all).to_string())
            }
            6 => V::U32(*self.pick(&[0, 7])),
            7 => V::String(self.pick(&["hi", "transfer"]).to_string()),
            _ => V::VecU32(self.pick(&[&[][..], &[1, 2][..]]).to_vec()),
        }
    }

    fn caveat(&mut self) -> Cav {
        match self.below(5) {
            0 => Cav::ContractIn(self.some(&CONTRACTS)),
            1 => Cav::FunctionIn(self.some(&FUNCTIONS)),
            2 => Cav::ArgI128AtMost(self.index(4), self.amount().to_string()),
            _ => Cav::ArgEq(self.index(3), self.value()),
        }
    }

    /// The contracts a root grant names: mostly the asset and the other
    /// contracts, sometimes the account or the grant signer as well.
    fn root_contracts(&mut self) -> std::vec::Vec<String> {
        if self.chance(15) {
            return self.some(&CONTRACTS);
        }
        let mut list = self.some(&["asset", "c1", "c2", "c3"]);
        if self.chance(40) && !list.iter().any(|c| c == "asset") {
            list.push("asset".to_string());
        }
        list
    }

    /// A root grant's caveats: one that names contracts, then up to three
    /// more of any kind, in a random order.
    fn root(&mut self) -> std::vec::Vec<Cav> {
        let mut list = std::vec![Cav::ContractIn(self.root_contracts())];
        for _ in 0..self.below(4) {
            list.push(self.caveat());
        }
        let first = self.below(list.len());
        list.swap(0, first);
        list
    }

    /// A context, guided by `caveats` most of the time so that some
    /// authorizations pass.
    fn context(&mut self, caveats: &[Cav], grant: u32) -> Ctx {
        if self.chance(8) {
            return Ctx::Create;
        }
        let guided = self.chance(85);
        let contract = match caveats.iter().find(|c| matches!(c, Cav::ContractIn(_))) {
            Some(Cav::ContractIn(list)) if guided => self.pick(list).clone(),
            _ => self.pick(&CONTRACTS).to_string(),
        };
        let function = match caveats.iter().find(|c| matches!(c, Cav::FunctionIn(_))) {
            Some(Cav::FunctionIn(list)) if guided => self.pick(list).clone(),
            _ => self.pick(&FUNCTIONS).to_string(),
        };
        let function = if contract == "asset" && self.chance(85) {
            "transfer".to_string()
        } else {
            function
        };
        if contract == "asset" && function == "transfer" && self.chance(85) {
            let amount = match caveats
                .iter()
                .find(|c| matches!(c, Cav::ArgI128AtMost(2, _)))
            {
                Some(Cav::ArgI128AtMost(_, bound)) if guided && self.chance(50) => bound.clone(),
                _ => self.pick(&[0i128, 1, 10, 30, 60, 100, 600, -1]).to_string(),
            };
            let args = std::vec![
                V::Address("account".into()),
                V::Address(self.pick(&PEOPLE).to_string()),
                V::I128(amount),
            ];
            return Ctx::Call {
                contract,
                function,
                args,
            };
        }
        if contract == "me" && self.chance(60) {
            let parent = if self.chance(70) { grant } else { grant + 1 };
            return Ctx::Call {
                contract,
                function: "delegate".to_string(),
                args: std::vec![V::U32(parent)],
            };
        }
        let mut args: std::vec::Vec<V> = (0..self.below(4)).map(|_| self.value()).collect();
        if guided && self.chance(80) {
            for c in caveats {
                if let Cav::ArgEq(i, _) | Cav::ArgI128AtMost(i, _) = c {
                    while args.len() <= *i as usize {
                        args.push(self.value());
                    }
                }
            }
        }
        if guided {
            for c in caveats {
                match c {
                    Cav::ArgEq(i, v) if (*i as usize) < args.len() && self.chance(80) => {
                        args[*i as usize] = v.clone();
                    }
                    Cav::ArgI128AtMost(i, bound)
                        if (*i as usize) < args.len() && self.chance(80) =>
                    {
                        args[*i as usize] = V::I128(bound.clone());
                    }
                    _ => {}
                }
            }
        }
        Ctx::Call {
            contract,
            function,
            args,
        }
    }
}

/// What the generator tracks of each grant: its caveats (its parent's, then
/// its own), its holder's key, and whether it or an ancestor was revoked.
struct Known {
    caveats: std::vec::Vec<Cav>,
    key: u8,
    parent: Option<usize>,
    revoked: bool,
}

fn revoked(known: &[Known], mut grant: usize) -> bool {
    loop {
        if known[grant].revoked {
            return true;
        }
        match known[grant].parent {
            Some(p) => grant = p,
            None => return false,
        }
    }
}

/// A grant id.
fn id(i: usize) -> u32 {
    u32::try_from(i).unwrap()
}

fn generate(rng: &mut Rng) -> std::vec::Vec<Op> {
    let mut known: std::vec::Vec<Known> = std::vec::Vec::new();
    let mut ops = std::vec::Vec::new();
    let mut next_key = 1u8;
    let mut fresh_key = || {
        next_key = next_key.wrapping_add(1).max(1);
        next_key
    };
    for _ in 0..=rng.below(2) {
        let key = fresh_key();
        let caveats = rng.root();
        ops.push(Op::Issue {
            key,
            caveats: caveats.clone(),
            allowance: rng.allowance().to_string(),
        });
        known.push(Known {
            caveats,
            key,
            parent: None,
            revoked: false,
        });
    }
    for _ in 0..STEPS {
        let roll = rng.below(100);
        if roll < 18 {
            let parent = rng.below(known.len());
            let added: std::vec::Vec<Cav> = (0..rng.below(3)).map(|_| rng.caveat()).collect();
            let key = fresh_key();
            let mut caveats = known[parent].caveats.clone();
            caveats.extend(added.iter().cloned());
            ops.push(Op::Delegate {
                parent: id(parent),
                key,
                caveats: added,
                allowance: rng.allowance().to_string(),
            });
            known.push(Known {
                caveats,
                key,
                parent: Some(parent),
                revoked: false,
            });
        } else if roll < 21 {
            let grant = rng.below(known.len());
            ops.push(Op::Revoke { grant: id(grant) });
            known[grant].revoked = true;
        } else if roll < 25 {
            let grant = rng.below(known.len());
            let key = fresh_key();
            ops.push(Op::Rotate {
                grant: id(grant),
                key,
            });
            known[grant].key = key;
        } else if roll < 34 {
            ops.push(Op::Refill {
                grant: id(rng.below(known.len())),
                extra: rng.allowance().to_string(),
            });
        } else {
            let live: std::vec::Vec<usize> =
                (0..known.len()).filter(|&g| !revoked(&known, g)).collect();
            let grant = if live.is_empty() || rng.chance(10) {
                rng.below(known.len())
            } else {
                *rng.pick(&live)
            };
            let key = if rng.chance(4) {
                fresh_key()
            } else {
                known[grant].key
            };
            let caveats = known[grant].caveats.clone();
            let contexts = (0..=rng.below(3))
                .map(|_| rng.context(&caveats, id(grant)))
                .collect();
            let grant = if rng.chance(2) {
                id(known.len())
            } else {
                id(grant)
            };
            ops.push(Op::Auth {
                grant,
                key,
                contexts,
            });
        }
    }
    ops
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

fn run(ops: &[Op]) -> std::vec::Vec<Step> {
    let s = Signer::new();
    ops.iter()
        .map(|op| {
            let out = s.apply(op);
            Step {
                op: op.clone(),
                out,
                grants: s.grants(),
            }
        })
        .collect()
}

fn write(corpus: &Corpus) {
    let mut text = format!("{{\n  \"seed\": {},\n  \"scenarios\": [\n", corpus.seed);
    for (i, steps) in corpus.scenarios.iter().enumerate() {
        text.push_str("    [\n");
        for (j, step) in steps.iter().enumerate() {
            text.push_str("      ");
            text.push_str(&serde_json::to_string(step).unwrap());
            text.push_str(if j + 1 < steps.len() { ",\n" } else { "\n" });
        }
        text.push_str(if i + 1 < corpus.scenarios.len() {
            "    ],\n"
        } else {
            "    ]\n"
        });
    }
    text.push_str("  ]\n}\n");
    let path = corpus_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
}

#[test]
fn grant_signer_corpus_replays() {
    if std::env::var_os("NIDO_RECORD_GRANT_CORPUS").is_some() {
        let mut rng = Rng(SEED);
        let scenarios = (0..SCENARIOS).map(|_| run(&generate(&mut rng))).collect();
        write(&Corpus {
            seed: SEED,
            scenarios,
        });
    }
    let text = std::fs::read_to_string(corpus_path()).expect("the recorded corpus");
    let corpus: Corpus = serde_json::from_str(&text).unwrap();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut differences = std::vec::Vec::new();
    for (i, recorded) in corpus.scenarios.iter().enumerate() {
        let ops: std::vec::Vec<Op> = recorded.iter().map(|s| s.op.clone()).collect();
        let replayed = run(&ops);
        for (j, (r, p)) in recorded.iter().zip(&replayed).enumerate() {
            if let Op::Auth { .. } = r.op {
                *counts.entry(format!("{:?}", r.out)).or_default() += 1;
            }
            if r != p {
                differences.push(format!(
                    "scenario {i}, step {j}: {:?}\n  recorded {:?} {:?}\n  replayed {:?} {:?}",
                    r.op, r.out, r.grants, p.out, p.grants
                ));
            }
        }
    }
    std::println!("authorization outcomes: {counts:?}");
    assert!(
        differences.is_empty(),
        "{} differences:\n{}",
        differences.len(),
        differences.join("\n")
    );
}
