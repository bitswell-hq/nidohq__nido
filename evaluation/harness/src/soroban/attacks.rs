//! The attack suite against the grant signer on a factory-minted Perch
//! account, in the Soroban host under enforcing authorization.
//!
//! Every attempt is made by an agent the owner authorized and records the
//! component that refused it, its error, and whether balances, grants (and
//! their budget nodes) and the account's configuration are unchanged
//! afterwards. Control rows are allowed calls of the same shape, showing that
//! the refusal is the caveat's and not a broken call.

use ed25519_dalek::SigningKey;
use nido_grant_signer::{Arg, Caveat};
use nido_integration_tests::world::strkey;
use serde::Serialize;
use soroban_sdk::xdr::{
    ContractIdPreimage, ContractIdPreimageFromAddress, CreateContractArgsV2, MuxedEd25519Account,
    ScAddress, ScVal, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, Uint256, VecM,
};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, BytesN, Env, IntoVal, String as SorobanString, Symbol,
    TryFromVal, Val, Vec,
};

use super::fixture::{agent, pubkey, Fixture, Misrule};
use crate::outcome::Outcome;

/// Deploys a wasm with `deployer` as the deploying address, which needs
/// `deployer`'s authorization of the creation.
#[contract]
pub struct Deployer;

#[contractimpl]
impl Deployer {
    #[allow(clippy::needless_pass_by_value)]
    pub fn deploy(e: Env, deployer: Address, wasm: BytesN<32>, salt: BytesN<32>) -> Address {
        e.deployer()
            .with_address(deployer.clone(), salt)
            .deploy_v2(wasm, (deployer,))
    }
}

#[derive(Debug, Serialize)]
pub struct Row {
    pub id: String,
    pub category: &'static str,
    pub attempt: String,
    /// The enforcement point the attempt goes through.
    pub boundary: &'static str,
    /// An allowed call of the same shape, not an attack.
    pub control: bool,
    #[serde(flatten)]
    pub outcome: Outcome,
    pub state_unchanged: bool,
    pub changes: std::vec::Vec<String>,
    /// CPU instructions of the whole invocation (allowed or refused).
    pub cpu_instructions: i64,
}

struct Suite<'a> {
    rows: std::vec::Vec<Row>,
    wasm: &'a [u8],
}

impl Suite<'_> {
    fn record(
        &mut self,
        f: &Fixture,
        id: &str,
        category: &'static str,
        attempt: &str,
        control: bool,
        run: impl FnOnce() -> Outcome,
    ) -> Outcome {
        let before = f.snapshot();
        let outcome = run();
        let cpu = f.env().cost_estimate().resources().instructions;
        let after = f.snapshot();
        let changes = before.diff(&after);
        self.rows.push(Row {
            id: id.to_owned(),
            category,
            attempt: attempt.to_owned(),
            boundary: "soroban-simulation",
            control,
            state_unchanged: changes.is_empty(),
            changes,
            outcome: outcome.clone(),
            cpu_instructions: cpu,
        });
        outcome
    }
}

/// `contract.f(args)` for the account, authorized by `grant`'s holder with
/// `tree` as the signed authorization tree.
fn agent_call(
    f: &Fixture,
    grant: u32,
    key: &SigningKey,
    tree: SorobanAuthorizedInvocation,
    contract: &Address,
    func: &str,
    args: &Vec<Val>,
) -> Outcome {
    let entry = f.agent_entry(grant, key, None, tree);
    f.call(&[entry], contract, func, args)
}

/// A direct call whose signed tree is just that call.
fn direct(
    f: &Fixture,
    grant: u32,
    key: &SigningKey,
    contract: &Address,
    func: &str,
    args: &Vec<Val>,
) -> Outcome {
    let tree = f.node(contract, func, args, std::vec![]);
    agent_call(f, grant, key, tree, contract, func, args)
}

fn transfer(
    f: &Fixture,
    grant: u32,
    key: &SigningKey,
    token: &Address,
    to: &Address,
    amount: i128,
) -> Outcome {
    direct(
        f,
        grant,
        key,
        token,
        "transfer",
        &f.transfer_args(to, amount),
    )
}

/// `delegate(parent, child, caveats, allowance)` authorized as the grant
/// signer by `signer`'s holder `key`.
pub fn delegate(
    f: &Fixture,
    signer: u32,
    key: &SigningKey,
    parent: u32,
    child: &SigningKey,
    caveats: &[Caveat],
    allowance: u128,
) -> Outcome {
    let e = f.env();
    let args = Vec::from_array(
        e,
        [
            parent.into_val(e),
            pubkey(e, child).into_val(e),
            Vec::from_slice(e, caveats).into_val(e),
            allowance.into_val(e),
        ],
    );
    let root = f.node(&f.signer, "delegate", &args, std::vec![]);
    let entry = f.signer_entry(signer, key, root);
    f.call(&[entry], &f.signer, "delegate", &args)
}

/// Delegate and return the child's id.
fn child(
    f: &Fixture,
    signer: u32,
    key: &SigningKey,
    child_key: &SigningKey,
    caveats: &[Caveat],
    allowance: u128,
) -> u32 {
    let id = f.next_id();
    assert_eq!(
        delegate(f, signer, key, signer, child_key, caveats, allowance),
        Outcome::Allowed,
        "delegation"
    );
    id
}

/// The grant signer's own verdict on one context.
fn verdict(
    f: &Fixture,
    grant: u32,
    key: &SigningKey,
    context: soroban_sdk::auth::Context,
) -> Outcome {
    match f.verdict(grant, key, &[context]) {
        Ok(()) => Outcome::Allowed,
        Err(Ok(err)) => Outcome::refused("grant-signer", crate::outcome::grant_error(err as u32)),
        Err(Err(err)) => Outcome::refused("host", format!("{err:?}")),
    }
}

/// A Stellar account address (`G…`) for `seed`.
fn account_address(env: &Env, seed: u8) -> (Address, [u8; 32]) {
    let key = agent(seed).verifying_key().to_bytes();
    let s = stellar_strkey::ed25519::PublicKey(key).to_string();
    (Address::from_str(env, &s), key)
}

fn sc_to_val(env: &Env, v: &ScVal) -> Val {
    Val::try_from_val(env, v).expect("a host value")
}

/// Run the suite. `wasm` is the evaluation dApp.
#[must_use]
#[allow(
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::many_single_char_names
)]
pub fn run(wasm: &[u8]) -> std::vec::Vec<Row> {
    let mut s = Suite {
        rows: std::vec::Vec::new(),
        wasm,
    };
    let f = Fixture::new("attacks", s.wasm, 5, None);
    let e = f.env();
    let (pay, open, hop, router) = (agent(1), agent(4), agent(3), agent(2));
    let g_pay = f.issue(
        &pay,
        &[
            f.contract_in(&[&f.asset]),
            f.function_in(&["transfer"]),
            f.arg_address(1, &f.bob),
            Caveat::ArgI128AtMost(2, 100),
        ],
        500,
    );
    let g_open = f.issue(&open, &[], 10);
    let d: std::vec::Vec<&Address> = f.dapps.iter().collect();
    let g_hop = f.issue(
        &hop,
        &[f.contract_in(&d[..4]), f.function_in(&["hop"])],
        1_000,
    );
    let g_router = f.issue(
        &router,
        &[
            f.contract_in(&[d[0], &f.asset]),
            f.function_in(&["forward", "transfer"]),
        ],
        300,
    );
    let sub = agent(5);
    let g_sub = child(&f, g_pay, &pay, &sub, &[Caveat::ArgI128AtMost(2, 10)], 50);

    // --- self-escalation ---------------------------------------------------
    let cat = "self-escalation";
    let admin_calls: [(&str, Vec<Val>); 3] = [
        (
            "issue",
            Vec::from_array(
                e,
                [
                    pubkey(e, &open).into_val(e),
                    Vec::<Caveat>::new(e).into_val(e),
                    f.asset.into_val(e),
                    u128::MAX.into_val(e),
                ],
            ),
        ),
        (
            "refill",
            Vec::from_array(e, [g_open.into_val(e), 1_000_000u128.into_val(e)]),
        ),
        (
            "rotate",
            Vec::from_array(e, [g_open.into_val(e), pubkey(e, &agent(99)).into_val(e)]),
        ),
    ];
    for (name, args) in &admin_calls {
        s.record(
            &f,
            &format!("se-{name}-through-account"),
            cat,
            &format!("{name} on the grant signer, authorized for the account by the agent's grant"),
            false,
            || direct(&f, g_open, &open, &f.signer, name, args),
        );
        s.record(
            &f,
            &format!("se-{name}-as-grant-signer"),
            cat,
            &format!(
                "{name} on the grant signer, authorized by the agent as the grant signer itself"
            ),
            false,
            || {
                let root = f.node(&f.signer, name, args, std::vec![]);
                let entry = f.signer_entry(g_open, &open, root);
                f.call(&[entry], &f.signer, name, args)
            },
        );
    }
    let widened = f.doc(Some(&[(
        String::from("a-asset"),
        String::from(r#"{"type":"self-admin"}"#),
    )]));
    let account_calls: [(&str, Vec<Val>); 3] = [
        (
            "apply_doc",
            Vec::from_array(
                e,
                [
                    widened.into_val(e),
                    0u32.into_val(e),
                    Option::<u64>::None.into_val(e),
                ],
            ),
        ),
        (
            "execute",
            Vec::from_array(
                e,
                [
                    f.signer.into_val(e),
                    Symbol::new(e, "refill").into_val(e),
                    Vec::<Val>::from_array(e, [g_open.into_val(e), 1_000u128.into_val(e)])
                        .into_val(e),
                ],
            ),
        ),
        (
            "schedule_upgrade",
            Vec::from_array(
                e,
                [
                    BytesN::from_array(e, &[1; 32]).into_val(e),
                    0u32.into_val(e),
                ],
            ),
        ),
    ];
    for (name, args) in &account_calls {
        s.record(
            &f,
            &format!("se-account-{name}"),
            cat,
            &format!("the account's own {name}, authorized by an agent grant with no caveats"),
            false,
            || direct(&f, g_open, &open, &f.account.address, name, args),
        );
    }
    s.record(
        &f,
        "se-select-admin-rule",
        cat,
        "a transfer authorized by the agent through the owner's admin rule",
        false,
        || {
            let args = f.transfer_args(&f.bob, 1);
            let tree = f.node(&f.asset, "transfer", &args, std::vec![]);
            let entry = f.agent_entry(g_open, &open, Some(&["admin"]), tree);
            f.call(&[entry], &f.asset, "transfer", &args)
        },
    );
    s.record(
        &f,
        "se-delegate-from-parent",
        cat,
        "a sub-agent delegates from its parent's grant, dropping its own caveats",
        false,
        || delegate(&f, g_sub, &sub, g_pay, &sub, &[], 1_000),
    );
    s.record(
        &f,
        "se-delegate-unheld",
        cat,
        "a sub-agent delegates from a grant it does not hold",
        false,
        || delegate(&f, g_sub, &sub, g_open, &sub, &[], 1_000),
    );
    s.record(
        &f,
        "se-delegate-forged-signature",
        cat,
        "a sub-agent signs as its parent's grant with its own key",
        false,
        || delegate(&f, g_pay, &sub, g_pay, &sub, &[], 1_000),
    );

    // The same escalations against documents that wrongly give agents a rule
    // for the account or for the grant signer.
    let fs = Fixture::new("attacks-self-rule", s.wasm, 1, Some(Misrule::SelfAdmin));
    let fs_open = agent(4);
    let gs = fs.issue(&fs_open, &[], 10);
    let es = fs.env();
    let fs_calls: [(&str, Vec<Val>); 2] = [
        (
            "execute",
            Vec::from_array(
                es,
                [
                    fs.signer.into_val(es),
                    Symbol::new(es, "refill").into_val(es),
                    Vec::<Val>::from_array(es, [gs.into_val(es), 1_000u128.into_val(es)])
                        .into_val(es),
                ],
            ),
        ),
        (
            "schedule_upgrade",
            Vec::from_array(
                es,
                [
                    BytesN::from_array(es, &[1; 32]).into_val(es),
                    0u32.into_val(es),
                ],
            ),
        ),
    ];
    for (name, args) in &fs_calls {
        s.record(
            &fs,
            &format!("se-account-{name}-agent-rule-on-account"),
            cat,
            &format!("the account's own {name}, with a document that scopes an agent rule to the account"),
            false,
            || direct(&fs, gs, &fs_open, &fs.account.address, name, args),
        );
    }
    let fg = Fixture::new("attacks-signer-rule", s.wasm, 1, Some(Misrule::Signer));
    let fg_open = agent(4);
    let gg = fg.issue(&fg_open, &[], 10);
    let eg = fg.env();
    let refill = Vec::from_array(eg, [gg.into_val(eg), 1_000_000u128.into_val(eg)]);
    s.record(
        &fg,
        "se-refill-agent-rule-on-grant-signer",
        cat,
        "refill on the grant signer, with a document that scopes an agent rule to the grant signer",
        false,
        || direct(&fg, gg, &fg_open, &fg.signer, "refill", &refill),
    );

    // --- nested-call smuggling --------------------------------------------
    let cat = "nested-call smuggling";
    for depth in 1..=4usize {
        let path: std::vec::Vec<usize> = (0..depth).collect();
        let (to, args, tree) = f.hop(&path, &f.asset, &f.mallory, 10);
        s.record(
            &f,
            &format!("ns-transfer-at-depth-{}", depth + 1),
            cat,
            &format!(
                "a grant for hop on the dApp; the hop chain ({depth} call(s)) transfers the account's asset to the attacker at depth {}",
                depth + 1
            ),
            false,
            || agent_call(&f, g_hop, &hop, tree, &to, "hop", &args),
        );
    }
    let (to, args) = f.forward_args(0, &f.other, &f.mallory, 10);
    let tree = f.node(
        &to,
        "forward",
        &args,
        std::vec![f.transfer_node(&f.other, &f.mallory, 10)],
    );
    s.record(
        &f,
        "ns-forward-other-token",
        cat,
        "an allowed forward whose nested transfer is of a token the grant leaves out",
        false,
        || agent_call(&f, g_router, &router, tree, &to, "forward", &args),
    );
    let (to, args) = f.forward_args(0, &f.asset, &f.bob, 10);
    let tree = f.node(&to, "forward", &args, std::vec![]);
    s.record(
        &f,
        "ns-forward-transfer-left-out-of-tree",
        cat,
        "an allowed forward whose nested transfer the agent leaves out of the signed tree",
        false,
        || agent_call(&f, g_router, &router, tree, &to, "forward", &args),
    );
    let full = agent(11);
    let g_full = f.issue(
        &full,
        &[
            f.contract_in(&[d[0], d[1], d[2], d[3], &f.asset]),
            f.function_in(&["hop", "transfer"]),
        ],
        30,
    );
    let (to, args, tree) = f.hop(&[0, 1], &f.asset, &f.bob, 10);
    s.record(
        &f,
        "ns-control-transfer-at-depth-3",
        cat,
        "control: a grant for hop and transfer authorizes the depth-3 transfer",
        true,
        || agent_call(&f, g_full, &full, tree, &to, "hop", &args),
    );
    let (to, args, mut tree) = f.hop(&[0, 1], &f.asset, &f.bob, 10);
    let mut hops = tree.sub_invocations.to_vec();
    hops[0].sub_invocations = VecM::default();
    tree.sub_invocations = hops.try_into().unwrap();
    s.record(
        &f,
        "ns-transfer-at-depth-3-left-out-of-tree",
        cat,
        "the same depth-3 transfer with the transfer left out of the signed tree",
        false,
        || agent_call(&f, g_full, &full, tree, &to, "hop", &args),
    );
    let (to, args, tree) = f.hop(&[0, 1, 2], &f.asset, &f.bob, 25);
    s.record(
        &f,
        "ns-transfer-at-depth-4-over-allowance",
        cat,
        "a depth-4 transfer the caveats allow, larger than what is left of the allowance",
        false,
        || agent_call(&f, g_full, &full, tree, &to, "hop", &args),
    );

    // --- delegation workarounds -------------------------------------------
    let cat = "delegation workarounds";
    let w = &f.w;
    let wasm_hash = w
        .env
        .deployer()
        .upload_contract_wasm(nido_integration_tests::GRANT_SIGNER_WASM);
    let salt = BytesN::from_array(&w.env, &[3; 32]);
    let deployer = w.env.register(Deployer, ());
    s.record(
        &f,
        "dw-deploy-contract",
        cat,
        "deploy a contract with the account as deployer, under a grant with no caveats",
        false,
        || {
            let root = SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::CreateContractV2HostFn(CreateContractArgsV2 {
                    contract_id_preimage: ContractIdPreimage::Address(
                        ContractIdPreimageFromAddress {
                            address: f.account.address.clone().into(),
                            salt: Uint256(salt.to_array()),
                        },
                    ),
                    executable: soroban_sdk::xdr::ContractExecutable::Wasm(soroban_sdk::xdr::Hash(
                        wasm_hash.to_array(),
                    )),
                    constructor_args: std::vec![w.sc(f.account.address.clone())]
                        .try_into()
                        .unwrap(),
                }),
                sub_invocations: VecM::default(),
            };
            let entry = f.agent_entry(g_open, &open, Some(&["a-target"]), root);
            let args = Vec::from_array(
                e,
                [
                    f.account.address.into_val(e),
                    wasm_hash.into_val(e),
                    salt.into_val(e),
                ],
            );
            f.call(&[entry], &deployer, "deploy", &args)
        },
    );
    s.record(
        &f,
        "dw-deploy-contract-grant-signer-verdict",
        cat,
        "the grant signer's own verdict on a contract-creation context, for a one-caveat grant",
        false,
        || {
            let create = soroban_sdk::auth::Context::CreateContractHostFn(
                soroban_sdk::auth::CreateContractHostFnContext {
                    executable: soroban_sdk::auth::ContractExecutable::Wasm(BytesN::from_array(
                        e, &[7; 32],
                    )),
                    salt: BytesN::from_array(e, &[1; 32]),
                },
            );
            verdict(&f, g_hop, &hop, create)
        },
    );
    let fresh = w.mint(
        "attacks/mallory-account",
        nido_integration_tests::world::Passkey::labelled("mallory"),
        std::vec![],
    );
    s.record(
        &f,
        "dw-new-account-pinned-recipient",
        cat,
        "move the budget asset to a Nido account the attacker minted, under a grant that pins the recipient",
        false,
        || transfer(&f, g_pay, &pay, &f.asset, &fresh.address, 10),
    );
    s.record(
        &f,
        "dw-new-account-over-allowance",
        cat,
        "move more than the allowance to the attacker's new account, under a grant with no caveats",
        false,
        || transfer(&f, g_open, &open, &f.asset, &fresh.address, 11),
    );
    let exp = f.w.ledger() + 100;
    let approve = Vec::from_array(
        e,
        [
            f.account.address.into_val(e),
            f.mallory.into_val(e),
            1_000i128.into_val(e),
            exp.into_val(e),
        ],
    );
    s.record(
        &f,
        "dw-approve-budget-asset",
        cat,
        "approve the attacker to spend the budget asset, under a grant with no caveats",
        false,
        || direct(&f, g_open, &open, &f.asset, "approve", &approve),
    );
    let burn = Vec::from_array(e, [f.account.address.into_val(e), 1i128.into_val(e)]);
    s.record(
        &f,
        "dw-burn-budget-asset",
        cat,
        "burn the budget asset, under a grant with no caveats",
        false,
        || direct(&f, g_open, &open, &f.asset, "burn", &burn),
    );
    let other_key = agent(12);
    let g_other = f.issue(
        &other_key,
        &[f.contract_in(&[&f.other]), f.function_in(&["transfer"])],
        0,
    );
    s.record(
        &f,
        "dw-approve-other-token",
        cat,
        "approve the attacker on a token the grant allows only transfer of",
        false,
        || direct(&f, g_other, &other_key, &f.other, "approve", &approve),
    );
    let wide = agent(13);
    let g_wide = child(&f, g_pay, &pay, &wide, &[], 1_000_000);
    s.record(
        &f,
        "dw-sub-agent-wider-recipient",
        cat,
        "a sub-agent delegated with no added caveats and a larger allowance pays a recipient its parent's grant excludes",
        false,
        || transfer(&f, g_wide, &wide, &f.asset, &f.carol, 10),
    );
    s.record(
        &f,
        "dw-sub-agent-wider-amount",
        cat,
        "the same sub-agent pays more per call than its parent's grant allows",
        false,
        || transfer(&f, g_wide, &wide, &f.asset, &f.bob, 1_000),
    );

    // Type confusion: an argument of another type with the same bytes.
    let (dave, dave_key) = account_address(e, 77);
    let typed = agent(14);
    let g_dave = f.issue(
        &typed,
        &[
            f.contract_in(&[&f.asset]),
            f.function_in(&["transfer"]),
            f.arg_address(1, &dave),
        ],
        100,
    );
    let muxed = sc_to_val(
        e,
        &ScVal::Address(ScAddress::MuxedAccount(MuxedEd25519Account {
            id: 7,
            ed25519: Uint256(dave_key),
        })),
    );
    let muxed_args = Vec::from_array(
        e,
        [f.account.address.into_val(e), muxed, 10i128.into_val(e)],
    );
    s.record(
        &f,
        "dw-type-muxed-recipient",
        cat,
        "pay a muxed form (M…) of the one recipient the grant pins (G…)",
        false,
        || direct(&f, g_dave, &typed, &f.asset, "transfer", &muxed_args),
    );
    // A transfer to a `G…` account of this asset needs a trustline the
    // simulation does not create, so the control asks the grant signer alone.
    s.record(
        &f,
        "dw-type-control-pinned-recipient",
        cat,
        "control: the grant signer's verdict on a payment to the pinned recipient",
        true,
        || {
            let context =
                soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
                    contract: f.asset.clone(),
                    fn_name: Symbol::new(e, "transfer"),
                    args: f.transfer_args(&dave, 10),
                });
            verdict(&f, g_dave, &typed, context)
        },
    );
    let take = |v: Val| Vec::from_array(e, [f.account.address.into_val(e), v]);
    let u32_xdr = {
        use soroban_sdk::xdr::{Limits, WriteXdr};
        ScVal::U32(7).to_xdr(Limits::none()).unwrap()
    };
    let bob_strkey = strkey(&f.bob);
    let typed_cases: [(&str, &str, Caveat, Val, Val); 4] = [
        (
            "u64-for-i128-bound",
            "an amount bound on an i128 argument, given a u64",
            Caveat::ArgI128AtMost(1, 100),
            50u64.into_val(e),
            50i128.into_val(e),
        ),
        (
            "u32-for-bytes-of-its-xdr",
            "a bytes value pinned, given a u32 whose XDR is those bytes",
            Caveat::ArgEq(1, Arg::Bytes(Bytes::from_slice(e, &u32_xdr))),
            7u32.into_val(e),
            Bytes::from_slice(e, &u32_xdr).into_val(e),
        ),
        (
            "string-for-symbol",
            "a symbol pinned, given a string with the same text",
            Caveat::ArgEq(1, Arg::Symbol(Bytes::from_slice(e, b"approve"))),
            SorobanString::from_str(e, "approve").into_val(e),
            Symbol::new(e, "approve").into_val(e),
        ),
        (
            "address-for-bytes-of-its-strkey",
            "a bytes value pinned to an address's strkey, given that address",
            Caveat::ArgEq(1, Arg::Bytes(Bytes::from_slice(e, bob_strkey.as_bytes()))),
            f.bob.into_val(e),
            Bytes::from_slice(e, bob_strkey.as_bytes()).into_val(e),
        ),
    ];
    for (i, (name, what, caveat, bad, good)) in typed_cases.into_iter().enumerate() {
        let key = agent(30 + u8::try_from(i).expect("four cases"));
        let g = f.issue(
            &key,
            &[f.contract_in(&[d[0]]), f.function_in(&["take"]), caveat],
            0,
        );
        s.record(&f, &format!("dw-type-{name}"), cat, what, false, || {
            direct(&f, g, &key, d[0], "take", &take(bad))
        });
        s.record(
            &f,
            &format!("dw-type-control-{name}"),
            cat,
            "control: the same caveat given the value of the pinned type",
            true,
            || direct(&f, g, &key, d[0], "take", &take(good)),
        );
    }

    let revoked = agent(15);
    let g_rev = f.issue(&revoked, &[f.contract_in(&[&f.asset])], 100);
    let rev_child_key = agent(16);
    let g_rev_child = child(&f, g_rev, &revoked, &rev_child_key, &[], 100);
    assert_eq!(f.admin_grant_op("revoke", g_rev, None), Outcome::Allowed);
    s.record(
        &f,
        "dw-revoked-grant",
        cat,
        "spend under a revoked grant",
        false,
        || transfer(&f, g_rev, &revoked, &f.asset, &f.bob, 1),
    );
    s.record(
        &f,
        "dw-revoked-ancestor",
        cat,
        "spend under a grant whose parent was revoked",
        false,
        || transfer(&f, g_rev_child, &rev_child_key, &f.asset, &f.bob, 1),
    );
    let rotated = agent(17);
    let g_rot = f.issue(&rotated, &[f.contract_in(&[&f.asset])], 100);
    assert_eq!(
        f.admin_grant_op("rotate", g_rot, Some(pubkey(e, &agent(18)).into_val(e))),
        Outcome::Allowed
    );
    s.record(
        &f,
        "dw-rotated-old-key",
        cat,
        "sign with the holder key the owner rotated out",
        false,
        || transfer(&f, g_rot, &rotated, &f.asset, &f.bob, 1),
    );
    let args = f.transfer_args(&f.bob, 10);
    let entry = f.agent_entry(
        g_pay,
        &pay,
        None,
        f.node(&f.asset, "transfer", &args, std::vec![]),
    );
    s.record(
        &f,
        "dw-control-signed-payment",
        cat,
        "control: one signed payment",
        true,
        || f.call(std::slice::from_ref(&entry), &f.asset, "transfer", &args),
    );
    s.record(
        &f,
        "dw-replay-signed-payment",
        cat,
        "replay the same signed authorization entry",
        false,
        || f.call(std::slice::from_ref(&entry), &f.asset, "transfer", &args),
    );

    // --- allowance oversubscription ---------------------------------------
    let cat = "allowance oversubscription";
    let root_key = agent(20);
    let g_root = f.issue(
        &root_key,
        &[f.contract_in(&[&f.asset]), f.function_in(&["transfer"])],
        100,
    );
    let (k1, k2, k3) = (agent(21), agent(22), agent(23));
    let s1 = child(&f, g_root, &root_key, &k1, &[], 80);
    let s2 = child(&f, g_root, &root_key, &k2, &[], 80);
    let s3 = child(&f, g_root, &root_key, &k3, &[], 5);
    s.record(
        &f,
        "ao-control-first-sibling",
        cat,
        "control: the first of two siblings (allowance 80 each, root 100) spends 80",
        true,
        || transfer(&f, s1, &k1, &f.asset, &f.bob, 80),
    );
    s.record(
        &f,
        "ao-second-sibling-over-root",
        cat,
        "the second sibling spends 80 of its own 80, past what is left of the root's 100",
        false,
        || transfer(&f, s2, &k2, &f.asset, &f.bob, 80),
    );
    s.record(
        &f,
        "ao-child-over-own",
        cat,
        "a sibling with allowance 5 spends 10",
        false,
        || transfer(&f, s3, &k3, &f.asset, &f.bob, 10),
    );
    let k4 = agent(24);
    let gc = child(&f, s1, &k1, &k4, &[], 1_000_000);
    s.record(
        &f,
        "ao-grandchild-over-exhausted-parent",
        cat,
        "a grandchild with allowance 1,000,000 spends 1 under its exhausted parent",
        false,
        || transfer(&f, gc, &k4, &f.asset, &f.bob, 1),
    );
    s.record(
        &f,
        "ao-control-second-sibling-within-root",
        cat,
        "control: the second sibling spends what is left of the root",
        true,
        || transfer(&f, s2, &k2, &f.asset, &f.bob, 20),
    );
    s.rows
}
