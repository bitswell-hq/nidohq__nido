//! The grant signer (`contracts/grant-signer`) on a Nido account, under
//! enforcing authorization: the account is minted by Nido's factory, its
//! document declares the grant signer as a delegated signer of the rules
//! agents act through, and every agent authorization is one
//! `AddressWithDelegates` entry carrying the holder's ed25519 signature.
//! Admin operations go through the account's `execute`, authorized by the
//! owner passkey through the admin rule.
//!
//! A refused call reports only the host's outer `InvalidAction`, so each
//! agent call runs to its panic and [`Outcome`] reads the host's event log
//! from it: which contract refused, and with which error. Every entry
//! builder is exercised by a passing call too.
//!
//! `cargo test -p nido-integration-tests --test it grant_signer -- --nocapture`
//! prints the cost rows of `enforce_costs`.

use ed25519_dalek::{Signer as _, SigningKey};
use grant_eval::chain;
use nido_grant_signer::{Arg, Caveat, Grant, GrantError, GrantSignature, GrantSignerClient};
use nido_integration_tests::world::{
    strkey, world, Account, Passkey, TargetClient, World, NETWORK,
};
use nido_integration_tests::GRANT_SIGNER_WASM;
use perch_smart_account::PerchAuthError;
use soroban_sdk::auth::{
    Context, ContractContext, ContractExecutable, CreateContractHostFnContext,
    CreateContractWithConstructorHostFnContext,
};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::xdr::{
    AccountId, ContractIdPreimage, ContractIdPreimageFromAddress, CreateContractArgsV2,
    HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, InvokeContractArgs, Limits, MuxedEd25519Account,
    PublicKey, ScAddress, ScVal, SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, SorobanDelegateSignature, StringM, Uint256, VecM, WriteXdr,
};
use soroban_sdk::{
    contract, contractimpl, Address, Bytes, BytesN, Env, IntoVal, InvokeError, Map, Symbol,
    TryFromVal, Val, Vec,
};
use std::cell::Cell;
use std::format;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::string::String;
use stellar_accounts::smart_account::{AuthPayload, Signer};

/// A dApp that moves the account's tokens inside its own call: the nested
/// `transfer` needs the account's authorization too, so it is a second
/// context of the same authorization.
#[contract]
pub struct Router;

#[contractimpl]
impl Router {
    #[allow(clippy::needless_pass_by_value)]
    pub fn forward(e: Env, account: Address, token: Address, to: Address, amount: i128) {
        account.require_auth();
        TokenClient::new(&e, &token).transfer(&account, &to, &amount);
    }
}

/// Deploys a grant signer wasm with `deployer` as the deploying address,
/// which needs `deployer`'s authorization of the creation.
#[contract]
pub struct Deployer;

#[contractimpl]
impl Deployer {
    #[allow(clippy::needless_pass_by_value)]
    pub fn deploy(e: Env, deployer: Address, wasm: BytesN<32>, salt: BytesN<32>) -> Address {
        e.deployer()
            .with_address(deployer.clone(), salt)
            .deploy_contract(soroban_sdk::ContractExecutable::Wasm(wasm), (deployer,))
    }
}

/// Calls `Router::forward` and catches its failure: the account's
/// authorization is then asked for inside a call whose failure the
/// transaction survives.
#[contract]
pub struct Catcher;

#[contractimpl]
impl Catcher {
    /// Whether `router.forward(account, token, to, amount)` succeeded.
    #[allow(clippy::needless_pass_by_value)]
    pub fn catch_forward(
        e: Env,
        router: Address,
        account: Address,
        token: Address,
        to: Address,
        amount: i128,
    ) -> bool {
        let args: Vec<Val> = (account, token, to, amount).into_val(&e);
        e.try_invoke_contract::<(), InvokeError>(&router, &Symbol::new(&e, "forward"), args)
            .is_ok()
    }
}

/// The account's starting balance in the budget asset.
const BALANCE: i128 = 1_000;

/// How a call went.
#[derive(Debug, PartialEq)]
enum Outcome {
    Ok,
    /// The grant signer returned this error.
    Refused(GrantError),
    /// An authentication failed without the grant signer returning an
    /// error, with this error as the host's event log prints it (for
    /// example `Error(Contract, #3002)`).
    AuthFailed(String),
    /// The call failed otherwise; the panic message's first line.
    Other(String),
}

/// A document rule signed by the grant signer that no correct document for
/// agents has, used to show the grant signer's own guards hold whatever
/// rule the account matches.
#[derive(Clone, Copy)]
enum Misrule {
    /// `a-self`, scoped to the account itself.
    SelfAdmin,
    /// `a-signer`, scoped to the grant signer.
    Signer,
}

struct Fixture {
    w: World,
    account: Account,
    /// The account's grant signer.
    signer: Address,
    /// The budget asset (a Stellar Asset Contract).
    asset: Address,
    router: Address,
    bob: Address,
    carol: Address,
    nonce: Cell<i64>,
}

/// An agent's ed25519 key.
fn agent(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey(env: &Env, key: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &key.verifying_key().to_bytes())
}

fn contract_scope(contract: &Address) -> String {
    format!(r#"{{"type":"contract","address":"{}"}}"#, strkey(contract))
}

fn refused(e: GrantError) -> Outcome {
    Outcome::Refused(e)
}

/// The account's own refusal of a context no rule matches.
/// The account refuses the context before any signer is asked: rule-eval
/// allows it under no rule the payload chooses.
fn unvalidated() -> Outcome {
    Outcome::AuthFailed(format!(
        "Error(Contract, #{})",
        PerchAuthError::RuleEvalRefused as u32
    ))
}

impl Fixture {
    fn new(label: &str) -> Self {
        Self::with_rule(label, None)
    }

    /// A fixture whose document also has the `extra` rule.
    fn with_rule(label: &str, extra: Option<Misrule>) -> Self {
        let w = world();
        let account = w.mint(
            &format!("grants/{label}"),
            Passkey::labelled(&format!("grants/{label}/owner")),
            std::vec![],
        );
        let signer = w
            .env
            .register(GRANT_SIGNER_WASM, (account.address.clone(),));
        let issuer = Address::generate(&w.env);
        let asset = w.env.register_stellar_asset_contract_v2(issuer).address();
        let router = w.env.register(Router, ());
        w.env.mock_all_auths();
        StellarAssetClient::new(&w.env, &asset).mint(&account.address, &BALANCE);
        w.env.set_auths(&[]);
        let f = Fixture {
            bob: Address::generate(&w.env),
            carol: Address::generate(&w.env),
            w,
            account,
            signer,
            asset,
            router,
            // Clear of the world's own nonces for the same account.
            nonce: Cell::new(1 << 40),
        };
        let mut rules = std::vec![
            ("a-target", contract_scope(&f.w.target)),
            ("a-router", contract_scope(&f.router)),
            ("a-asset", contract_scope(&f.asset)),
        ];
        match extra {
            None => {}
            Some(Misrule::SelfAdmin) => {
                rules.push(("a-self", String::from(r#"{"type":"self-admin"}"#)));
            }
            Some(Misrule::Signer) => rules.push(("a-signer", contract_scope(&f.signer))),
        }
        f.w.apply_bytes_as(&f.account, "owner", &f.doc(&rules), 0)
            .expect("the agents' document applies");
        f
    }

    fn env(&self) -> &Env {
        &self.w.env
    }

    fn client(&self) -> GrantSignerClient<'_> {
        GrantSignerClient::new(self.env(), &self.signer)
    }

    /// The account's document: the owner passkey on the admin rule, the
    /// grant signer as delegated signer `grants`, and `rules` signed by it.
    fn doc(&self, rules: &[(&str, String)]) -> Bytes {
        let owner = hex::encode(self.account.key("owner").pubkey());
        let mut all = std::vec![String::from(
            r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#
        )];
        for (name, scope) in rules {
            all.push(format!(
                r#"{{"name":"{name}","scope":{scope},"principals":{{"type":"all","signers":["grants"]}}}}"#
            ));
        }
        let json = format!(
            r#"{{"version":1,"network":"{NETWORK}","signers":[{{"id":"owner","verifier":"{}","key":"{owner}"}},{{"id":"grants","address":"{}"}}],"rules":[{}]}}"#,
            strkey(&self.w.verifier),
            strkey(&self.signer),
            all.join(",")
        );
        Bytes::from_slice(self.env(), json.as_bytes())
    }

    fn next_nonce(&self) -> i64 {
        let n = self.nonce.get() + 1;
        self.nonce.set(n);
        n
    }

    // --- running calls -----------------------------------------------------

    /// Run `call` with exactly `entries` authorized.
    fn run(&self, entries: &[SorobanAuthorizationEntry], call: impl FnOnce()) -> Outcome {
        self.env().set_auths(entries);
        let result = catch_unwind(AssertUnwindSafe(call));
        self.env().set_auths(&[]);
        match result {
            Ok(()) => Outcome::Ok,
            Err(panic) => {
                let message = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| String::from(*s)))
                    .unwrap_or_default();
                self.outcome(&message)
            }
        }
    }

    /// Read a failed call's outcome from the host's event log in its panic
    /// message (newest event first).
    fn outcome(&self, message: &str) -> Outcome {
        let refusal = format!(
            "contract:{}, topics:[error, Error(Contract, #",
            strkey(&self.signer)
        );
        for line in message.lines() {
            if let Some(at) = line.find(&refusal) {
                let rest = &line[at + refusal.len()..];
                let code: u32 = rest[..rest.find(')').unwrap()].parse().unwrap();
                return Outcome::Refused(
                    GrantError::try_from(soroban_sdk::Error::from_contract_error(code)).unwrap(),
                );
            }
        }
        let auth = "\"failed account authentication with error\", ";
        for line in message.lines() {
            if let Some(at) = line.find(auth) {
                let rest = &line[at + auth.len()..];
                let error = &rest[rest.find(", ").unwrap() + 2..];
                return Outcome::AuthFailed(String::from(error.trim_end_matches(']')));
            }
        }
        Outcome::Other(String::from(message.lines().next().unwrap_or_default()))
    }

    // --- caveats -------------------------------------------------------------

    fn id(&self, a: &Address) -> Bytes {
        Bytes::from_slice(self.env(), strkey(a).as_bytes())
    }

    fn contract_in(&self, list: &[&Address]) -> Caveat {
        Caveat::ContractIn(Vec::from_iter(self.env(), list.iter().map(|a| self.id(a))))
    }

    fn function_in(&self, list: &[&str]) -> Caveat {
        Caveat::FunctionIn(Vec::from_iter(
            self.env(),
            list.iter()
                .map(|f| Bytes::from_slice(self.env(), f.as_bytes())),
        ))
    }

    fn arg_address(&self, index: u32, a: &Address) -> Caveat {
        Caveat::ArgEq(index, Arg::Address(self.id(a)))
    }

    fn caveats(&self, list: &[Caveat]) -> Vec<Caveat> {
        Vec::from_slice(self.env(), list)
    }

    // --- admin operations, through the account's `execute` -------------------

    /// Call `f(args)` on the grant signer as the account, authorized by the
    /// owner passkey through the admin rule.
    fn admin(&self, f: &str, args: &Vec<Val>) -> Outcome {
        let w = &self.w;
        let name = Symbol::new(self.env(), f);
        let root = w.invocation(
            &self.account.address,
            "execute",
            std::vec![
                w.sc(self.signer.clone()),
                w.sc(name.clone()),
                w.sc(args.clone())
            ],
        );
        let entry = w.signed(&self.account, "owner", "admin", root);
        self.run(&[entry], || {
            w.account(&self.account).execute(&self.signer, &name, args);
        })
    }

    fn issue_args(&self, key: &SigningKey, caveats: &[Caveat], allowance: u128) -> Vec<Val> {
        let e = self.env();
        Vec::from_array(
            e,
            [
                pubkey(e, key).into_val(e),
                self.caveats(caveats).into_val(e),
                self.asset.into_val(e),
                allowance.into_val(e),
            ],
        )
    }

    /// The owner issues a root grant; returns its id.
    fn issue(&self, key: &SigningKey, caveats: &[Caveat], allowance: u128) -> u32 {
        let next = (0..u32::MAX)
            .find(|id| self.client().grant(id).is_none())
            .unwrap();
        assert_eq!(
            self.admin("issue", &self.issue_args(key, caveats, allowance)),
            Outcome::Ok
        );
        next
    }

    fn revoke(&self, grant: u32) {
        let args = Vec::from_array(self.env(), [grant.into_val(self.env())]);
        assert_eq!(self.admin("revoke", &args), Outcome::Ok);
    }

    fn rotate(&self, grant: u32, key: &SigningKey) {
        let e = self.env();
        let args = Vec::from_array(e, [grant.into_val(e), pubkey(e, key).into_val(e)]);
        assert_eq!(self.admin("rotate", &args), Outcome::Ok);
    }

    fn refill(&self, grant: u32, extra: u128) {
        let e = self.env();
        let args = Vec::from_array(e, [grant.into_val(e), extra.into_val(e)]);
        assert_eq!(self.admin("refill", &args), Outcome::Ok);
    }

    fn grant(&self, id: u32) -> Grant {
        self.client().grant(&id).expect("grant exists")
    }

    // --- agent authorizations ----------------------------------------------

    /// The host's signature payload for an authorization of `root`. With
    /// `address` (delegated credentials), the preimage names the authorizing
    /// address, so the payload is bound to that one account.
    fn payload(
        &self,
        address: Option<&Address>,
        nonce: i64,
        expiration: u32,
        root: &SorobanAuthorizedInvocation,
    ) -> [u8; 32] {
        let network_id = soroban_sdk::xdr::Hash(self.env().ledger().network_id().to_array());
        let preimage = match address {
            Some(a) => HashIdPreimage::SorobanAuthorizationWithAddress(
                HashIdPreimageSorobanAuthorizationWithAddress {
                    network_id,
                    address: a.clone().into(),
                    nonce,
                    signature_expiration_ledger: expiration,
                    invocation: root.clone(),
                },
            ),
            None => HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
                network_id,
                nonce,
                signature_expiration_ledger: expiration,
                invocation: root.clone(),
            }),
        };
        self.env()
            .crypto()
            .sha256(&Bytes::from_slice(
                self.env(),
                &preimage.to_xdr(Limits::none()).unwrap(),
            ))
            .to_array()
    }

    fn grant_signature(&self, grant: u32, key: &SigningKey, payload: &[u8; 32]) -> ScVal {
        self.w.sc(GrantSignature {
            grant,
            signature: BytesN::from_array(self.env(), &key.sign(payload).to_bytes()),
        })
    }

    /// The account's authorization of `root`, given by grant `grant`'s
    /// holder `key` through the grant signer, with `rules` (one document rule
    /// name per context) as the account's rule selection.
    fn agent_entry(
        &self,
        grant: u32,
        key: &SigningKey,
        rules: &[&str],
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.next_nonce();
        let expiration = self.w.ledger() + 1_000;
        let payload = self.payload(Some(&self.account.address), nonce, expiration, &root);
        let mut signers: Map<Signer, Bytes> = Map::new(self.env());
        signers.set(
            Signer::Delegated(self.signer.clone()),
            Bytes::new(self.env()),
        );
        let context_rule_ids = Vec::from_iter(
            self.env(),
            rules
                .iter()
                .map(|r| self.w.rule_id(&self.account.address, r)),
        );
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::AddressWithDelegates(
                SorobanAddressCredentialsWithDelegates {
                    address_credentials: SorobanAddressCredentials {
                        address: self.account.address.clone().into(),
                        nonce,
                        signature_expiration_ledger: expiration,
                        signature: self.w.sc(AuthPayload {
                            signers,
                            context_rule_ids,
                        }),
                    },
                    delegates: std::vec![SorobanDelegateSignature {
                        address: self.signer.clone().into(),
                        signature: self.grant_signature(grant, key, &payload),
                        nested_delegates: VecM::default(),
                    }]
                    .try_into()
                    .unwrap(),
                },
            ),
            root_invocation: root,
        }
    }

    /// The grant signer's own authorization of `root`, given by grant
    /// `grant`'s holder `key`.
    fn signer_entry(
        &self,
        grant: u32,
        key: &SigningKey,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.next_nonce();
        let expiration = self.w.ledger() + 1_000;
        let payload = self.payload(None, nonce, expiration, &root);
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: self.signer.clone().into(),
                nonce,
                signature_expiration_ledger: expiration,
                signature: self.grant_signature(grant, key, &payload),
            }),
            root_invocation: root,
        }
    }

    /// `contract.f(args)`, authorized for the account by `grant`'s holder
    /// selecting `rules`.
    fn agent_call(
        &self,
        grant: u32,
        key: &SigningKey,
        rules: &[&str],
        contract: &Address,
        f: &str,
        args: &Vec<Val>,
    ) -> Outcome {
        let w = &self.w;
        let root = w.invocation(contract, f, args.iter().map(|v| w.sc(v)).collect());
        let entry = self.agent_entry(grant, key, rules, root);
        self.run(&[entry], || {
            self.env()
                .invoke_contract::<Val>(contract, &Symbol::new(self.env(), f), args.clone());
        })
    }

    /// `Target::protected(account)`, authorized by `grant`'s holder.
    fn protected(&self, grant: u32, key: &SigningKey) -> Outcome {
        let w = &self.w;
        let root = w.invocation(
            &w.target,
            "protected",
            std::vec![w.sc(self.account.address.clone())],
        );
        let entry = self.agent_entry(grant, key, &["a-target"], root);
        self.run(&[entry], || {
            TargetClient::new(&w.env, &w.target).protected(&self.account.address);
        })
    }

    /// The account's `transfer(account, to, amount)` of the budget asset,
    /// authorized by `grant`'s holder.
    fn transfer(&self, grant: u32, key: &SigningKey, to: &Address, amount: i128) -> Outcome {
        let e = self.env();
        let args = Vec::from_array(
            e,
            [
                self.account.address.into_val(e),
                to.into_val(e),
                amount.into_val(e),
            ],
        );
        self.agent_call(grant, key, &["a-asset"], &self.asset, "transfer", &args)
    }

    /// `Router::forward(account, asset, to, amount)`, whose nested transfer
    /// is the second context, authorized by `grant`'s holder.
    fn forward(&self, grant: u32, key: &SigningKey, to: &Address, amount: i128) -> Outcome {
        let entry = self.forward_entry(grant, key, to, amount);
        self.run(&[entry], || {
            RouterClient::new(self.env(), &self.router).forward(
                &self.account.address,
                &self.asset,
                to,
                &amount,
            );
        })
    }

    /// The authorization `forward` asks of the account: `Router::forward`,
    /// with the nested transfer as its second context.
    fn forward_entry(
        &self,
        grant: u32,
        key: &SigningKey,
        to: &Address,
        amount: i128,
    ) -> SorobanAuthorizationEntry {
        let w = &self.w;
        let mut root = w.invocation(
            &self.router,
            "forward",
            std::vec![
                w.sc(self.account.address.clone()),
                w.sc(self.asset.clone()),
                w.sc(to.clone()),
                w.sc(amount)
            ],
        );
        root.sub_invocations = std::vec![w.invocation(
            &self.asset,
            "transfer",
            std::vec![
                w.sc(self.account.address.clone()),
                w.sc(to.clone()),
                w.sc(amount)
            ],
        )]
        .try_into()
        .unwrap();
        self.agent_entry(grant, key, &["a-router", "a-asset"], root)
    }

    /// The same authorization as `forward`, asked for inside
    /// `Catcher::catch_forward`, which catches a failure of `forward`: the
    /// transaction's outcome, and whether `forward` succeeded.
    fn caught_forward(
        &self,
        catcher: &Address,
        grant: u32,
        key: &SigningKey,
        to: &Address,
        amount: i128,
    ) -> (Outcome, Option<bool>) {
        let entry = self.forward_entry(grant, key, to, amount);
        let forwarded = Cell::new(None);
        let outcome = self.run(&[entry], || {
            forwarded.set(Some(CatcherClient::new(self.env(), catcher).catch_forward(
                &self.router,
                &self.account.address,
                &self.asset,
                to,
                &amount,
            )));
        });
        (outcome, forwarded.get())
    }

    /// `delegate(parent, child, caveats, allowance)`, authorized as the grant
    /// signer by grant `signer`'s holder `key`. The child's id on success.
    fn delegate(
        &self,
        signer: u32,
        key: &SigningKey,
        parent: u32,
        child: &SigningKey,
        caveats: &[Caveat],
        allowance: u128,
    ) -> Result<u32, Outcome> {
        let w = &self.w;
        let child = pubkey(self.env(), child);
        let caveats = self.caveats(caveats);
        let root = w.invocation(
            &self.signer,
            "delegate",
            std::vec![
                w.sc(parent),
                w.sc(child.clone()),
                w.sc(caveats.clone()),
                w.sc(allowance)
            ],
        );
        let entry = self.signer_entry(signer, key, root);
        let id = Cell::new(None);
        match self.run(&[entry], || {
            id.set(Some(
                self.client()
                    .delegate(&parent, &child, &caveats, &allowance),
            ));
        }) {
            Outcome::Ok => Ok(id.get().unwrap()),
            other => Err(other),
        }
    }

    // --- the grant signer's own verdict --------------------------------------

    /// The grant signer's `__check_auth` on `contexts` for `grant`'s holder,
    /// called directly: for contexts the account never forwards.
    fn verdict(
        &self,
        grant: u32,
        key: &SigningKey,
        contexts: &[Context],
    ) -> Result<(), Result<GrantError, InvokeError>> {
        let payload = [0x5a; 32];
        let signature = GrantSignature {
            grant,
            signature: BytesN::from_array(self.env(), &key.sign(&payload).to_bytes()),
        };
        self.env().try_invoke_contract_check_auth::<GrantError>(
            &self.signer,
            &BytesN::from_array(self.env(), &payload),
            signature.into_val(self.env()),
            &Vec::from_slice(self.env(), contexts),
        )
    }

    fn context(&self, contract: &Address, f: &str, args: Vec<Val>) -> Context {
        Context::Contract(ContractContext {
            contract: contract.clone(),
            fn_name: Symbol::new(self.env(), f),
            args,
        })
    }

    fn protected_context(&self) -> Context {
        self.context(
            &self.w.target,
            "protected",
            Vec::from_array(self.env(), [self.account.address.into_val(self.env())]),
        )
    }

    fn transfer_context(&self, to: &Address, amount: i128) -> Context {
        let e = self.env();
        self.context(
            &self.asset,
            "transfer",
            Vec::from_array(
                e,
                [
                    self.account.address.into_val(e),
                    to.into_val(e),
                    amount.into_val(e),
                ],
            ),
        )
    }

    fn balance(&self, a: &Address) -> i128 {
        TokenClient::new(self.env(), &self.asset).balance(a)
    }
}

// ---------------------------------------------------------------------------
// Allowed and disallowed calls
// ---------------------------------------------------------------------------

#[test]
fn allowed_call_passes() {
    let f = Fixture::new("allowed");
    let a = agent(1);
    let g = f.issue(
        &a,
        &[f.contract_in(&[&f.w.target]), f.function_in(&["protected"])],
        0,
    );
    assert_eq!(f.protected(g, &a), Outcome::Ok);
    assert_eq!(f.protected(g, &a), Outcome::Ok);
}

#[test]
fn disallowed_function_or_contract_is_denied() {
    let f = Fixture::new("function");
    let a = agent(1);
    let wrong_function = f.issue(
        &a,
        &[f.contract_in(&[&f.w.target]), f.function_in(&["other"])],
        0,
    );
    assert_eq!(
        f.protected(wrong_function, &a),
        refused(GrantError::NotAllowed)
    );
    let wrong_contract = f.issue(&a, &[f.contract_in(&[&f.router])], 0);
    assert_eq!(
        f.protected(wrong_contract, &a),
        refused(GrantError::NotAllowed)
    );
}

#[test]
fn disallowed_argument_is_denied() {
    let f = Fixture::new("argument");
    let a = agent(1);
    let g = f.issue(
        &a,
        &[
            f.contract_in(&[&f.asset]),
            f.arg_address(1, &f.bob),
            Caveat::ArgI128AtMost(2, 100),
        ],
        1_000,
    );
    // To bob, within the per-call bound: allowed.
    assert_eq!(f.transfer(g, &a, &f.bob, 100), Outcome::Ok);
    assert_eq!(f.balance(&f.bob), 100);
    // Over the bound, or to anyone else: denied.
    assert_eq!(
        f.transfer(g, &a, &f.bob, 101),
        refused(GrantError::NotAllowed)
    );
    assert_eq!(
        f.transfer(g, &a, &f.carol, 1),
        refused(GrantError::NotAllowed)
    );
    assert_eq!(f.balance(&f.bob), 100);
    assert_eq!(f.balance(&f.carol), 0);
}

#[test]
fn hidden_nested_call_is_denied() {
    let f = Fixture::new("nested");
    let a = agent(1);
    // The router is allowed; the transfer it makes inside its call is not.
    let g = f.issue(&a, &[f.contract_in(&[&f.router])], 1_000);
    assert_eq!(
        f.forward(g, &a, &f.bob, 10),
        refused(GrantError::NotAllowed)
    );
    assert_eq!(f.balance(&f.account.address), BALANCE);

    // Leaving the nested transfer out of the signed tree does not hide it:
    // the host refuses the `require_auth` the entry does not cover.
    let env = f.env();
    let args = Vec::from_array(
        env,
        [
            f.account.address.into_val(env),
            f.asset.into_val(env),
            f.bob.into_val(env),
            10i128.into_val(env),
        ],
    );
    assert!(matches!(
        f.agent_call(g, &a, &["a-router"], &f.router, "forward", &args),
        Outcome::Other(_)
    ));
    assert_eq!(f.balance(&f.account.address), BALANCE);

    // A grant that allows both contracts authorizes the same tree.
    let b = agent(2);
    let both = f.issue(&b, &[f.contract_in(&[&f.router, &f.asset])], 1_000);
    assert_eq!(f.forward(both, &b, &f.bob, 10), Outcome::Ok);
    assert_eq!(f.balance(&f.bob), 10);
}

#[test]
fn contract_deployment_is_denied() {
    let f = Fixture::new("deploy");
    let a = agent(1);
    let g = f.issue(&a, &[f.contract_in(&[&f.w.target])], 0);
    // An empty grant: no caveat stands in the way, only the guard.
    let empty = f.issue(&a, &[], 0);

    // The grant signer refuses a creation context under every grant, alone
    // or behind an allowed call, with or without constructor arguments.
    let env = f.env();
    let wasm_hash = BytesN::from_array(env, &[7; 32]);
    let salt = BytesN::from_array(env, &[1; 32]);
    let creations = [
        Context::CreateContractHostFn(CreateContractHostFnContext {
            executable: ContractExecutable::Wasm(wasm_hash.clone()),
            salt: salt.clone(),
        }),
        Context::CreateContractWithCtorHostFn(CreateContractWithConstructorHostFnContext {
            executable: ContractExecutable::Wasm(wasm_hash),
            salt,
            constructor_args: Vec::from_array(env, [f.account.address.into_val(env)]),
        }),
    ];
    for grant in [g, empty] {
        for create in &creations {
            assert_eq!(
                f.verdict(grant, &a, std::slice::from_ref(create)),
                Err(Ok(GrantError::ContractCreation))
            );
            assert_eq!(
                f.verdict(grant, &a, &[f.protected_context(), create.clone()]),
                Err(Ok(GrantError::ContractCreation))
            );
        }
        assert_eq!(f.verdict(grant, &a, &[f.protected_context()]), Ok(()));
    }

    // `creation(by)` is a deployment with `by` as the deploying address;
    // `deploy(by, entry)` runs it, authorized by `entry`.
    let w = &f.w;
    let wasm = w.env.deployer().upload_contract_wasm(GRANT_SIGNER_WASM);
    let salt = BytesN::from_array(&w.env, &[3; 32]);
    let deployer = w.env.register(Deployer, ());
    let creation = |by: &Address| SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::CreateContractV2HostFn(CreateContractArgsV2 {
            contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: by.clone().into(),
                salt: Uint256(salt.to_array()),
            }),
            executable: soroban_sdk::xdr::ContractExecutable::Wasm(soroban_sdk::xdr::Hash(
                wasm.to_array(),
            )),
            constructor_args: std::vec![w.sc(by.clone())].try_into().unwrap(),
        }),
        sub_invocations: VecM::default(),
    };
    let deploy = |by: &Address, entry: SorobanAuthorizationEntry| {
        f.run(&[entry], || {
            DeployerClient::new(&w.env, &deployer).deploy(by, &wasm, &salt);
        })
    };

    for grant in [g, empty] {
        // Through the account, a deployment with the account as deployer has
        // no rule to select (document rules are scoped to contracts), so the
        // account refuses it before any signer is asked.
        let account = &f.account.address;
        let entry = f.agent_entry(grant, &a, &["a-target"], creation(account));
        assert_eq!(deploy(account, entry), unvalidated());

        // As the grant signer's own address (its second role), no document
        // applies; the grant signer refuses the deployment itself.
        let entry = f.signer_entry(grant, &a, creation(&f.signer));
        assert_eq!(
            deploy(&f.signer, entry),
            refused(GrantError::ContractCreation)
        );
    }
}

/// The grant signer's `__check_auth` is also the custom-account check of its
/// own address, called with the same three arguments, so the guards and the
/// caveats apply alike in both roles (and `verdict`, which calls it
/// directly, stands for both). In this second role a holder authorizes only
/// as the grant signer's address, within its grant; that never counts as the
/// account's authorization.
#[test]
fn the_grant_signers_own_address_acts_only_for_itself_within_the_grant() {
    let f = Fixture::new("own-address");
    let a = agent(1);
    let empty = f.issue(&a, &[], 0);
    let router_only = f.issue(&a, &[f.contract_in(&[&f.router])], 0);
    let w = &f.w;
    let protected = |who: &Address, grant: u32| {
        let root = w.invocation(&w.target, "protected", std::vec![w.sc(who.clone())]);
        let entry = f.signer_entry(grant, &a, root);
        f.run(&[entry], || {
            TargetClient::new(&w.env, &w.target).protected(who);
        })
    };

    // `protected(grant signer)` needs the grant signer's own authorization:
    // the empty grant gives it, and a grant that leaves out the target
    // refuses it.
    assert_eq!(protected(&f.signer, empty), Outcome::Ok);
    assert_eq!(
        protected(&f.signer, router_only),
        refused(GrantError::NotAllowed)
    );

    // The same holder's signature as the grant signer's address authorizes
    // nothing for the account.
    let out = protected(&f.account.address, empty);
    assert!(matches!(out, Outcome::Other(_)), "{out:?}");

    // In this role too, a call on the account, an unmetered call on the
    // budget asset and a call on the grant signer other than the holder's
    // own delegation are refused under the empty grant.
    let e = f.env();
    let approve = f.context(
        &f.asset,
        "approve",
        Vec::from_array(
            e,
            [
                f.signer.into_val(e),
                f.bob.into_val(e),
                1i128.into_val(e),
                1u32.into_val(e),
            ],
        ),
    );
    for (context, error) in [
        (
            f.context(&f.account.address, "cancel_upgrade", Vec::new(e)),
            GrantError::AccountCall,
        ),
        (approve, GrantError::UnmeteredCall),
        (
            f.context(&f.signer, "refill", Vec::new(e)),
            GrantError::NotHolder,
        ),
    ] {
        assert_eq!(f.verdict(empty, &a, &[context]), Err(Ok(error)));
    }
}

// ---------------------------------------------------------------------------
// Self-escalation
// ---------------------------------------------------------------------------

/// The grant signer's admin functions, each with arguments that would widen
/// grant `g` or replace its key if they ran.
fn admin_calls(f: &Fixture, g: u32) -> std::vec::Vec<(&'static str, Vec<Val>)> {
    let e = f.env();
    std::vec![
        ("issue", f.issue_args(&agent(1), &[], u128::MAX)),
        ("revoke", Vec::from_array(e, [g.into_val(e)])),
        (
            "rotate",
            Vec::from_array(e, [g.into_val(e), pubkey(e, &agent(9)).into_val(e)]),
        ),
        (
            "refill",
            Vec::from_array(e, [g.into_val(e), 1_000_000u128.into_val(e)]),
        ),
    ]
}

#[test]
fn agent_cannot_call_the_grant_signers_admin_functions() {
    let a = agent(1);

    // Through the account: no document rule is scoped to the grant signer,
    // so the account has no rule to select.
    let f = Fixture::new("escalate-signer");
    let g = f.issue(&a, &[f.contract_in(&[&f.w.target])], 10);
    let before = f.grant(g);
    for (name, args) in admin_calls(&f, g) {
        assert_eq!(
            f.agent_call(g, &a, &["a-target"], &f.signer, name, &args),
            unvalidated(),
            "{name}"
        );
    }

    // With a document rule scoped to the grant signer for the agents, the
    // account asks the grant signer, which the host refuses to re-enter while
    // its admin function runs.
    let f2 = Fixture::with_rule("escalate-signer-rule", Some(Misrule::Signer));
    let g2 = f2.issue(&a, &[f2.contract_in(&[&f2.w.target])], 10);
    let before2 = f2.grant(g2);
    for (name, args) in admin_calls(&f2, g2) {
        assert_eq!(
            f2.agent_call(g2, &a, &["a-signer"], &f2.signer, name, &args),
            Outcome::AuthFailed(String::from("Error(Context, InvalidAction)")),
            "{name}"
        );
    }
    // Asked directly, the grant signer refuses every call on itself but a
    // delegation from the signing grant.
    assert_eq!(
        f2.verdict(
            g2,
            &a,
            &[f2.context(&f2.signer, "refill", Vec::new(f2.env()))]
        ),
        Err(Ok(GrantError::NotHolder))
    );

    // The grant signer's own address does not stand in for the account's.
    for (name, args) in admin_calls(&f, g) {
        let w = &f.w;
        let root = w.invocation(&f.signer, name, args.iter().map(|v| w.sc(v)).collect());
        let entry = f.signer_entry(g, &a, root);
        let out = f.run(&[entry], || {
            f.env()
                .invoke_contract::<Val>(&f.signer, &Symbol::new(f.env(), name), args.clone());
        });
        assert!(matches!(out, Outcome::Other(_)), "{name}: {out:?}");
    }

    assert_eq!(f.grant(g), before);
    assert_eq!(f2.grant(g2), before2);
    assert_eq!(f.client().grant(&(g + 1)), None);
    assert_eq!(f2.client().grant(&(g2 + 1)), None);
}

#[test]
fn agent_cannot_change_the_accounts_rules_or_call_its_admin_functions() {
    let a = agent(1);
    for (label, misrule, rule) in [
        ("escalate-account", None, "a-target"),
        ("escalate-account-rule", Some(Misrule::SelfAdmin), "a-self"),
    ] {
        let f = Fixture::with_rule(label, misrule);
        // An empty grant: no caveat stands in the way, only the guards.
        let g = f.issue(&a, &[], 10);
        let env = f.env();
        let revision = f.w.account(&f.account).revision();
        let widened = f.doc(&[("a-target", String::from(r#"{"type":"self-admin"}"#))]);
        let refill: Vec<Val> = Vec::from_array(env, [g.into_val(env), 1_000u128.into_val(env)]);
        let calls: [(&str, Vec<Val>); 4] = [
            (
                "apply_doc",
                Vec::from_array(
                    env,
                    [
                        widened.into_val(env),
                        0u32.into_val(env),
                        Option::<u64>::None.into_val(env),
                    ],
                ),
            ),
            (
                "execute",
                Vec::from_array(
                    env,
                    [
                        f.signer.into_val(env),
                        Symbol::new(env, "refill").into_val(env),
                        refill.into_val(env),
                    ],
                ),
            ),
            (
                "schedule_upgrade",
                Vec::from_array(
                    env,
                    [
                        BytesN::from_array(env, &[1; 32]).into_val(env),
                        0u32.into_val(env),
                    ],
                ),
            ),
            ("cancel_upgrade", Vec::new(env)),
        ];
        for (name, args) in calls {
            let expected = match misrule {
                // The account's only rule for itself is the owner's.
                None => unvalidated(),
                // The document gave the agents a rule for the account; the
                // grant signer still refuses.
                Some(_) => refused(GrantError::AccountCall),
            };
            assert_eq!(
                f.agent_call(g, &a, &[rule], &f.account.address, name, &args),
                expected,
                "{label}: {name}"
            );
        }
        assert_eq!(f.w.account(&f.account).revision(), revision);
        assert_eq!(f.w.account(&f.account).pending_upgrade(), None);
        assert_eq!(f.grant(g).allowance, 10);
    }
}

#[test]
fn agent_cannot_edit_its_grant_by_delegating_from_another() {
    let f = Fixture::new("escalate-delegate");
    let (a, b) = (agent(1), agent(2));
    let root = f.issue(&a, &[f.contract_in(&[&f.w.target, &f.asset])], 100);
    let child = f
        .delegate(root, &a, root, &b, &[f.contract_in(&[&f.w.target])], 10)
        .expect("the root's holder delegates");
    // The child's holder cannot delegate from the root (which would hand it
    // the root's grant without its own caveats), nor from a grant id it does
    // not hold.
    assert_eq!(
        f.delegate(child, &b, root, &b, &[], 1_000),
        Err(refused(GrantError::NotHolder))
    );
    assert_eq!(
        f.delegate(child, &b, child + 1, &b, &[], 1_000),
        Err(refused(GrantError::NotHolder))
    );
    // Claiming the root with its own key fails the root's signature check.
    assert!(matches!(
        f.delegate(root, &b, root, &b, &[], 1_000),
        Err(Outcome::AuthFailed(e)) if e.contains("Crypto")
    ));
    assert_eq!(f.client().grant(&(child + 1)), None);
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

#[test]
fn delegation_narrows_and_cannot_widen() {
    let f = Fixture::new("delegation");
    let (a, b, c) = (agent(1), agent(2), agent(3));
    let root_caveats = [f.contract_in(&[&f.w.target, &f.asset])];
    let root = f.issue(&a, &root_caveats, 100);
    assert_eq!(f.protected(root, &a), Outcome::Ok);
    assert_eq!(f.transfer(root, &a, &f.bob, 1), Outcome::Ok);

    // b gets the root's caveats followed by "target only".
    let added = [f.contract_in(&[&f.w.target])];
    let child = f
        .delegate(root, &a, root, &b, &added, 50)
        .expect("the root's holder delegates");
    let stored = f.grant(child);
    assert_eq!(stored.parent, Some(root));
    assert_eq!(stored.asset, f.asset);
    assert_eq!(
        stored.caveats,
        f.caveats(&[root_caveats[0].clone(), added[0].clone()])
    );
    assert_eq!(f.protected(child, &b), Outcome::Ok);
    assert_eq!(
        f.transfer(child, &b, &f.bob, 1),
        refused(GrantError::NotAllowed)
    );

    // c's added caveat names the router, which neither ancestor allows: an
    // added caveat only narrows, so c can reach nothing at all.
    let grandchild = f
        .delegate(child, &b, child, &c, &[f.contract_in(&[&f.router])], 50)
        .expect("the child's holder delegates");
    assert_eq!(
        f.forward(grandchild, &c, &f.bob, 1),
        refused(GrantError::NotAllowed)
    );
    assert_eq!(f.protected(grandchild, &c), refused(GrantError::NotAllowed));
    assert_eq!(
        f.transfer(grandchild, &c, &f.bob, 1),
        refused(GrantError::NotAllowed)
    );

    // A delegation adding nothing is the parent's grant exactly.
    let copy = f
        .delegate(root, &a, root, &c, &[], 100)
        .expect("the root's holder delegates");
    assert_eq!(f.grant(copy).caveats, f.caveats(&root_caveats));
    assert_eq!(f.protected(copy, &c), Outcome::Ok);
}

// ---------------------------------------------------------------------------
// Budgets
// ---------------------------------------------------------------------------

#[test]
fn oversubscribed_siblings_are_safe_and_an_overdrawn_ancestor_changes_nothing() {
    let f = Fixture::new("budget");
    let (a, b1, b2) = (agent(1), agent(2), agent(3));
    let root = f.issue(&a, &[f.contract_in(&[&f.asset, &f.router])], 100);
    // Siblings whose allowances sum to 160 under a root of 100.
    let s1 = f.delegate(root, &a, root, &b1, &[], 80).expect("delegates");
    let s2 = f.delegate(root, &a, root, &b2, &[], 80).expect("delegates");

    assert_eq!(f.transfer(s1, &b1, &f.bob, 60), Outcome::Ok);
    assert_eq!((f.grant(root).spent, f.grant(s1).spent), (60, 60));

    // 50 fits s2 (0 + 50 <= 80) but not the root (60 + 50 > 100): the spend
    // fails and nothing changes, on the ledger or the asset.
    assert_eq!(f.client().overdrawn_at(&s2, &50), Some(root));
    assert_eq!(
        f.transfer(s2, &b2, &f.bob, 50),
        refused(GrantError::Overdrawn)
    );
    assert_eq!(
        (f.grant(root).spent, f.grant(s1).spent, f.grant(s2).spent),
        (60, 60, 0)
    );
    assert_eq!(f.balance(&f.bob), 60);

    // The root's remaining 40 is still spendable by either sibling.
    assert_eq!(f.transfer(s2, &b2, &f.bob, 40), Outcome::Ok);
    assert_eq!((f.grant(root).spent, f.grant(s2).spent), (100, 40));
    assert_eq!(
        f.transfer(s1, &b1, &f.bob, 1),
        refused(GrantError::Overdrawn)
    );
    assert_eq!(f.client().overdrawn_at(&s1, &1), Some(root));

    // Refilling the root is the owner's; then s1 can spend again, up to its
    // own allowance, where the next refill request would go.
    f.refill(root, 50);
    assert_eq!(f.client().overdrawn_at(&s1, &1), None);
    assert_eq!(f.transfer(s1, &b1, &f.bob, 20), Outcome::Ok);
    assert_eq!(f.client().overdrawn_at(&s1, &1), Some(s1));
    assert_eq!(
        f.transfer(s1, &b1, &f.bob, 1),
        refused(GrantError::Overdrawn)
    );
    assert_eq!(
        (f.grant(root).spent, f.grant(s1).spent, f.grant(s2).spent),
        (120, 80, 40)
    );
    assert_eq!((f.grant(root).allowance, f.grant(s1).allowance), (150, 80));
    assert_eq!(f.balance(&f.bob), 120);
}

#[test]
fn every_transfer_in_one_authorization_is_charged() {
    let f = Fixture::new("budget-tree");
    let a = agent(1);
    let g = f.issue(&a, &[f.contract_in(&[&f.asset, &f.router])], 100);
    // Two transfers of 60 in one authorization overdraw a budget of 100.
    assert_eq!(
        f.verdict(
            g,
            &a,
            &[
                f.transfer_context(&f.bob, 60),
                f.transfer_context(&f.bob, 60)
            ]
        ),
        Err(Ok(GrantError::Overdrawn))
    );
    assert_eq!(f.grant(g).spent, 0);
    // The router's nested transfer is metered like a direct one.
    assert_eq!(f.forward(g, &a, &f.bob, 70), Outcome::Ok);
    assert_eq!(f.grant(g).spent, 70);
    assert_eq!(f.forward(g, &a, &f.bob, 31), refused(GrantError::Overdrawn));
    assert_eq!(f.grant(g).spent, 70);
    assert_eq!(f.balance(&f.bob), 70);
}

/// A refused authorization fails the call that asked for it, not the
/// transaction: a caller can catch the failure and go on. The host then
/// rolls back that call's storage writes and authorization state, and the
/// grant signer charges in the `require_auth` of the authorization's root,
/// inside the call that encloses everything the authorization allows, so a
/// caught failure leaves no charge and a charge stays only with its calls.
#[test]
fn a_caught_refusal_or_failure_leaves_the_budget_as_if_the_call_never_ran() {
    let f = Fixture::new("budget-caught");
    let a = agent(1);
    let catcher = f.env().register(Catcher, ());
    let g = f.issue(&a, &[f.contract_in(&[&f.asset, &f.router])], 100);

    // Over the allowance: refused, and called directly the refusal fails the
    // transaction. Behind the catcher the transaction succeeds, and nothing
    // was charged or moved.
    assert_eq!(
        f.forward(g, &a, &f.bob, 150),
        refused(GrantError::Overdrawn)
    );
    assert_eq!(
        f.caught_forward(&catcher, g, &a, &f.bob, 150),
        (Outcome::Ok, Some(false))
    );
    assert_eq!((f.grant(g).spent, f.balance(&f.bob)), (0, 0));

    // Within the allowance but over the account's balance: the grant signer
    // charges, then the nested transfer fails. The caught failure rolls the
    // charge back with the call.
    // Called directly, the grant signer allows it and the asset contract's
    // balance check (its error #10) fails the transfer.
    f.refill(g, 4_900);
    assert!(
        matches!(
            f.forward(g, &a, &f.bob, 2 * BALANCE),
            Outcome::Other(ref m) if m.contains("Error(Contract, #10)")
        ),
        "the direct call fails in the transfer, not the authorization"
    );
    assert_eq!(f.grant(g).spent, 0);
    assert_eq!(
        f.caught_forward(&catcher, g, &a, &f.bob, 2 * BALANCE),
        (Outcome::Ok, Some(false))
    );
    assert_eq!((f.grant(g).spent, f.balance(&f.bob)), (0, 0));

    // An allowed call behind the catcher is charged once, with its transfer.
    assert_eq!(
        f.caught_forward(&catcher, g, &a, &f.bob, 60),
        (Outcome::Ok, Some(true))
    );
    assert_eq!((f.grant(g).spent, f.balance(&f.bob)), (60, 60));
}

#[test]
fn the_budget_asset_accepts_only_metered_transfers() {
    let f = Fixture::new("budget-unmetered");
    let a = agent(1);
    // No caveat names a function, so only the budget rule stands in the way.
    let g = f.issue(&a, &[f.contract_in(&[&f.asset])], 1_000);
    let e = f.env();
    let approve = Vec::from_array(
        e,
        [
            f.account.address.into_val(e),
            f.bob.into_val(e),
            500i128.into_val(e),
            10_000u32.into_val(e),
        ],
    );
    let burn = Vec::from_array(e, [f.account.address.into_val(e), 500i128.into_val(e)]);
    assert_eq!(
        f.agent_call(g, &a, &["a-asset"], &f.asset, "approve", &approve),
        refused(GrantError::UnmeteredCall)
    );
    assert_eq!(
        f.agent_call(g, &a, &["a-asset"], &f.asset, "burn", &burn),
        refused(GrantError::UnmeteredCall)
    );
    assert_eq!(
        f.verdict(g, &a, &[f.transfer_context(&f.bob, -1)]),
        Err(Ok(GrantError::UnmeteredCall))
    );
    assert_eq!(
        TokenClient::new(e, &f.asset).allowance(&f.account.address, &f.bob),
        0
    );
    assert_eq!(f.balance(&f.account.address), BALANCE);
}

// ---------------------------------------------------------------------------
// Revocation and key rotation
// ---------------------------------------------------------------------------

#[test]
fn revocation_cascades() {
    let f = Fixture::new("revoke");
    let (a, b, c) = (agent(1), agent(2), agent(3));
    let root = f.issue(&a, &[f.contract_in(&[&f.w.target])], 0);
    let child = f.delegate(root, &a, root, &b, &[], 0).expect("delegates");
    let grandchild = f.delegate(child, &b, child, &c, &[], 0).expect("delegates");
    for (g, k) in [(root, &a), (child, &b), (grandchild, &c)] {
        assert_eq!(f.protected(g, k), Outcome::Ok);
    }

    f.revoke(child);
    assert_eq!(f.protected(root, &a), Outcome::Ok);
    assert_eq!(f.protected(child, &b), refused(GrantError::Revoked));
    assert_eq!(f.protected(grandchild, &c), refused(GrantError::Revoked));
    // A revoked grant can no longer delegate.
    assert_eq!(
        f.delegate(child, &b, child, &c, &[], 0),
        Err(refused(GrantError::Revoked))
    );

    f.revoke(root);
    assert_eq!(f.protected(root, &a), refused(GrantError::Revoked));
}

#[test]
fn key_rotation_is_an_admin_action() {
    let f = Fixture::new("rotate");
    let (old, new) = (agent(1), agent(2));
    let g = f.issue(&old, &[f.contract_in(&[&f.w.target])], 0);
    assert_eq!(f.protected(g, &old), Outcome::Ok);
    f.rotate(g, &new);
    assert!(matches!(
        f.protected(g, &old),
        Outcome::AuthFailed(e) if e.contains("Crypto")
    ));
    assert_eq!(f.protected(g, &new), Outcome::Ok);
}

#[test]
fn issue_requires_a_stellar_asset_contract() {
    let f = Fixture::new("issue-asset");
    let e = f.env();
    let args = Vec::from_array(
        e,
        [
            pubkey(e, &agent(1)).into_val(e),
            Vec::<Caveat>::new(e).into_val(e),
            f.router.into_val(e),
            1u128.into_val(e),
        ],
    );
    assert_eq!(
        f.admin("issue", &args),
        refused(GrantError::NotStellarAsset)
    );
    assert_eq!(f.client().grant(&0), None);
}

// ---------------------------------------------------------------------------
// One mapping at both boundaries
// ---------------------------------------------------------------------------

/// The contract's form of a value `grant_relay::actions` produced.
fn arg(e: &Env, v: &chain::Val) -> Arg {
    match v {
        chain::Val::I128(n) => Arg::I128(*n),
        chain::Val::U64(n) => Arg::U64(*n),
        chain::Val::Bool(b) => Arg::Bool(*b),
        chain::Val::Bytes(b) => Arg::Bytes(Bytes::from_slice(e, b)),
        chain::Val::Address(b) => Arg::Address(Bytes::from_slice(e, b)),
        chain::Val::Symbol(b) => Arg::Symbol(Bytes::from_slice(e, b)),
        chain::Val::Other(b) => Arg::Other(Bytes::from_slice(e, b)),
    }
}

/// The relay maps a call's XDR to chain actions; the grant signer maps the
/// host's contexts. A caveat built from the relay's mapping of one value
/// holds, in the grant signer, for a context carrying exactly that value and
/// for no other, over every argument type: so the two boundaries read a
/// grant's bytes the same way.
#[test]
fn the_account_and_the_relay_map_actions_alike() {
    let f = Fixture::new("relay");
    let a = agent(1);
    let e = f.env();
    let account_g = ScVal::Address(ScAddress::Account(AccountId(
        PublicKey::PublicKeyTypeEd25519(Uint256([7; 32])),
    )));
    let muxed = ScVal::Address(ScAddress::MuxedAccount(MuxedEd25519Account {
        id: 42,
        ed25519: Uint256([7; 32]),
    }));
    let mut map: Map<u32, bool> = Map::new(e);
    map.set(1, true);
    let values: std::vec::Vec<Val> = std::vec![
        5i128.into_val(e),
        (-(1i128 << 100)).into_val(e),
        7u64.into_val(e),
        (u64::MAX - 1).into_val(e),
        true.into_val(e),
        Bytes::from_slice(e, b"bytes").into_val(e),
        BytesN::from_array(e, &[9u8; 32]).into_val(e),
        Symbol::new(e, "short").into_val(e),
        Symbol::new(e, "a_symbol_longer_than_nine").into_val(e),
        f.account.address.into_val(e),
        Val::try_from_val(e, &account_g).unwrap(),
        Val::try_from_val(e, &muxed).unwrap(),
        7u32.into_val(e),
        7i64.into_val(e),
        soroban_sdk::String::from_str(e, "short").into_val(e),
        Vec::<u32>::from_array(e, [1, 2]).into_val(e),
        map.into_val(e),
        ().into_val(e),
    ];
    for (i, v) in values.iter().enumerate() {
        let relay = grant_relay::actions::val(&ScVal::try_from_val(e, v).unwrap());
        let g = f.issue(&a, &[Caveat::ArgEq(0, arg(e, &relay))], 0);
        for (j, w) in values.iter().enumerate() {
            let context = f.context(&f.w.target, "f", Vec::from_array(e, [*w]));
            let expected = if i == j {
                Ok(())
            } else {
                Err(Ok(GrantError::NotAllowed))
            };
            assert_eq!(
                f.verdict(g, &a, &[context]),
                expected,
                "caveat {i}, argument {j}"
            );
        }
    }

    // Contract and function names.
    let call = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
        contract_address: f.w.target.clone().into(),
        function_name: StringM::try_from("protected").unwrap().into(),
        args: VecM::default(),
    });
    let chain::Action::Invoke {
        contract, function, ..
    } = grant_relay::actions::authorized_function(&call)
    else {
        panic!("a contract call");
    };
    let g = f.issue(
        &a,
        &[
            Caveat::ContractIn(Vec::from_array(e, [Bytes::from_slice(e, &contract)])),
            Caveat::FunctionIn(Vec::from_array(e, [Bytes::from_slice(e, &function)])),
        ],
        0,
    );
    assert_eq!(f.verdict(g, &a, &[f.protected_context()]), Ok(()));
}

// ---------------------------------------------------------------------------
// Costs
// ---------------------------------------------------------------------------

/// `n` caveats that all hold for `protected(account)`, so the evaluator
/// checks every one.
fn holding_caveats(f: &Fixture, n: usize) -> std::vec::Vec<Caveat> {
    let kinds = [
        f.contract_in(&[&f.w.target]),
        f.function_in(&["protected"]),
        f.arg_address(0, &f.account.address),
    ];
    (0..n).map(|i| kinds[i % kinds.len()].clone()).collect()
}

/// CPU instructions and memory bytes of the grant signer's `__check_auth`
/// (VM instantiation, lineage, signature, mapping, evaluation) for
/// `contexts`, from the wasm build.
fn check_auth_cost(f: &Fixture, grant: u32, key: &SigningKey, contexts: &[Context]) -> (u64, u64) {
    let mut budget = f.env().cost_estimate().budget();
    budget.reset_unlimited();
    assert_eq!(f.verdict(grant, key, contexts), Ok(()));
    (budget.cpu_instruction_cost(), budget.memory_bytes_cost())
}

#[test]
fn enforce_costs() {
    let f = Fixture::new("costs");
    let a = agent(1);
    for caveats in [1usize, 4, 16] {
        let g = f.issue(&a, &holding_caveats(&f, caveats), 0);
        let (cpu1, mem1) = check_auth_cost(&f, g, &a, &[f.protected_context()]);
        let five: std::vec::Vec<Context> = (0..5).map(|_| f.protected_context()).collect();
        let (cpu5, mem5) = check_auth_cost(&f, g, &a, &five);
        std::println!(
            "{{\"case\":\"check_auth\",\"caveats\":{caveats},\"contexts\":1,\"instructions\":{cpu1},\"mem_bytes\":{mem1}}}"
        );
        std::println!(
            "{{\"case\":\"check_auth\",\"caveats\":{caveats},\"contexts\":5,\"instructions\":{cpu5},\"mem_bytes\":{mem5}}}"
        );
        std::println!(
            "{{\"case\":\"per_extra_context\",\"caveats\":{caveats},\"instructions\":{},\"mem_bytes\":{}}}",
            (cpu5 - cpu1) / 4,
            (mem5 - mem1) / 4
        );
    }
    // One metered transfer, charged to the grant and stored.
    for caveats in [1usize, 4, 16] {
        let kinds = [f.contract_in(&[&f.asset]), f.function_in(&["transfer"])];
        let list: std::vec::Vec<Caveat> = (0..caveats).map(|i| kinds[i % 2].clone()).collect();
        let g = f.issue(&a, &list, 1_000_000);
        let (cpu, mem) = check_auth_cost(&f, g, &a, &[f.transfer_context(&f.bob, 10)]);
        std::println!(
            "{{\"case\":\"check_auth_metered_transfer\",\"caveats\":{caveats},\"contexts\":1,\"instructions\":{cpu},\"mem_bytes\":{mem}}}"
        );
    }
    // A whole agent transaction through the account: `protected` authorized
    // by a 4-caveat grant via the account's `__check_auth` and the grant
    // signer.
    let g = f.issue(&a, &holding_caveats(&f, 4), 0);
    assert_eq!(f.protected(g, &a), Outcome::Ok);
    let r = f.env().cost_estimate().resources();
    std::println!(
        "{{\"case\":\"agent_transaction\",\"caveats\":4,\"contexts\":1,\"instructions\":{},\"mem_bytes\":{}}}",
        r.instructions,
        r.mem_bytes
    );
}
