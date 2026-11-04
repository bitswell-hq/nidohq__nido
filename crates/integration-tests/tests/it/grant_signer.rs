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
use nido_grant_signer::{
    Grant, GrantError, GrantSignature, GrantSignerClient, Step, StoredCap, StoredFunctions,
    StoredRule, StoredVal,
};
use nido_integration_tests::grants::{self, Arg, Caveat};
use nido_integration_tests::world::{
    strkey, world, Account, Enrolled, Mode, Passkey, Profile, TargetClient, World, DELAY, NETWORK,
};
use nido_integration_tests::GRANT_SIGNER_WASM;
use perch_account::PerchAccountError;
use perch_recovery::EvidenceDomain;
use perch_recovery_interface::RecoveryAction;
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
        let f = Self::on(w, account);
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

    /// A fixture on an account enrolled in guardian-only `Loss` recovery,
    /// whose admin document gives agents no rule: they act through scoped
    /// documents ([`Self::apply_scope`]).
    fn enrolled(label: &str) -> (Self, Enrolled) {
        let w = world();
        let enrolled = w.enrolled(&format!("grants/{label}"), Profile::Loss, Mode::Guardian);
        (Self::on(w, enrolled.account.clone()), enrolled)
    }

    /// The grant signer for `account`, the budget asset with the account's
    /// balance in it, and the router.
    fn on(w: World, account: Account) -> Self {
        let signer = w
            .env
            .register(GRANT_SIGNER_WASM, (account.address.clone(),));
        let issuer = Address::generate(&w.env);
        let asset = w.env.register_stellar_asset_contract_v2(issuer).address();
        let router = w.env.register(Router, ());
        w.env.mock_all_auths();
        StellarAssetClient::new(&w.env, &asset).mint(&account.address, &BALANCE);
        w.env.set_auths(&[]);
        Fixture {
            bob: Address::generate(&w.env),
            carol: Address::generate(&w.env),
            w,
            account,
            signer,
            asset,
            router,
            // Clear of the world's own nonces for the same account.
            nonce: Cell::new(1 << 40),
        }
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

    /// A scoped document of `rules`, each signed by the grant signer.
    fn scope_doc(&self, rules: &[(&str, String)]) -> Bytes {
        let all: std::vec::Vec<String> = rules
            .iter()
            .map(|(name, scope)| {
                format!(
                    r#"{{"name":"{name}","scope":{scope},"principals":{{"type":"all","signers":["grants"]}}}}"#
                )
            })
            .collect();
        let json = format!(
            r#"{{"version":1,"network":"{NETWORK}","signers":[{{"id":"grants","address":"{}"}}],"rules":[{}]}}"#,
            strkey(&self.signer),
            all.join(",")
        );
        Bytes::from_slice(self.env(), json.as_bytes())
    }

    /// `apply_scope(scope, doc)`, authorized by `owner`'s passkey through the
    /// admin rule.
    fn apply_scope(
        &self,
        owner: &Account,
        scope: u32,
        doc: &Bytes,
    ) -> Result<BytesN<32>, PerchAccountError> {
        let w = &self.w;
        let root = w.invocation(
            &self.account.address,
            "apply_scope",
            std::vec![w.sc(scope), w.sc(doc.clone())],
        );
        let entry = w.signed(owner, "owner", "admin", root);
        match w.with_auths(&[entry], || {
            w.account(&self.account).try_apply_scope(&scope, doc)
        }) {
            Ok(Ok(hash)) => Ok(hash),
            Err(Ok(e)) => Err(e),
            other => panic!("apply_scope: {other:?}"),
        }
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

    /// The rule set a root grant with `caveats` lowers to.
    fn root_rules(&self, caveats: &[Caveat]) -> Vec<StoredRule> {
        grants::root(self.env(), &self.signer, caveats)
    }

    /// Grant `id`'s rule set; empty when there is no such grant.
    fn rules(&self, id: u32) -> Vec<StoredRule> {
        match self.client().try_rules(&id) {
            Ok(Ok(rules)) => rules,
            _ => Vec::new(self.env()),
        }
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
                self.root_rules(caveats).into_val(e),
                self.asset.into_val(e),
                allowance.into_val(e),
            ],
        )
    }

    /// The owner issues a root grant with the rule set `caveats` lower to;
    /// returns its id.
    fn issue(&self, key: &SigningKey, caveats: &[Caveat], allowance: u128) -> u32 {
        self.issue_rules(key, &self.root_rules(caveats), allowance)
    }

    /// The owner issues a root grant with the rule set `rules`; returns its
    /// id.
    fn issue_rules(&self, key: &SigningKey, rules: &Vec<StoredRule>, allowance: u128) -> u32 {
        let next = (0..u32::MAX)
            .find(|id| self.client().grant(id).is_none())
            .unwrap();
        let e = self.env();
        let args = Vec::from_array(
            e,
            [
                pubkey(e, key).into_val(e),
                rules.into_val(e),
                self.asset.into_val(e),
                allowance.into_val(e),
            ],
        );
        assert_eq!(self.admin("issue", &args), Outcome::Ok);
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
        let ids: std::vec::Vec<u32> = rules
            .iter()
            .map(|r| self.w.rule_id(&self.account.address, r))
            .collect();
        self.agent_entry_ids(grant, key, &ids, root)
    }

    /// [`Self::agent_entry`], selecting the account's rules by OZ id.
    fn agent_entry_ids(
        &self,
        grant: u32,
        key: &SigningKey,
        ids: &[u32],
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
        let context_rule_ids = Vec::from_slice(self.env(), ids);
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
        self.protected_by(
            grant,
            key,
            self.w.rule_id(&self.account.address, "a-target"),
        )
    }

    /// `Target::protected(account)`, authorized by `grant`'s holder through
    /// the account's rule with OZ id `rule`.
    fn protected_by(&self, grant: u32, key: &SigningKey, rule: u32) -> Outcome {
        let w = &self.w;
        let root = w.invocation(
            &w.target,
            "protected",
            std::vec![w.sc(self.account.address.clone())],
        );
        let entry = self.agent_entry_ids(grant, key, &[rule], root);
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

    /// `delegate(parent, child, steps, allowance)` with the steps that add
    /// `caveats` to `parent`'s rule set, authorized as the grant signer by
    /// grant `signer`'s holder `key`. The child's id on success.
    fn delegate(
        &self,
        signer: u32,
        key: &SigningKey,
        parent: u32,
        child: &SigningKey,
        caveats: &[Caveat],
        allowance: u128,
    ) -> Result<u32, Outcome> {
        let steps = grants::steps(self.env(), &self.rules(parent), caveats);
        self.delegate_steps(signer, key, parent, child, &steps, allowance)
    }

    /// `delegate(parent, child, steps, allowance)`, authorized as the grant
    /// signer by grant `signer`'s holder `key`. The child's id on success.
    fn delegate_steps(
        &self,
        signer: u32,
        key: &SigningKey,
        parent: u32,
        child: &SigningKey,
        steps: &Vec<Step>,
        allowance: u128,
    ) -> Result<u32, Outcome> {
        let w = &self.w;
        let child = pubkey(self.env(), child);
        let root = w.invocation(
            &self.signer,
            "delegate",
            std::vec![
                w.sc(parent),
                w.sc(child.clone()),
                w.sc(steps.clone()),
                w.sc(allowance)
            ],
        );
        let entry = self.signer_entry(signer, key, root);
        let id = Cell::new(None);
        match self.run(&[entry], || {
            id.set(Some(
                self.client().delegate(&parent, &child, steps, &allowance),
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
    // A grant over every contract the test calls: only the guard stands in
    // the way (no rule allows a creation either).
    let wide = f.issue(&a, &[f.contract_in(&[&f.w.target, &f.router, &f.asset])], 0);

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
    for grant in [g, wide] {
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

    for grant in [g, wide] {
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
/// rule set apply alike in both roles (and `verdict`, which calls it
/// directly, stands for both). In this second role a holder authorizes only
/// as the grant signer's address, within its grant; that never counts as the
/// account's authorization.
#[test]
fn the_grant_signers_own_address_acts_only_for_itself_within_the_grant() {
    let f = Fixture::new("own-address");
    let a = agent(1);
    // A grant whose rules name every contract below, so that only the
    // guards refuse.
    let wide = f.issue(
        &a,
        &[f.contract_in(&[&f.w.target, &f.account.address, &f.asset, &f.signer])],
        0,
    );
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
    // a grant naming the target gives it, and a grant that leaves out the
    // target refuses it.
    assert_eq!(protected(&f.signer, wide), Outcome::Ok);
    assert_eq!(
        protected(&f.signer, router_only),
        refused(GrantError::NotAllowed)
    );

    // The same holder's signature as the grant signer's address authorizes
    // nothing for the account.
    let out = protected(&f.account.address, wide);
    assert!(matches!(out, Outcome::Other(_)), "{out:?}");

    // In this role too, a call on the account, an unmetered call on the
    // budget asset and a call on the grant signer other than the holder's
    // own delegation are refused under a grant whose rules name them.
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
        assert_eq!(f.verdict(wide, &a, &[context]), Err(Ok(error)));
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
        (
            "issue",
            f.issue_args(&agent(1), &[f.contract_in(&[&f.w.target])], u128::MAX)
        ),
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
        // A grant whose rules name the account: only the guards stand in the
        // way.
        let g = f.issue(&a, &[f.contract_in(&[&f.account.address])], 10);
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
    // the root's rule set without its own steps), nor from a grant id it
    // does not hold.
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

    // b gets the root's rule set without the asset's rule: "target only".
    let added = [f.contract_in(&[&f.w.target])];
    let child = f
        .delegate(root, &a, root, &b, &added, 50)
        .expect("the root's holder delegates");
    let stored = f.grant(child);
    assert_eq!(stored.parent, Some(root));
    assert_eq!(stored.asset, f.asset);
    assert_eq!(stored.steps, Vec::from_array(f.env(), [Step::DropRule(1)]));
    assert!(stored.rules.is_empty());
    assert_eq!(
        f.rules(child),
        f.root_rules(&[root_caveats[0].clone(), added[0].clone()])
    );
    assert_eq!(f.protected(child, &b), Outcome::Ok);
    assert_eq!(
        f.transfer(child, &b, &f.bob, 1),
        refused(GrantError::NotAllowed)
    );

    // c's added caveat names the router, which neither ancestor allows: it
    // drops the target's rule, so c's rule set is empty and reaches nothing
    // at all.
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
    assert!(f.grant(copy).steps.is_empty());
    assert_eq!(f.rules(copy), f.rules(root));
    assert_eq!(f.rules(root), f.root_rules(&root_caveats));
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
            Vec::<StoredRule>::new(e).into_val(e),
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
// Grants from scopes, and what rule sets add
// ---------------------------------------------------------------------------

/// The design's path end to end: the owner applies a scoped document for its
/// agents whose rule names this grant signer, issues a grant with the rule
/// set the account's `scope_rule_set` returns, and the agent authorizes
/// through the scoped rule; a delegation narrows it. A completed recovery
/// then ends the grant: the account refuses the wiped scope's rule
/// (`StaleScope`) before the grant signer is asked, and no document may name
/// this grant signer again (`WipedCredential`), so no later scope revives
/// its grants.
#[test]
fn a_grant_from_a_scope_acts_until_a_recovery_completes() {
    let (f, enrolled) = Fixture::enrolled("scope");
    let (a, b) = (agent(1), agent(2));
    let env = f.env();
    let doc = f.scope_doc(&[("a-target", contract_scope(&f.w.target))]);
    f.apply_scope(&f.account, 7, &doc)
        .expect("the owner applies the agents' scope");
    let account = f.w.account(&f.account);
    let rules = account.scope_rule_set(&7);
    assert_eq!(rules.len(), 1);
    assert_eq!(rules.get_unchecked(0).generation, Some(0));
    let id = account.scope(&7).unwrap().rules.get_unchecked(0).id;
    let grant = f.issue_rules(&a, &rules, 0);
    assert_eq!(f.rules(grant), rules);
    assert_eq!(f.protected_by(grant, &a, id), Outcome::Ok);

    // A delegation restricted to another function allows nothing on the
    // target.
    let other = Vec::from_array(env, [Symbol::new(env, "other")]);
    let steps = Vec::from_array(env, [Step::RestrictFunctions(0, other)]);
    let child = f
        .delegate_steps(grant, &a, grant, &b, &steps, 0)
        .expect("the grant's holder delegates");
    assert_eq!(
        f.protected_by(child, &b, id),
        refused(GrantError::NotAllowed)
    );

    // A guardian quorum recovers the account after the timelock.
    let w = &f.w;
    let new_owner = Passkey::labelled("grants/scope/new-owner");
    let source = account.applied_doc().unwrap();
    let replacements = w.replacements(&new_owner, None);
    let attempt = w
        .begin_lost_key(&f.account, &replacements)
        .expect("permissionless begin");
    for guardian in &enrolled.guardians[..2] {
        w.try_guardian(&f.account, guardian, attempt, EvidenceDomain::Initiate)
            .unwrap();
    }
    let target = w.target_bytes(&f.account, RecoveryAction::LostKey, &source, &replacements);
    w.advance(DELAY);
    w.complete(&f.account, &target).expect("anyone completes");
    assert_eq!(account.scope_generation(), 1);

    assert_eq!(
        f.protected_by(grant, &a, id),
        Outcome::AuthFailed(format!(
            "Error(Contract, #{})",
            PerchAuthError::StaleScope as u32
        ))
    );
    let mut recovered = f.account.clone();
    recovered.keys[0].1 = new_owner;
    assert_eq!(
        f.apply_scope(&recovered, 8, &doc),
        Err(PerchAccountError::WipedCredential)
    );
}

/// Removing an agent's scope ends its grants at the account: the owner's
/// `remove_scope` removes the scoped rule the grant was issued from, so the
/// agent's next authorization fails at the account although the grant
/// signer still holds the grant, unrevoked.
#[test]
fn an_agent_grant_lives_in_a_scope_and_ends_with_it() {
    let f = Fixture::new("scope-removed");
    let a = agent(1);
    let doc = f.scope_doc(&[("a-target", contract_scope(&f.w.target))]);
    f.apply_scope(&f.account, 9, &doc)
        .expect("the owner applies the agent's scope");
    let account = f.w.account(&f.account);
    let id = account.scope(&9).unwrap().rules.get_unchecked(0).id;
    let grant = f.issue_rules(&a, &account.scope_rule_set(&9), 0);
    assert_eq!(f.protected_by(grant, &a, id), Outcome::Ok);

    f.w.remove_scope_as(&f.account, "owner", 9)
        .expect("the owner removes the agent's scope");
    assert!(
        f.client().grant(&grant).is_some(),
        "the grant itself is not revoked"
    );
    // OZ's `ContextRuleNotFound`: the account no longer has the rule.
    assert_eq!(
        f.protected_by(grant, &a, id),
        Outcome::AuthFailed(String::from("Error(Contract, #3000)"))
    );
}

/// A spending cap a delegation adds to the budget asset's rule: within each
/// window of `period` ledgers the grant's transfers sum to at most the
/// cap's limit (`CapExceeded` past it, charging nothing), two transfers in
/// one authorization are charged one after the other, and the budget is
/// charged as before. The parent's rule keeps no cap.
#[test]
fn a_cap_added_by_delegation_bounds_spending_per_window() {
    let f = Fixture::new("cap");
    let (a, b) = (agent(1), agent(2));
    let e = f.env();
    let root = f.issue(&a, &[f.contract_in(&[&f.asset])], 1_000);
    let cap = StoredCap {
        limit: 100,
        period: 10,
        amount_arg: 2,
    };
    let child = f
        .delegate_steps(
            root,
            &a,
            root,
            &b,
            &Vec::from_array(e, [Step::AddCap(0, cap)]),
            1_000,
        )
        .expect("the root's holder delegates");
    let transfer = |amount| f.transfer_context(&f.bob, amount);
    assert_eq!(f.verdict(child, &b, &[transfer(60)]), Ok(()));
    assert_eq!(
        f.verdict(child, &b, &[transfer(60)]),
        Err(Ok(GrantError::CapExceeded))
    );
    assert_eq!(f.verdict(child, &b, &[transfer(40)]), Ok(()));
    assert_eq!(f.grant(child).spent, 100);

    f.w.advance(10);
    assert_eq!(
        f.verdict(child, &b, &[transfer(60), transfer(60)]),
        Err(Ok(GrantError::CapExceeded))
    );
    assert_eq!(f.grant(child).spent, 100, "a refusal charges nothing");
    assert_eq!(f.verdict(child, &b, &[transfer(50), transfer(50)]), Ok(()));
    assert_eq!(f.grant(child).spent, 200);
    assert_eq!(f.grant(root).spent, 200);

    assert_eq!(f.verdict(root, &a, &[transfer(500)]), Ok(()));
}

/// A last ledger a delegation sets: the rule authorizes up to and including
/// it (`Expired` after), and a later delegation cannot move it later.
#[test]
fn a_last_ledger_ends_a_rule() {
    let f = Fixture::new("expiry");
    let (a, b, c) = (agent(1), agent(2), agent(3));
    let env = f.env();
    let root = f.issue(&a, &[f.contract_in(&[&f.w.target])], 0);
    let last = f.w.ledger() + 5;
    let child = f
        .delegate_steps(
            root,
            &a,
            root,
            &b,
            &Vec::from_array(env, [Step::LowerValidUntil(0, last)]),
            0,
        )
        .expect("the root's holder delegates");
    assert_eq!(f.verdict(child, &b, &[f.protected_context()]), Ok(()));
    f.w.advance(5);
    assert_eq!(f.verdict(child, &b, &[f.protected_context()]), Ok(()));
    f.w.advance(1);
    assert_eq!(
        f.verdict(child, &b, &[f.protected_context()]),
        Err(Ok(GrantError::Expired))
    );
    assert_eq!(f.verdict(root, &a, &[f.protected_context()]), Ok(()));
    assert_eq!(
        f.delegate_steps(
            child,
            &b,
            child,
            &c,
            &Vec::from_array(env, [Step::LowerValidUntil(0, last + 100)]),
            0,
        ),
        Err(refused(GrantError::InvalidStep))
    );
}

/// The signer steps: removing the grant signer from a rule's signers, or
/// raising its threshold past the one signer the grant signer
/// authenticates, leaves a rule that allows nothing.
#[test]
fn signer_steps_narrow_to_nothing() {
    let f = Fixture::new("signers");
    let (a, b) = (agent(1), agent(2));
    let e = f.env();
    let root = f.issue(&a, &[f.contract_in(&[&f.w.target])], 0);
    let me = Vec::from_array(e, [Signer::Delegated(f.signer.clone())]);
    for step in [Step::RemoveSigners(0, me), Step::RaiseThreshold(0, 2)] {
        let child = f
            .delegate_steps(root, &a, root, &b, &Vec::from_array(e, [step]), 0)
            .expect("the root's holder delegates");
        assert_eq!(
            f.verdict(child, &b, &[f.protected_context()]),
            Err(Ok(GrantError::NotAllowed))
        );
    }
}

/// `issue` refuses a rule set `rule_eval::authorize` would not check as
/// issued: a cap that is not valid, more than one cap on a rule, or rules
/// of different generations. `delegate` refuses a step `rule_eval` refuses.
#[test]
fn issue_and_delegate_refuse_what_rule_eval_refuses() {
    let f = Fixture::new("refusals");
    let (a, b) = (agent(1), agent(2));
    let e = f.env();
    let issue = |rules: &Vec<StoredRule>| {
        let args = Vec::from_array(
            e,
            [
                pubkey(e, &a).into_val(e),
                rules.into_val(e),
                f.asset.into_val(e),
                0u128.into_val(e),
            ],
        );
        f.admin("issue", &args)
    };
    let one = f.root_rules(&[f.contract_in(&[&f.w.target])]);
    let with = |change: &dyn Fn(&mut StoredRule)| {
        let mut rules = one.clone();
        let mut rule = rules.get_unchecked(0);
        change(&mut rule);
        rules.set(0, rule);
        rules
    };
    let cap = |limit, period| StoredCap {
        limit,
        period,
        amount_arg: 2,
    };
    for rules in [
        with(&|r| r.cap = Vec::from_array(e, [cap(0, 10)])),
        with(&|r| r.cap = Vec::from_array(e, [cap(10, 0)])),
        with(&|r| r.cap = Vec::from_array(e, [cap(10, 10), cap(10, 10)])),
        {
            let mut two = one.clone();
            let mut later = one.get_unchecked(0);
            later.generation = Some(1);
            two.push_back(later);
            two
        },
    ] {
        assert_eq!(issue(&rules), refused(GrantError::InvalidRules));
    }
    assert_eq!(f.client().grant(&0), None);

    let root = f.issue(&a, &[f.contract_in(&[&f.w.target])], 0);
    for step in [
        Step::DropRule(1),
        Step::RaiseThreshold(0, 0),
        Step::LowerCapLimit(0, 5),
        Step::AddCap(0, cap(-1, 10)),
    ] {
        assert_eq!(
            f.delegate_steps(root, &a, root, &b, &Vec::from_array(e, [step]), 0),
            Err(refused(GrantError::InvalidStep))
        );
    }
    assert_eq!(f.client().grant(&(root + 1)), None);
}

// ---------------------------------------------------------------------------
// One reading at both boundaries
// ---------------------------------------------------------------------------

/// Whether the relay's and the grant signer's readings of a value agree.
fn same_reading(relay: &rule_eval::Val, signer: &rule_eval::Val) -> bool {
    rule_eval::val_eq(relay, signer)
}

/// The relay reads a call's XDR as `rule_eval` contexts; the grant signer
/// reads the host's contexts through soroban-facade. Over every argument
/// type the two readings are the same value; a rule whose condition holds
/// the relay's reading of one value allows, in the grant signer, a context
/// carrying exactly that value and no other; and a rule on the contract and
/// function the relay reads a call as allows that call. So the two
/// boundaries read a grant the same way. A muxed address has no stored
/// form, so no stored condition names one.
#[test]
fn the_account_and_the_relay_read_contexts_alike() {
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
    let relay = |v: &Val| {
        grant_relay::actions::val(&ScVal::try_from_val(e, v).unwrap()).expect("a value it reads")
    };
    for v in &values {
        let context = f.context(&f.w.target, "f", Vec::from_array(e, [*v]));
        let calls = perch_rule_eval::convert::calls(e, &Vec::from_array(e, [context]))
            .expect("a call the grant signer reads");
        let rule_eval::Context::Call { args, .. } = &calls[0] else {
            panic!("a call")
        };
        assert!(same_reading(&relay(v), &args[0]), "{v:?}");
    }
    let mut stored = 0;
    for (i, v) in values.iter().enumerate() {
        let Some(value) = StoredVal::from_val(e, &relay(v)) else {
            assert_eq!(i, 11, "only the muxed address has no stored form");
            continue;
        };
        stored += 1;
        let mut rules = f.root_rules(&[f.contract_in(&[&f.w.target])]);
        let mut rule = rules.get_unchecked(0);
        rule.conds = Vec::from_array(e, [nido_grant_signer::StoredCond::ArgEq(0, value)]);
        rules.set(0, rule);
        let g = f.issue_rules(&a, &rules, 0);
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
                "condition {i}, argument {j}"
            );
        }
    }
    assert_eq!(stored, values.len() - 1);

    // Contract and function names.
    let call = SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
        contract_address: f.w.target.clone().into(),
        function_name: StringM::try_from("protected").unwrap().into(),
        args: VecM::default(),
    });
    let Some(rule_eval::Context::Call {
        contract, function, ..
    }) = grant_relay::actions::authorized_function(&call)
    else {
        panic!("a contract call");
    };
    let mut rules = f.root_rules(&[f.contract_in(&[&f.w.target])]);
    let mut rule = rules.get_unchecked(0);
    rule.contract = perch_rule_eval::convert::host_address(e, &contract).unwrap();
    rule.functions = StoredFunctions::Only(Vec::from_array(
        e,
        [perch_rule_eval::convert::host_symbol(e, &function).unwrap()],
    ));
    rules.set(0, rule);
    let g = f.issue_rules(&a, &rules, 0);
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
