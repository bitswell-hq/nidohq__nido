//! One Nido account with agents: the account minted by Nido's factory, the
//! grant signer from its wasm as the account's delegated signer, two Stellar
//! Asset Contracts (the budget asset and another token) and instances of the
//! evaluation's dApp wasm.
//!
//! The same fixture runs on two backends ([`Backend`]): the Soroban host
//! under enforcing authorization, on the world of `crates/integration-tests`
//! (every Perch contract from its deployed wasm); and a local Stellar network
//! (`crate::network`), where the owner's setup goes straight to the chain and
//! every agent call goes through the relay. The attack suite and the
//! workloads are written once against this fixture.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use ed25519_dalek::{Signer as _, SigningKey};
use nido_grant_signer::{Grant, GrantError, GrantSignature, GrantSignerClient, Step, StoredRule};
use nido_integration_tests::grants::{self, Arg, Caveat};
use nido_integration_tests::world::{strkey, world, Account, Passkey, World, NETWORK};
use nido_integration_tests::{account_auth_digest, build_contract_assertion, GRANT_SIGNER_WASM};
use perch_smart_account::AccountConfiguration;
use serde::Serialize;
use soroban_sdk::auth::Context;
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::xdr::{
    HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, InvokeContractArgs, Limits, ScVal,
    SorobanAddressCredentials, SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials,
    SorobanDelegateSignature, StringM, ToXdr as _, VecM, WriteXdr,
};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, IntoVal, InvokeError, Map, Symbol, TryFromVal, Val, Vec,
};
use stellar_accounts::smart_account::{AuthPayload, Signer};
use stellar_accounts::verifiers::webauthn::WebAuthnSigData;

use crate::network::relay::{self, AgentSpec, Reply};
use crate::network::{Mode, Net};
use crate::outcome::{classify, Outcome};

/// The account's starting balance in each asset.
pub const BALANCE: i128 = 1_000_000;

/// An agent's ed25519 holder key.
#[must_use]
pub fn agent(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn pubkey(env: &Env, key: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &key.verifying_key().to_bytes())
}

/// A document rule for agents that no correct document has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Misrule {
    /// `a-self`, scoped to the account itself.
    SelfAdmin,
    /// `a-signer`, scoped to the grant signer.
    Signer,
}

/// Where the fixture's contracts run.
pub enum Backend {
    /// The Soroban host, every authorization installed with `set_auths`.
    Sim(Box<World>),
    /// A local Stellar network: the owner's setup sent from the network's
    /// operator account, agent calls sent through the relay.
    Net(Arc<Net>),
}

pub struct Fixture {
    backend: Backend,
    /// The simulation's host; on the network, a host that only builds
    /// values, on the network's id.
    env: Env,
    verifier: Address,
    /// The network passphrase documents name.
    network: &'static str,
    pub account: Account,
    pub signer: Address,
    /// The budget asset.
    pub asset: Address,
    /// A second Stellar Asset Contract the account holds, not metered.
    pub other: Address,
    pub dapps: std::vec::Vec<Address>,
    pub bob: Address,
    pub carol: Address,
    /// An address the attacking agent controls.
    pub mallory: Address,
    /// Contract to document rule name, for the account's rule selection.
    rules: BTreeMap<String, String>,
    nonce: Cell<i64>,
    /// On the network: the budget asset (code and issuer).
    budget: Option<soroban_sdk::xdr::AlphaNum4>,
    /// On the network: the relay agents for the current grants, `None` when
    /// a setup step may have changed them.
    agents: RefCell<Option<std::vec::Vec<AgentSpec>>>,
    /// On the network: the relay's reply to the latest agent call.
    last_reply: RefCell<Option<Reply>>,
    /// Each grant's caveats as the evaluation wrote them, by id: its root's
    /// ([`Self::named`]), then each delegation's. The grant signer holds
    /// the rule set they lower to; the relay mirrors them.
    issued: RefCell<BTreeMap<u32, std::vec::Vec<Caveat>>>,
}

impl Fixture {
    /// An account whose document gives agents one rule per asset and dApp
    /// instance, plus `extra`, with `dapps` instances of `dapp_wasm`, in the
    /// Soroban host.
    #[must_use]
    pub fn new(label: &str, dapp_wasm: &[u8], dapps: usize, extra: Option<Misrule>) -> Self {
        let w = world();
        let account = w.mint(
            &format!("eval/{label}"),
            Passkey::labelled(&format!("eval/{label}/owner")),
            std::vec![],
        );
        let env = w.env.clone();
        let signer = env.register(GRANT_SIGNER_WASM, (account.address.clone(),));
        let asset = env
            .register_stellar_asset_contract_v2(Address::generate(&env))
            .address();
        let other = env
            .register_stellar_asset_contract_v2(Address::generate(&env))
            .address();
        let dapps: std::vec::Vec<Address> =
            (0..dapps).map(|_| env.register(dapp_wasm, ())).collect();
        env.mock_all_auths();
        StellarAssetClient::new(&env, &asset).mint(&account.address, &BALANCE);
        StellarAssetClient::new(&env, &other).mint(&account.address, &BALANCE);
        env.set_auths(&[]);
        let parties = [
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ];
        let verifier = w.verifier.clone();
        let target = w.target.clone();
        Self::finish(
            Backend::Sim(Box::new(w)),
            env,
            verifier,
            NETWORK,
            account,
            signer,
            [asset, other],
            dapps,
            parties,
            &target,
            extra,
        )
    }

    /// The same account on the local network: minted by the network's
    /// factory, its grant signer, two credit assets' contracts and `dapps`
    /// dApp instances deployed there, and its document applied by the owner.
    ///
    /// # Panics
    ///
    /// If a setup step fails.
    #[must_use]
    pub fn on_network(net: &Arc<Net>, label: &str, dapps: usize, extra: Option<Misrule>) -> Self {
        let env = Env::new_with_config(soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        });
        env.cost_estimate().budget().reset_unlimited();
        env.ledger()
            .with_mut(|l| l.network_id = grant_relay::local::network_id());
        let at = |s: &str| Address::from_str(&env, s);
        let owner = Passkey::labelled(&format!("eval/{label}/owner"));
        let account = mint(net, &env, &format!("eval/{label}"), owner);
        let signer = at(&net
            .deploy(
                "grant-signer",
                net.grant_signer_hash,
                std::vec![sc(&env, account.address.clone())],
            )
            .expect("the grant signer deploys"));
        let holder = std::vec![strkey(&account.address)];
        let (asset, budget) = net
            .asset("BUDG", &holder, BALANCE)
            .expect("the budget asset");
        let asset = at(&asset);
        let other = at(&net
            .asset("OTHR", &holder, BALANCE)
            .expect("the other token")
            .0);
        let dapps = (0..dapps)
            .map(|i| {
                at(&net
                    .deploy(&format!("dapp-{i}"), net.dapp_hash, std::vec![])
                    .expect("a dApp instance deploys"))
            })
            .collect();
        // Parties that only receive the asset: contract addresses, which hold
        // a Stellar asset without a trustline, as in the simulation.
        let party = |name: &str| at(&stellar_strkey::Contract(net.salt(name)).to_string());
        let parties = [party("bob"), party("carol"), party("mallory")];
        let target = party("target");
        let verifier = at(&net.verifier);
        let mut f = Self::finish(
            Backend::Net(Arc::clone(net)),
            env,
            verifier,
            grant_relay::local::PASSPHRASE,
            account,
            signer,
            [asset, other],
            dapps,
            parties,
            &target,
            extra,
        );
        f.budget = Some(budget);
        f
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        backend: Backend,
        env: Env,
        verifier: Address,
        network: &'static str,
        account: Account,
        signer: Address,
        [asset, other]: [Address; 2],
        dapps: std::vec::Vec<Address>,
        [bob, carol, mallory]: [Address; 3],
        target: &Address,
        extra: Option<Misrule>,
    ) -> Self {
        let mut rules = BTreeMap::new();
        rules.insert(strkey(&asset), "a-asset".to_owned());
        rules.insert(strkey(&other), "a-other".to_owned());
        rules.insert(strkey(target), "a-target".to_owned());
        for (i, d) in dapps.iter().enumerate() {
            rules.insert(strkey(d), format!("a-dapp-{i}"));
        }
        match extra {
            None => {}
            Some(Misrule::SelfAdmin) => {
                rules.insert(strkey(&account.address), "a-self".to_owned());
            }
            Some(Misrule::Signer) => {
                rules.insert(strkey(&signer), "a-signer".to_owned());
            }
        }
        let f = Self {
            backend,
            env,
            verifier,
            network,
            bob,
            carol,
            mallory,
            account,
            signer,
            asset,
            other,
            dapps,
            rules,
            nonce: Cell::new(1 << 40),
            budget: None,
            agents: RefCell::new(None),
            last_reply: RefCell::new(None),
            issued: RefCell::new(BTreeMap::new()),
        };
        let doc = f.doc(None);
        match &f.backend {
            Backend::Sim(w) => {
                w.apply_bytes_as(&f.account, "owner", &doc, 0)
                    .expect("the agents' document applies");
            }
            Backend::Net(_) => {
                let e = f.env();
                let args = Vec::from_array(
                    e,
                    [
                        doc.into_val(e),
                        0u32.into_val(e),
                        Option::<u64>::None.into_val(e),
                    ],
                );
                assert_eq!(
                    f.owner_call(&f.account.address, "apply_doc", &args),
                    Outcome::Allowed,
                    "the agents' document applies"
                );
            }
        }
        f
    }

    #[must_use]
    pub fn env(&self) -> &Env {
        &self.env
    }

    /// The enforcement point agent calls go through.
    #[must_use]
    pub fn boundary(&self) -> &'static str {
        match &self.backend {
            Backend::Sim(_) => "soroban-simulation",
            Backend::Net(_) => "local-network",
        }
    }

    /// CPU instructions and memory bytes of the latest invocation, where the
    /// backend meters them (the simulation).
    #[must_use]
    pub fn resources(&self) -> Option<(i64, i64)> {
        match &self.backend {
            Backend::Sim(_) => {
                let r = self.env.cost_estimate().resources();
                Some((r.instructions, r.mem_bytes))
            }
            Backend::Net(_) => None,
        }
    }

    /// The relay's reply to the latest agent call, on the network.
    #[must_use]
    pub fn take_reply(&self) -> Option<Reply> {
        self.last_reply.borrow_mut().take()
    }

    #[must_use]
    pub fn client(&self) -> GrantSignerClient<'_> {
        GrantSignerClient::new(self.env(), &self.signer)
    }

    /// `v` as an XDR value.
    #[must_use]
    pub fn sc<T: IntoVal<Env, Val>>(&self, v: T) -> ScVal {
        sc(&self.env, v)
    }

    /// The latest ledger.
    ///
    /// # Panics
    ///
    /// If the network does not answer.
    #[must_use]
    pub fn ledger(&self) -> u32 {
        match &self.backend {
            Backend::Sim(w) => w.ledger(),
            Backend::Net(n) => n.ledger().expect("the latest ledger"),
        }
    }

    /// The account's document: the owner passkey on the admin rule, the grant
    /// signer as delegated signer `grants`, and one agent rule per entry of
    /// `self.rules` (or `rules`), each signed by `grants`.
    #[must_use]
    pub fn doc(&self, rules: Option<&[(String, String)]>) -> Bytes {
        let owner = hex::encode(self.account.key("owner").pubkey());
        let mut all = std::vec![String::from(
            r#"{"name":"admin","scope":{"type":"self-admin"},"principals":{"type":"all","signers":["owner"]}}"#
        )];
        let scoped: std::vec::Vec<(String, String)> = match rules {
            Some(r) => r.to_vec(),
            None => self
                .rules
                .iter()
                .map(|(contract, name)| {
                    let scope = if *contract == strkey(&self.account.address) {
                        String::from(r#"{"type":"self-admin"}"#)
                    } else {
                        format!(r#"{{"type":"contract","address":"{contract}"}}"#)
                    };
                    (name.clone(), scope)
                })
                .collect(),
        };
        for (name, scope) in scoped {
            all.push(format!(
                r#"{{"name":"{name}","scope":{scope},"principals":{{"type":"all","signers":["grants"]}}}}"#
            ));
        }
        let json = format!(
            r#"{{"version":1,"network":"{}","signers":[{{"id":"owner","verifier":"{}","key":"{owner}"}},{{"id":"grants","address":"{}"}}],"rules":[{}]}}"#,
            self.network,
            strkey(&self.verifier),
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

    // --- caveats -------------------------------------------------------------

    #[must_use]
    pub fn id(&self, a: &Address) -> Bytes {
        Bytes::from_slice(self.env(), strkey(a).as_bytes())
    }

    #[must_use]
    pub fn contract_in(&self, list: &[&Address]) -> Caveat {
        Caveat::ContractIn(Vec::from_iter(self.env(), list.iter().map(|a| self.id(a))))
    }

    #[must_use]
    pub fn function_in(&self, list: &[&str]) -> Caveat {
        Caveat::FunctionIn(Vec::from_iter(
            self.env(),
            list.iter()
                .map(|f| Bytes::from_slice(self.env(), f.as_bytes())),
        ))
    }

    #[must_use]
    pub fn arg_address(&self, index: u32, a: &Address) -> Caveat {
        Caveat::ArgEq(index, Arg::Address(self.id(a)))
    }

    // --- running calls -------------------------------------------------------

    /// Run `call` with exactly `entries` authorized, and classify a failure
    /// by the host's event log.
    fn run(&self, entries: &[SorobanAuthorizationEntry], call: impl FnOnce()) -> Outcome {
        self.env().set_auths(entries);
        let result = catch_unwind(AssertUnwindSafe(call));
        self.env().set_auths(&[]);
        match result {
            Ok(()) => Outcome::Allowed,
            Err(panic) => {
                let message = panic
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| panic.downcast_ref::<&str>().map(|s| String::from(*s)))
                    .unwrap_or_default();
                classify(
                    &message,
                    &strkey(&self.signer),
                    &strkey(&self.account.address),
                )
            }
        }
    }

    /// `contract.f(args)` signed by the owner passkey through the admin rule,
    /// sent from the network's operator account.
    fn owner_call(&self, contract: &Address, f: &str, args: &Vec<Val>) -> Outcome {
        let Backend::Net(net) = &self.backend else {
            unreachable!("the simulation's owner signs through its world")
        };
        let root = self.node(contract, f, args, std::vec![]);
        let entry = self.owner_entry(net, root);
        *self.agents.borrow_mut() = None;
        match net.setup(&host_function(&root_call(&entry)), Some(std::vec![entry])) {
            Ok(()) => Outcome::Allowed,
            Err(e) => classify(&e, &strkey(&self.signer), &strkey(&self.account.address)),
        }
    }

    /// The owner passkey's authorization of `root` through the admin rule,
    /// as a browser assertion signs it.
    fn owner_entry(
        &self,
        net: &Net,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let e = self.env();
        let nonce = self.next_nonce();
        let expiration = net.ledger().expect("the latest ledger") + 1_000;
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: soroban_sdk::xdr::Hash(e.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger: expiration,
            invocation: root.clone(),
        });
        let payload = e.crypto().sha256(&Bytes::from_slice(
            e,
            &preimage.to_xdr(Limits::none()).unwrap(),
        ));
        let rule_ids = soroban_sdk::vec![e, self.rule_id("admin")];
        let digest = account_auth_digest(e, &self.account.address, &payload, &rule_ids);
        let owner = self.account.key("owner");
        let a = build_contract_assertion(&owner.key, e, &digest);
        let sig = WebAuthnSigData {
            signature: a.signature,
            authenticator_data: a.authenticator_data,
            client_data: a.client_data,
        };
        let mut signers: Map<Signer, Bytes> = Map::new(e);
        signers.set(owner.signer(e, &self.verifier), sig.to_xdr(e));
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: self.account.address.clone().into(),
                nonce,
                signature_expiration_ledger: expiration,
                signature: self.sc(AuthPayload {
                    signers,
                    context_rule_ids: rule_ids,
                }),
            }),
            root_invocation: root,
        }
    }

    /// Call `f(args)` on the grant signer as the account, authorized by the
    /// owner passkey through the admin rule.
    pub fn admin(&self, f: &str, args: &Vec<Val>) -> Outcome {
        let name = Symbol::new(self.env(), f);
        match &self.backend {
            Backend::Sim(w) => {
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
            Backend::Net(_) => {
                let e = self.env();
                let exec = Vec::from_array(
                    e,
                    [self.signer.into_val(e), name.into_val(e), args.into_val(e)],
                );
                self.owner_call(&self.account.address, "execute", &exec)
            }
        }
    }

    /// `caveats`, naming every contract the fixture deploys when no caveat
    /// names contracts: a rule set names the contracts it allows, so the
    /// evaluation's open grant is one over all of them, which leaves the
    /// grant signer's guards as the only check on the account, the grant
    /// signer and the budget asset.
    #[must_use]
    pub fn named(&self, caveats: &[Caveat]) -> std::vec::Vec<Caveat> {
        if caveats.iter().any(|c| matches!(c, Caveat::ContractIn(_))) {
            return caveats.to_vec();
        }
        let mut all = std::vec![
            &self.account.address,
            &self.signer,
            &self.asset,
            &self.other
        ];
        all.extend(&self.dapps);
        let mut out = std::vec![self.contract_in(&all)];
        out.extend_from_slice(caveats);
        out
    }

    /// The rule set grant `id` holds, lowered from its recorded caveats;
    /// empty for an id the evaluation issued no grant at.
    #[must_use]
    pub fn rules_of(&self, id: u32) -> Vec<StoredRule> {
        match self.issued.borrow().get(&id) {
            Some(caveats) => grants::root(self.env(), &self.signer, caveats),
            None => Vec::new(self.env()),
        }
    }

    /// The attenuation steps that add `caveats` to grant `parent`.
    #[must_use]
    pub fn delegation_steps(&self, parent: u32, caveats: &[Caveat]) -> Vec<Step> {
        grants::steps(self.env(), &self.rules_of(parent), caveats)
    }

    /// Record that grant `id` was delegated from `parent`, adding `caveats`.
    pub fn delegated(&self, id: u32, parent: u32, caveats: &[Caveat]) {
        let mut issued = self.issued.borrow_mut();
        let mut all = issued.get(&parent).cloned().unwrap_or_default();
        all.extend_from_slice(caveats);
        issued.insert(id, all);
    }

    /// The owner issues a root grant over the budget asset, with the rule set
    /// `caveats` lower to ([`Self::named`]); returns its id.
    ///
    /// # Panics
    /// If the owner's `issue` fails.
    pub fn issue(&self, key: &SigningKey, caveats: &[Caveat], allowance: u128) -> u32 {
        let e = self.env();
        let next = self.next_id();
        let named = self.named(caveats);
        let args = Vec::from_array(
            e,
            [
                pubkey(e, key).into_val(e),
                grants::root(e, &self.signer, &named).into_val(e),
                self.asset.into_val(e),
                allowance.into_val(e),
            ],
        );
        assert_eq!(self.admin("issue", &args), Outcome::Allowed, "issue");
        self.issued.borrow_mut().insert(next, named);
        next
    }

    pub fn admin_grant_op(&self, f: &str, grant: u32, extra: Option<Val>) -> Outcome {
        let e = self.env();
        let mut args = Vec::from_array(e, [grant.into_val(e)]);
        if let Some(v) = extra {
            args.push_back(v);
        }
        self.admin(f, &args)
    }

    /// The id the next grant gets.
    ///
    /// # Panics
    /// If there are `u32::MAX` grants.
    #[must_use]
    pub fn next_id(&self) -> u32 {
        u32::try_from(self.grants().len()).expect("fewer than u32::MAX grants")
    }

    /// Every grant, by id.
    #[must_use]
    pub fn grants(&self) -> std::vec::Vec<Grant> {
        (0u32..)
            .map_while(|id| match &self.backend {
                Backend::Sim(_) => self.client().grant(&id),
                Backend::Net(_) => self.view::<Option<Grant>>(
                    &self.signer,
                    "grant",
                    &Vec::from_array(self.env(), [id.into_val(self.env())]),
                ),
            })
            .collect()
    }

    #[must_use]
    pub fn balance(&self, token: &Address, a: &Address) -> i128 {
        match &self.backend {
            Backend::Sim(_) => TokenClient::new(self.env(), token).balance(a),
            Backend::Net(_) => self.view(
                token,
                "balance",
                &Vec::from_array(self.env(), [a.into_val(self.env())]),
            ),
        }
    }

    /// `contract.f(args)` evaluated against the network's current state.
    fn view<T: TryFromVal<Env, Val>>(&self, contract: &Address, f: &str, args: &Vec<Val>) -> T {
        let Backend::Net(net) = &self.backend else {
            unreachable!("the simulation reads through its clients")
        };
        let result = net
            .read(&crate::network::invoke(
                &strkey(contract),
                f,
                args.iter().map(|v| self.sc(v)).collect(),
            ))
            .unwrap_or_else(|e| panic!("reading {f}: {e}"));
        let val = Val::try_from_val(self.env(), &result).expect("a host value");
        T::try_from_val(self.env(), &val)
            .unwrap_or_else(|_| panic!("reading {f}: unexpected value {result:?}"))
    }

    /// The id of the account's live rule named `name` (`u32::MAX` when there
    /// is none), as its `configuration()` view reports it.
    fn rule_id(&self, name: &str) -> u32 {
        match &self.backend {
            Backend::Sim(w) => w.rule_id(&self.account.address, name),
            Backend::Net(_) => {
                let config: AccountConfiguration = self.view(
                    &self.account.address,
                    "configuration",
                    &Vec::new(self.env()),
                );
                let wanted = soroban_sdk::String::from_str(self.env(), name);
                config
                    .rules
                    .iter()
                    .find(|r| !r.recovery && r.name == wanted)
                    .map_or(u32::MAX, |r| r.id)
            }
        }
    }

    // --- agent authorizations ------------------------------------------------

    /// The host's signature payload. With `address` (delegated credentials)
    /// the preimage names the authorizing address.
    #[must_use]
    pub fn payload(
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
        self.sc(GrantSignature {
            grant,
            signature: BytesN::from_array(self.env(), &key.sign(payload).to_bytes()),
        })
    }

    /// The account's rule selection for `root`'s tree: one rule per context,
    /// depth first, named by the contract it calls (`a-…`), unless `rules`
    /// overrides it.
    fn rule_ids(&self, root: &SorobanAuthorizedInvocation, rules: Option<&[&str]>) -> Vec<u32> {
        let names: std::vec::Vec<String> = rules.map_or_else(
            || {
                let mut out = std::vec::Vec::new();
                self.tree_rules(root, &mut out);
                out
            },
            |r| r.iter().map(|s| (*s).to_owned()).collect(),
        );
        Vec::from_iter(self.env(), names.iter().map(|r| self.rule_id(r)))
    }

    fn tree_rules(&self, node: &SorobanAuthorizedInvocation, out: &mut std::vec::Vec<String>) {
        let contract = match &node.function {
            SorobanAuthorizedFunction::ContractFn(args) => args.contract_address.to_string(),
            _ => strkey(&self.account.address),
        };
        out.push(
            self.rules
                .get(&contract)
                .cloned()
                .unwrap_or_else(|| "a-target".to_owned()),
        );
        for sub in node.sub_invocations.as_slice() {
            self.tree_rules(sub, out);
        }
    }

    /// The account's authorization of `root`, given by grant `grant`'s holder
    /// `key` through the grant signer.
    #[must_use]
    pub fn agent_entry(
        &self,
        grant: u32,
        key: &SigningKey,
        rules: Option<&[&str]>,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.next_nonce();
        let expiration = self.ledger() + 1_000;
        let payload = self.payload(Some(&self.account.address), nonce, expiration, &root);
        let mut signers: Map<Signer, Bytes> = Map::new(self.env());
        signers.set(
            Signer::Delegated(self.signer.clone()),
            Bytes::new(self.env()),
        );
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::AddressWithDelegates(
                SorobanAddressCredentialsWithDelegates {
                    address_credentials: SorobanAddressCredentials {
                        address: self.account.address.clone().into(),
                        nonce,
                        signature_expiration_ledger: expiration,
                        signature: self.sc(AuthPayload {
                            signers,
                            context_rule_ids: self.rule_ids(&root, rules),
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

    /// The grant signer's own authorization of `root`, given by `grant`'s
    /// holder `key`.
    #[must_use]
    pub fn signer_entry(
        &self,
        grant: u32,
        key: &SigningKey,
        root: SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.next_nonce();
        let expiration = self.ledger() + 1_000;
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

    /// An invocation node of `contract.f(args)` with `subs` nested in it.
    #[must_use]
    pub fn node(
        &self,
        contract: &Address,
        f: &str,
        args: &Vec<Val>,
        subs: std::vec::Vec<SorobanAuthorizedInvocation>,
    ) -> SorobanAuthorizedInvocation {
        let mut n = invocation(contract, f, args.iter().map(|v| self.sc(v)).collect());
        n.sub_invocations = subs.try_into().unwrap();
        n
    }

    /// Invoke `contract.f(args)` with `entries` as the only authorization:
    /// an agent's call. On the network it goes through the relay, as the
    /// holder of the grant whose signature the entries carry.
    pub fn call(
        &self,
        entries: &[SorobanAuthorizationEntry],
        contract: &Address,
        f: &str,
        args: &Vec<Val>,
    ) -> Outcome {
        match &self.backend {
            Backend::Sim(_) => self.run(entries, || {
                self.env().invoke_contract::<Val>(
                    contract,
                    &Symbol::new(self.env(), f),
                    args.clone(),
                );
            }),
            Backend::Net(net) => {
                let func = crate::network::invoke(
                    &strkey(contract),
                    f,
                    args.iter().map(|v| self.sc(v)).collect(),
                );
                let agents = self.relay_agents(net);
                let handle = net.relay_for(&agents).expect("the relay starts");
                let key = entries
                    .iter()
                    .find_map(|e| self.grant_of(e))
                    .map_or_else(|| "no-grant".to_owned(), |g| self.api_key(g));
                let mut reply = handle
                    .call(&key, &func, entries)
                    .unwrap_or_else(|e| panic!("relaying {f}: {e}"));
                relay::settle(&net.rpc, &mut reply, &strkey(&self.signer));
                let outcome = relay::outcome(
                    &reply,
                    &strkey(&self.signer),
                    &strkey(&self.account.address),
                );
                *self.last_reply.borrow_mut() = Some(reply);
                outcome
            }
        }
    }

    /// A setup step's call made by an agent (a holder delegating a
    /// sub-grant): in the simulation as [`Self::call`]; on the network sent
    /// straight to the chain, since the step sets up the scenario and is not
    /// one of its attempts.
    pub fn setup_call(
        &self,
        entries: &[SorobanAuthorizationEntry],
        contract: &Address,
        f: &str,
        args: &Vec<Val>,
    ) -> Outcome {
        match &self.backend {
            Backend::Sim(_) => self.call(entries, contract, f, args),
            Backend::Net(net) => {
                *self.agents.borrow_mut() = None;
                let func = crate::network::invoke(
                    &strkey(contract),
                    f,
                    args.iter().map(|v| self.sc(v)).collect(),
                );
                match net.setup(&func, Some(entries.to_vec())) {
                    Ok(()) => Outcome::Allowed,
                    Err(e) => classify(&e, &strkey(&self.signer), &strkey(&self.account.address)),
                }
            }
        }
    }

    /// The grant whose holder signed `entry`.
    fn grant_of(&self, entry: &SorobanAuthorizationEntry) -> Option<u32> {
        let signature = match &entry.credentials {
            SorobanCredentials::AddressWithDelegates(c) => &c.delegates.first()?.signature,
            SorobanCredentials::Address(c) => &c.signature,
            _ => return None,
        };
        let val = Val::try_from_val(self.env(), signature).ok()?;
        GrantSignature::try_from_val(self.env(), &val)
            .ok()
            .map(|s| s.grant)
    }

    /// The relay API key of grant `grant`'s holder.
    #[must_use]
    pub fn api_key(&self, grant: u32) -> String {
        format!("{}-grant-{grant}", strkey(&self.signer))
    }

    /// The relay's agents: one per grant, with the grant's caveats as its
    /// chain grant ([`Mode::Mirrored`], leaving out revoked grants and grants
    /// under a revoked ancestor), or with one naming every contract the
    /// fixture deploys ([`Mode::PassThrough`]).
    pub fn relay_agents(&self, net: &Net) -> std::vec::Vec<AgentSpec> {
        if let Some(a) = self.agents.borrow().as_ref() {
            return a.clone();
        }
        let grants = self.grants();
        let revoked = |mut id: u32| loop {
            let g = &grants[id as usize];
            if g.revoked {
                return true;
            }
            match g.parent {
                Some(p) => id = p,
                None => return false,
            }
        };
        let issued = self.issued.borrow();
        let agents: std::vec::Vec<AgentSpec> = (0u32..)
            .zip(&grants)
            .filter(|(id, _)| net.mode() == Mode::PassThrough || !revoked(*id))
            .map(|(id, _)| AgentSpec {
                api_key: self.api_key(id),
                chain: match net.mode() {
                    Mode::Mirrored => issued[&id].iter().map(relay_caveat).collect(),
                    Mode::PassThrough => self.named(&[]).iter().map(relay_caveat).collect(),
                },
            })
            .collect();
        *self.agents.borrow_mut() = Some(agents.clone());
        agents
    }

    /// A Nido account the factory mints, with `owner` as its admin passkey.
    #[must_use]
    pub fn mint(&self, label: &str, owner: Passkey) -> Account {
        match &self.backend {
            Backend::Sim(w) => w.mint(label, owner, std::vec![]),
            Backend::Net(net) => mint(net, self.env(), label, owner),
        }
    }

    /// Give `key`'s account a trustline for the budget asset, creating the
    /// account, on the network. The simulation needs none: its enforcing
    /// authorization refuses a refused transfer before the token looks for
    /// the recipient's trustline.
    ///
    /// # Panics
    ///
    /// If the network does not create it.
    pub fn trustline(&self, key: &SigningKey) {
        if let (Backend::Net(net), Some(budget)) = (&self.backend, &self.budget) {
            net.trustline(key, budget).expect("the trustline");
        }
    }

    /// Install `wasm`; returns its hash.
    #[must_use]
    pub fn upload(&self, wasm: &[u8]) -> BytesN<32> {
        match &self.backend {
            Backend::Sim(w) => w.env.deployer().upload_contract_wasm(wasm),
            Backend::Net(_) => BytesN::from_array(self.env(), &crate::network::hash(wasm)),
        }
    }

    /// The attack suite's deployer (`attacks::Deployer`): registered in the
    /// simulation, deployed from its wasm (`fixtures/deployer`) on the
    /// network.
    #[must_use]
    pub fn deployer(&self) -> Address {
        match &self.backend {
            Backend::Sim(w) => w.env.register(super::attacks::Deployer, ()),
            Backend::Net(net) => Address::from_str(
                self.env(),
                &net.deploy("deployer", net.deployer_hash, std::vec![])
                    .expect("the deployer deploys"),
            ),
        }
    }

    // --- argument lists and trees of the calls agents make ------------------

    #[must_use]
    pub fn transfer_args(&self, to: &Address, amount: i128) -> Vec<Val> {
        let e = self.env();
        Vec::from_array(
            e,
            [
                self.account.address.into_val(e),
                to.into_val(e),
                amount.into_val(e),
            ],
        )
    }

    /// `token.transfer(account, to, amount)` as a tree.
    #[must_use]
    pub fn transfer_node(
        &self,
        token: &Address,
        to: &Address,
        amount: i128,
    ) -> SorobanAuthorizedInvocation {
        self.node(
            token,
            "transfer",
            &self.transfer_args(to, amount),
            std::vec![],
        )
    }

    #[must_use]
    pub fn forward_args(
        &self,
        dapp: usize,
        token: &Address,
        to: &Address,
        amount: i128,
    ) -> (Address, Vec<Val>) {
        let e = self.env();
        (
            self.dapps[dapp].clone(),
            Vec::from_array(
                e,
                [
                    self.account.address.into_val(e),
                    token.into_val(e),
                    to.into_val(e),
                    amount.into_val(e),
                ],
            ),
        )
    }

    /// `dapps[path[0]].hop(account, [dapps[path[1..]]], token, to, amount)`:
    /// the call, its arguments and its whole tree (each hop one level
    /// deeper, the transfer at the bottom).
    #[must_use]
    pub fn hop(
        &self,
        path: &[usize],
        token: &Address,
        to: &Address,
        amount: i128,
    ) -> (Address, Vec<Val>, SorobanAuthorizedInvocation) {
        let e = self.env();
        let args_at = |i: usize| {
            let rest: Vec<Address> =
                Vec::from_iter(e, path[i + 1..].iter().map(|d| self.dapps[*d].clone()));
            Vec::from_array(
                e,
                [
                    self.account.address.into_val(e),
                    rest.into_val(e),
                    token.into_val(e),
                    to.into_val(e),
                    amount.into_val(e),
                ],
            )
        };
        let mut tree = self.transfer_node(token, to, amount);
        for i in (0..path.len()).rev() {
            tree = self.node(&self.dapps[path[i]], "hop", &args_at(i), std::vec![tree]);
        }
        (self.dapps[path[0]].clone(), args_at(0), tree)
    }

    /// `__check_auth` of the grant signer called directly on `contexts`, for
    /// `grant`'s holder `key`. Only the simulation can call it directly; the
    /// network's host refuses a direct call of `__check_auth`, so there it is
    /// `None`.
    pub fn verdict(
        &self,
        grant: u32,
        key: &SigningKey,
        contexts: &[Context],
    ) -> Option<Result<(), Result<GrantError, InvokeError>>> {
        if let Backend::Net(_) = &self.backend {
            return None;
        }
        let payload = [0x5a; 32];
        let signature = GrantSignature {
            grant,
            signature: BytesN::from_array(self.env(), &key.sign(&payload).to_bytes()),
        };
        Some(self.env().try_invoke_contract_check_auth::<GrantError>(
            &self.signer,
            &BytesN::from_array(self.env(), &payload),
            signature.into_val(self.env()),
            &Vec::from_slice(self.env(), contexts),
        ))
    }

    // --- state ---------------------------------------------------------------

    /// Everything a refused attack must leave unchanged.
    ///
    /// # Panics
    ///
    /// If the network does not answer.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let mut balances = BTreeMap::new();
        let mut holders = std::vec![
            ("account", self.account.address.clone()),
            ("bob", self.bob.clone()),
            ("carol", self.carol.clone()),
            ("mallory", self.mallory.clone()),
        ];
        for (i, d) in self.dapps.iter().enumerate() {
            holders.push((
                ["dapp-0", "dapp-1", "dapp-2", "dapp-3", "dapp-4"][i.min(4)],
                d.clone(),
            ));
        }
        for (token_name, token) in [("asset", &self.asset), ("other", &self.other)] {
            for (name, a) in &holders {
                balances.insert(format!("{token_name}:{name}"), self.balance(token, a));
            }
        }
        let grants = self.grants().iter().map(GrantView::from).collect();
        match &self.backend {
            Backend::Sim(w) => {
                let account = w.account(&self.account);
                Snapshot {
                    balances,
                    grants,
                    revision: account.revision(),
                    doc_hash: account
                        .applied_doc_hash()
                        .map(|h| hex::encode(h.to_array())),
                    pending_upgrade: account.pending_upgrade().is_some(),
                    channels: BTreeMap::new(),
                }
            }
            Backend::Net(net) => {
                let a = &self.account.address;
                let none = Vec::new(self.env());
                let doc_hash: Option<BytesN<32>> = self.view(a, "applied_doc_hash", &none);
                let pending: Val = self.view(a, "pending_upgrade", &none);
                Snapshot {
                    balances,
                    grants,
                    revision: self.view(a, "revision", &none),
                    doc_hash: doc_hash.map(|h| hex::encode(h.to_array())),
                    pending_upgrade: !pending.is_void(),
                    channels: net
                        .channel_sequences()
                        .expect("the channels' sequence numbers")
                        .into_iter()
                        .collect(),
                }
            }
        }
    }
}

/// A stored caveat as the relay's configuration file writes it. Contracts,
/// functions, symbols and addresses are stored as their text.
fn relay_caveat(c: &Caveat) -> serde_json::Value {
    use serde_json::json;
    let text = |b: &Bytes| String::from_utf8(b.to_alloc_vec()).expect("stored as text");
    let list = |l: &Vec<Bytes>| l.iter().map(|b| text(&b)).collect::<std::vec::Vec<_>>();
    match c {
        Caveat::ContractIn(l) => json!({ "contract_in": list(l) }),
        Caveat::FunctionIn(l) => json!({ "function_in": list(l) }),
        Caveat::ArgI128AtMost(i, n) => json!({ "arg_i128_at_most": [i, n.to_string()] }),
        Caveat::ArgEq(i, v) => {
            let v = match v {
                Arg::I128(n) => json!({ "i128": n.to_string() }),
                Arg::U64(n) => json!({ "u64": n }),
                Arg::Bool(b) => json!({ "bool": b }),
                Arg::Bytes(b) => json!({ "bytes": hex::encode(b.to_alloc_vec()) }),
                Arg::Address(b) => json!({ "address": text(b) }),
                Arg::Symbol(b) => json!({ "symbol": text(b) }),
                Arg::Other(b) => json!({ "other": hex::encode(b.to_alloc_vec()) }),
            };
            json!({ "arg_eq": [i, v] })
        }
    }
}

/// `v` as an XDR value in `env`.
///
/// # Panics
///
/// If `v` has no XDR form.
#[allow(clippy::needless_pass_by_value)]
pub fn sc<T: IntoVal<Env, Val>>(env: &Env, v: T) -> ScVal {
    let val: Val = v.into_val(env);
    ScVal::try_from_val(env, &val).unwrap()
}

/// An authorized invocation of `contract.f(args)`, with no sub-invocations.
fn invocation(
    contract: &Address,
    f: &str,
    args: std::vec::Vec<ScVal>,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: contract.clone().into(),
            function_name: StringM::try_from(f).unwrap().into(),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: VecM::default(),
    }
}

/// The call an entry's root invocation authorizes.
fn root_call(entry: &SorobanAuthorizationEntry) -> InvokeContractArgs {
    match &entry.root_invocation.function {
        SorobanAuthorizedFunction::ContractFn(args) => args.clone(),
        _ => panic!("the owner authorizes contract calls"),
    }
}

fn host_function(args: &InvokeContractArgs) -> soroban_sdk::xdr::HostFunction {
    soroban_sdk::xdr::HostFunction::InvokeContract(args.clone())
}

/// Mint an account on the network through its factory: a setup key seeded
/// from `sha256("nido-it/salt/<label>")` with this run's tag (its public key
/// fixes the address), admin passkey `owner`, bound to the factory by the
/// setup key's signature over `sha256("nido/bind/v1" || network_id ||
/// factory_id || key)`.
fn mint(net: &Net, env: &Env, label: &str, owner: Passkey) -> Account {
    use sha2::{Digest as _, Sha256};
    let setup = SigningKey::from_bytes(&net.salt(&format!("nido-it/salt/{label}")));
    let key = owner.pubkey();
    let factory_id = stellar_strkey::Contract::from_string(&net.factory)
        .expect("the factory is a contract strkey")
        .0;
    let mut binding = Sha256::new();
    binding.update(b"nido/bind/v1");
    binding.update(Sha256::digest(crate::local_stack::PASSPHRASE.as_bytes()));
    binding.update(factory_id);
    binding.update(key);
    let digest: [u8; 32] = binding.finalize().into();
    let setup_pk = setup.verifying_key().to_bytes();
    let args = std::vec![
        sc(env, BytesN::from_array(env, &setup_pk)),
        sc(env, BytesN::from_array(env, &key)),
        sc(
            env,
            BytesN::from_array(env, &setup.sign(&digest).to_bytes())
        ),
    ];
    net.setup(
        &crate::network::invoke(&net.factory, "create_account", args.clone()),
        None,
    )
    .unwrap_or_else(|e| panic!("minting {label}: {e}"));
    let address = net
        .read(&crate::network::invoke(
            &net.factory,
            "get_c_address",
            std::vec![args[0].clone()],
        ))
        .expect("the account's address");
    let address = Val::try_from_val(env, &address).expect("a host value");
    Account {
        address: Address::try_from_val(env, &address).expect("an address"),
        keys: std::vec![("owner", owner)],
    }
}

/// A grant as the snapshot records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrantView {
    pub parent: Option<u32>,
    pub key: String,
    pub rules: usize,
    pub steps: usize,
    pub rules_debug: String,
    pub allowance: String,
    pub spent: String,
    pub revoked: bool,
}

impl From<&Grant> for GrantView {
    fn from(g: &Grant) -> Self {
        Self {
            parent: g.parent,
            key: hex::encode(g.key.to_array()),
            rules: g.rules.len() as usize,
            steps: g.steps.len() as usize,
            rules_debug: format!("{:?} {:?}", g.rules, g.steps),
            allowance: g.allowance.to_string(),
            spent: g.spent.to_string(),
            revoked: g.revoked,
        }
    }
}

/// Balances, grants (with their budget nodes) and the account's
/// configuration; on the network, also the relay channels' sequence numbers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub balances: BTreeMap<String, i128>,
    pub grants: std::vec::Vec<GrantView>,
    pub revision: u64,
    pub doc_hash: Option<String>,
    pub pending_upgrade: bool,
    pub channels: BTreeMap<String, i64>,
}

impl Snapshot {
    /// The fields that differ from `other`, by name.
    #[must_use]
    pub fn diff(&self, other: &Snapshot) -> std::vec::Vec<String> {
        let mut out = std::vec::Vec::new();
        for (k, v) in &self.balances {
            if other.balances.get(k) != Some(v) {
                out.push(format!("balance {k}: {v} -> {:?}", other.balances.get(k)));
            }
        }
        if self.grants != other.grants {
            out.push(format!(
                "grants: {} -> {}",
                serde_json::to_string(&self.grants).unwrap_or_default(),
                serde_json::to_string(&other.grants).unwrap_or_default()
            ));
        }
        if self.revision != other.revision {
            out.push(format!("revision {} -> {}", self.revision, other.revision));
        }
        if self.doc_hash != other.doc_hash {
            out.push("doc hash".into());
        }
        if self.pending_upgrade != other.pending_upgrade {
            out.push("pending upgrade".into());
        }
        for (k, v) in &self.channels {
            if other.channels.get(k) != Some(v) {
                out.push(format!(
                    "channel {k}: sequence {v} -> {:?}",
                    other.channels.get(k)
                ));
            }
        }
        out
    }
}
