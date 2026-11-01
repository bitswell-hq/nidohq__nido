//! One Nido account with agents, in the Soroban host under enforcing
//! authorization: the world of `crates/integration-tests` (every Perch
//! contract from its deployed wasm, the account minted by Nido's factory),
//! the grant signer from its wasm as the account's delegated signer, two
//! Stellar Asset Contracts (the budget asset and another token) and
//! instances of the evaluation's dApp wasm.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use ed25519_dalek::{Signer as _, SigningKey};
use nido_grant_signer::{Arg, Caveat, Grant, GrantError, GrantSignature, GrantSignerClient};
use nido_integration_tests::world::{strkey, world, Account, Passkey, World, NETWORK};
use nido_integration_tests::GRANT_SIGNER_WASM;
use serde::Serialize;
use soroban_sdk::auth::Context;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::xdr::{
    HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, Limits, ScVal, SorobanAddressCredentials,
    SorobanAddressCredentialsWithDelegates, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, SorobanDelegateSignature, VecM, WriteXdr,
};
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal, InvokeError, Map, Symbol, Val, Vec};
use stellar_accounts::smart_account::{AuthPayload, Signer};

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

pub struct Fixture {
    pub w: World,
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
}

impl Fixture {
    /// An account whose document gives agents one rule per asset and dApp
    /// instance, plus `extra`, with `dapps` instances of `dapp_wasm`.
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

        let mut rules = BTreeMap::new();
        rules.insert(strkey(&asset), "a-asset".to_owned());
        rules.insert(strkey(&other), "a-other".to_owned());
        rules.insert(strkey(&w.target), "a-target".to_owned());
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
            bob: Address::generate(&env),
            carol: Address::generate(&env),
            mallory: Address::generate(&env),
            w,
            account,
            signer,
            asset,
            other,
            dapps,
            rules,
            nonce: Cell::new(1 << 40),
        };
        let doc = f.doc(None);
        f.w.apply_bytes_as(&f.account, "owner", &doc, 0)
            .expect("the agents' document applies");
        f
    }

    #[must_use]
    pub fn env(&self) -> &Env {
        &self.w.env
    }

    #[must_use]
    pub fn client(&self) -> GrantSignerClient<'_> {
        GrantSignerClient::new(self.env(), &self.signer)
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
    pub fn run(&self, entries: &[SorobanAuthorizationEntry], call: impl FnOnce()) -> Outcome {
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

    /// Call `f(args)` on the grant signer as the account, authorized by the
    /// owner passkey through the admin rule.
    pub fn admin(&self, f: &str, args: &Vec<Val>) -> Outcome {
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

    /// The owner issues a root grant over the budget asset; returns its id.
    ///
    /// # Panics
    /// If the owner's `issue` fails.
    pub fn issue(&self, key: &SigningKey, caveats: &[Caveat], allowance: u128) -> u32 {
        let e = self.env();
        let next = self.next_id();
        let args = Vec::from_array(
            e,
            [
                pubkey(e, key).into_val(e),
                Vec::from_slice(e, caveats).into_val(e),
                self.asset.into_val(e),
                allowance.into_val(e),
            ],
        );
        assert_eq!(self.admin("issue", &args), Outcome::Allowed, "issue");
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
        (0u32..).map_while(|id| self.client().grant(&id)).collect()
    }

    #[must_use]
    pub fn balance(&self, token: &Address, a: &Address) -> i128 {
        TokenClient::new(self.env(), token).balance(a)
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
        self.w.sc(GrantSignature {
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
        Vec::from_iter(
            self.env(),
            names
                .iter()
                .map(|r| self.w.rule_id(&self.account.address, r)),
        )
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
        let expiration = self.w.ledger() + 1_000;
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
                        signature: self.w.sc(AuthPayload {
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

    /// An invocation node of `contract.f(args)` with `subs` nested in it.
    #[must_use]
    pub fn node(
        &self,
        contract: &Address,
        f: &str,
        args: &Vec<Val>,
        subs: std::vec::Vec<SorobanAuthorizedInvocation>,
    ) -> SorobanAuthorizedInvocation {
        let w = &self.w;
        let mut n = w.invocation(contract, f, args.iter().map(|v| w.sc(v)).collect());
        n.sub_invocations = subs.try_into().unwrap();
        n
    }

    /// Invoke `contract.f(args)` with `entries` as the only authorization.
    pub fn call(
        &self,
        entries: &[SorobanAuthorizationEntry],
        contract: &Address,
        f: &str,
        args: &Vec<Val>,
    ) -> Outcome {
        self.run(entries, || {
            self.env()
                .invoke_contract::<Val>(contract, &Symbol::new(self.env(), f), args.clone());
        })
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
    /// `grant`'s holder `key`.
    pub fn verdict(
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

    // --- state ---------------------------------------------------------------

    /// Everything a refused attack must leave unchanged.
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
        let account = self.w.account(&self.account);
        Snapshot {
            balances,
            grants: self.grants().iter().map(GrantView::from).collect(),
            revision: account.revision(),
            doc_hash: account
                .applied_doc_hash()
                .map(|h| hex::encode(h.to_array())),
            pending_upgrade: account.pending_upgrade().is_some(),
        }
    }
}

/// A grant as the snapshot records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrantView {
    pub parent: Option<u32>,
    pub key: String,
    pub caveats: usize,
    pub caveats_debug: String,
    pub allowance: String,
    pub spent: String,
    pub revoked: bool,
}

impl From<&Grant> for GrantView {
    fn from(g: &Grant) -> Self {
        Self {
            parent: g.parent,
            key: hex::encode(g.key.to_array()),
            caveats: g.caveats.len() as usize,
            caveats_debug: format!("{:?}", g.caveats),
            allowance: g.allowance.to_string(),
            spent: g.spent.to_string(),
            revoked: g.revoked,
        }
    }
}

/// Balances, grants (with their budget nodes) and the account's
/// configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub balances: BTreeMap<String, i128>,
    pub grants: std::vec::Vec<GrantView>,
    pub revision: u64,
    pub doc_hash: Option<String>,
    pub pending_upgrade: bool,
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
        out
    }
}
