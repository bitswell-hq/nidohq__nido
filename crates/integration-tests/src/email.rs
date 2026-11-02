//! Email guardians on the Perch stack as Nido deploys it ([`crate::world`]).
//!
//! The guardian runs from its wasm (`just build-contracts`) with the
//! configuration a wallet would give it, and approves through a hand-built
//! authorization entry carrying an [`EmailApproval`], so the controller's
//! `require_auth_for_args((digest,))` runs the guardian's real
//! `__check_auth`.
//!
//! Every dependency is real: the proof verifier is `nido-email-verifier`
//! from its wasm (Perch's vendored `UltraHonk` verifier with the email
//! circuit's key compiled in), every approval carries a real proof
//! ([`crate::email_proof`]), and the DKIM key registry is
//! `contracts/dkim-registry` from its wasm, governed by a 3-of-5 multisig of
//! generated addresses (revocation 2-of-5) and fed by the TEST-ONLY DNS
//! attester mock (`crates/dns-attestation-mock`). [`EmailInfra::new`] has it
//! admit every launch domain's TEST-ONLY provider key through the attested
//! path.

// A test harness: every helper either returns the contract's own result or
// panics on a failed setup step (which fails the test).
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

extern crate std;

use crate::email_proof::{self, Inbox, KeyPath, ProviderKey};
use crate::world::{contract_at, Account, RecoveryResult, World};
use crate::{DKIM_REGISTRY_WASM, EMAIL_GUARDIAN_WASM, EMAIL_VERIFIER_WASM};
use nido_dkim_registry::{
    DkimRegistryClient, RegistryConfig, LAUNCH_DOMAINS, TIMELOCK_ATTESTED_SECONDS,
};
use nido_dns_attestation_mock::{
    fixture, key_hash, modulus_2048, observe, FixtureRecord, TestAttester,
};
use nido_email_guardian::{EmailApproval, EmailGuardianError, GuardianConfig, KeyPin};
use perch_recovery::EvidenceDomain;
use perch_recovery_interface::{RecoveryStatement, StatementSubject};
use perch_zk_primitives::contract_id;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedInvocation,
    SorobanCredentials,
};
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec};
use std::cell::Cell;
use std::format;
use std::string::ToString;

/// The DKIM key registry from its wasm, with test members and the mock's
/// test attesters. Member calls are authorized by `mock_auths` for exactly
/// that member and invocation; the world stays enforcing otherwise.
pub struct TestRegistry {
    pub address: Address,
    pub members: std::vec::Vec<Address>,
    attesters: std::vec::Vec<TestAttester>,
}

impl TestRegistry {
    /// 3-of-5 members, revocation 2-of-5, attesters 2-of-3, 24-hour grace,
    /// the proposed launch allowlist.
    #[must_use]
    pub fn deploy(w: &World, label: &str) -> Self {
        let members: std::vec::Vec<Address> = (0..5).map(|_| Address::generate(&w.env)).collect();
        let attesters: std::vec::Vec<TestAttester> = (0..3).map(TestAttester::new).collect();
        let mut m = Vec::new(&w.env);
        for a in &members {
            m.push_back(a.clone());
        }
        let mut keys = Vec::new(&w.env);
        for a in &attesters {
            keys.push_back(BytesN::from_array(&w.env, &a.public_key()));
        }
        let mut domains = Vec::new(&w.env);
        for d in LAUNCH_DOMAINS {
            domains.push_back(Bytes::from_slice(&w.env, d.as_bytes()));
        }
        let config = RegistryConfig {
            members: m,
            threshold: 3,
            revoke_threshold: 2,
            attesters: keys,
            attest_threshold: 2,
            grace_seconds: REGISTRY_GRACE,
            domains,
        };
        let address = contract_at(&w.env, &format!("email/dkim-registry/{label}"));
        w.env.register_at(&address, DKIM_REGISTRY_WASM, (config,));
        Self {
            address,
            members,
            attesters,
        }
    }

    #[must_use]
    pub fn client<'a>(&self, w: &'a World) -> DkimRegistryClient<'a> {
        DkimRegistryClient::new(&w.env, &self.address)
    }

    fn as_member<T>(
        &self,
        w: &World,
        member: usize,
        fn_name: &str,
        args: Vec<Val>,
        call: impl FnOnce(&DkimRegistryClient) -> T,
    ) -> T {
        w.env.mock_auths(&[MockAuth {
            address: &self.members[member],
            invoke: &MockAuthInvoke {
                contract: &self.address,
                fn_name,
                args,
                sub_invokes: &[],
            },
        }]);
        let out = call(&self.client(w));
        w.env.set_auths(&[]);
        out
    }

    pub fn propose_add(&self, w: &World, member: usize, domain: &str, modulus: &[u8]) -> u32 {
        let m = self.members[member].clone();
        let domain = Bytes::from_slice(&w.env, domain.as_bytes());
        let modulus = Bytes::from_slice(&w.env, modulus);
        let args = (m.clone(), domain.clone(), modulus.clone()).into_val(&w.env);
        self.as_member(w, member, "propose_add", args, |c| {
            c.propose_add(&m, &domain, &modulus)
        })
    }

    pub fn propose_revoke(
        &self,
        w: &World,
        member: usize,
        domain: &str,
        key_hash: &BytesN<32>,
    ) -> u32 {
        let m = self.members[member].clone();
        let domain = Bytes::from_slice(&w.env, domain.as_bytes());
        let args = (m.clone(), domain.clone(), key_hash.clone()).into_val(&w.env);
        self.as_member(w, member, "propose_revoke", args, |c| {
            c.propose_revoke(&m, &domain, key_hash)
        })
    }

    pub fn approve(&self, w: &World, member: usize, id: u32) {
        let m = self.members[member].clone();
        let args = (m.clone(), id).into_val(&w.env);
        self.as_member(w, member, "approve", args, |c| c.approve(&m, &id));
    }

    /// Attester `attester`'s observation of `record` (the record as the
    /// attester resolved it) for proposal `id`, submitted by anyone.
    pub fn attest(&self, w: &World, id: u32, attester: usize, record: &FixtureRecord) {
        let p = self.client(w).proposal(&id).expect("a proposal");
        let signed = self.attesters[attester].attest(
            &contract_id(&w.env, &self.address).unwrap().to_array(),
            &observe(
                &record.domain,
                &record.selector,
                Some(&record.strings()),
                p.key_hash.to_array(),
                w.env.ledger().timestamp(),
                &["8.8.8.8", "1.1.1.1", "9.9.9.9"],
            ),
        );
        self.client(w).attest(
            &id,
            &BytesN::from_array(&w.env, &signed.attester),
            &Bytes::from_slice(&w.env, &signed.bytes),
            &BytesN::from_array(&w.env, &signed.signature),
        );
    }

    /// Propose `record`'s key for its domain, approve it 3-of-5, and have two
    /// attesters see it live: an addition on the 72-hour path, not yet
    /// executed. Returns the proposal id.
    pub fn propose_attested_record(&self, w: &World, record: &FixtureRecord) -> u32 {
        let n = modulus_2048(&record.parse().unwrap()).expect("an RSA-2048 record");
        let id = self.propose_add(w, 0, &record.domain, &n);
        self.approve(w, 1, id);
        self.approve(w, 2, id);
        self.attest(w, id, 0, record);
        self.attest(w, id, 1, record);
        id
    }

    /// [`Self::propose_attested_record`] for the DNS attester mock's
    /// fixture record `name`. Returns the proposal id and the key's leaf.
    pub fn propose_attested(&self, w: &World, name: &str) -> (u32, BytesN<32>) {
        let record = fixture(name);
        let n = modulus_2048(&record.parse().unwrap()).expect("an RSA-2048 fixture");
        let id = self.propose_attested_record(w, &record);
        let kh = BytesN::from_array(&w.env, &key_hash(&n));
        let leaf =
            nido_dkim_registry::hash::Hasher::new(&w.env).leaf(record.domain.as_bytes(), &kh);
        (id, leaf)
    }

    /// [`Self::propose_attested_record`] for a provider key as the mock DNS
    /// publishes it.
    pub fn propose_attested_key(&self, w: &World, key: &ProviderKey) -> u32 {
        let record = FixtureRecord {
            name: format!("{}/{}", key.domain, key.selector),
            domain: key.domain.clone(),
            selector: key.selector.clone(),
            note: "TEST-ONLY provider key of @nidohq/email-mocks".to_string(),
            strings: key.strings().into_iter().map(ToString::to_string).collect(),
        };
        self.propose_attested_record(w, &record)
    }

    /// Revoke `(domain, key_hash)` with members 3 and 4.
    pub fn revoke(&self, w: &World, domain: &str, key_hash: &BytesN<32>) {
        let id = self.propose_revoke(w, 3, domain, key_hash);
        self.approve(w, 4, id);
    }
}

/// The test registry's grace period: 24 hours, in seconds.
pub const REGISTRY_GRACE: u64 = 86_400;

/// One account's email guardian and the inbox it commits to.
#[derive(Clone)]
pub struct EmailGuardian {
    pub address: Address,
    pub commitment: BytesN<32>,
    pub inbox: Inbox,
}

/// The verifier and the registry one world's email guardians share. At
/// creation the registry admits, through the attested path, the current
/// TEST-ONLY key of every launch domain (in the allowlist's order, so leaf
/// `i` is `LAUNCH_DOMAINS[i]`), which advances the world 72 hours; `root`
/// is the root they produce.
pub struct EmailInfra {
    pub verifier: Address,
    pub registry: TestRegistry,
    pub root: BytesN<32>,
    nonce: Cell<i64>,
}

impl EmailInfra {
    #[must_use]
    pub fn new(w: &World) -> Self {
        let verifier = contract_at(&w.env, "email/verifier");
        w.env.register_at(&verifier, EMAIL_VERIFIER_WASM, ());
        let registry = TestRegistry::deploy(w, "infra");
        let ids: std::vec::Vec<u32> = LAUNCH_DOMAINS
            .iter()
            .map(|d| registry.propose_attested_key(w, &email_proof::provider_key(d, "current")))
            .collect();
        w.advance_seconds(TIMELOCK_ATTESTED_SECONDS);
        let mut root = None;
        for id in ids {
            root = Some(registry.client(w).execute(&id));
        }
        Self {
            verifier,
            registry,
            root: root.unwrap(),
            nonce: Cell::new(0),
        }
    }

    /// The circuit id the verifier reports: `sha256` of its key.
    #[must_use]
    pub fn circuit_id(w: &World) -> BytesN<32> {
        BytesN::from_array(&w.env, &email_proof::circuit_id())
    }

    /// `key`'s path in the registry's current tree, read from the registry
    /// as a wallet reads it (`leaf`, `siblings`, `root`).
    #[must_use]
    pub fn registry_path(&self, w: &World, key: &ProviderKey) -> KeyPath {
        let c = self.registry.client(w);
        let record = c
            .leaf(
                &Bytes::from_slice(&w.env, key.domain.as_bytes()),
                &BytesN::from_array(&w.env, &key.key_hash()),
            )
            .expect("the key is in the registry");
        assert!(record.present, "the key's leaf is present");
        KeyPath {
            root: c.root().to_array(),
            index: record.index,
            siblings: c
                .siblings(&record.index)
                .iter()
                .map(|s| s.to_array())
                .collect(),
        }
    }

    /// The leaves of the registry's tree as `new` builds it.
    #[must_use]
    pub fn launch_leaves() -> std::vec::Vec<[u8; 32]> {
        LAUNCH_DOMAINS
            .iter()
            .map(|d| email_proof::provider_key(d, "current").leaf())
            .collect()
    }

    /// Deploy `label`'s guardian for `account` from the guardian wasm,
    /// committing to `inbox`, with the `ALLOW_*` bits `allowed_actions`.
    pub fn guardian(
        &self,
        w: &World,
        account: &Account,
        label: &str,
        inbox: &Inbox,
        allowed_actions: u32,
    ) -> EmailGuardian {
        self.guardian_with_pin(w, account, label, inbox, allowed_actions, None)
    }

    /// [`Self::guardian`] with an optional key pin (spec §7.4).
    pub fn guardian_with_pin(
        &self,
        w: &World,
        account: &Account,
        label: &str,
        inbox: &Inbox,
        allowed_actions: u32,
        pin: Option<KeyPin>,
    ) -> EmailGuardian {
        let address = contract_at(&w.env, &format!("email-guardian/{label}"));
        let mut key_pin = Vec::new(&w.env);
        if let Some(pin) = pin {
            key_pin.push_back(pin);
        }
        let commitment = BytesN::from_array(&w.env, &inbox.commitment());
        let config = GuardianConfig {
            account: account.address.clone(),
            controller: w.controller.clone(),
            commitment: commitment.clone(),
            registry: self.registry.address.clone(),
            key_pin,
            allowed_actions,
            verifier: self.verifier.clone(),
            circuit_id: Self::circuit_id(w),
        };
        w.env.register_at(&address, EMAIL_GUARDIAN_WASM, (config,));
        EmailGuardian {
            address,
            commitment,
            inbox: inbox.clone(),
        }
    }

    /// What the browser prover hands the wallet for `statement`: its bytes,
    /// the key root, and a real proof (fixture `name`) that `guardian`'s
    /// inbox emailed its approval, signed by a key at `path`.
    pub fn approval(
        &self,
        w: &World,
        guardian: &EmailGuardian,
        name: &str,
        description: &str,
        statement: &RecoveryStatement,
        path: &KeyPath,
    ) -> EmailApproval {
        EmailApproval {
            statement: statement.encode(&w.env).unwrap(),
            key_root: BytesN::from_array(&w.env, &path.root),
            proof: email_proof::proof(&w.env, name, description, &guardian.inbox, statement, path),
        }
    }

    /// [`Self::approval`] against the registry's current tree.
    pub fn registry_approval(
        &self,
        w: &World,
        guardian: &EmailGuardian,
        name: &str,
        description: &str,
        statement: &RecoveryStatement,
    ) -> EmailApproval {
        let path = self.registry_path(w, &guardian.inbox.key());
        self.approval(w, guardian, name, description, statement, &path)
    }

    /// The guardian's authorization entry for `root`, carrying `approval`.
    /// Nonces only need to be unique per guardian.
    pub fn entry(
        &self,
        w: &World,
        guardian: &EmailGuardian,
        root: SorobanAuthorizedInvocation,
        approval: &EmailApproval,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.nonce.get() + 1;
        self.nonce.set(nonce);
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: guardian.address.clone().into(),
                nonce,
                signature_expiration_ledger: w.ledger() + 1_000,
                signature: w.sc(approval.clone()),
            }),
            root_invocation: root,
        }
    }

    /// The guardian's `__check_auth` verdict on `approval` in the context the
    /// controller's `submit_guardian` gives it for `account`'s attempt in
    /// `domain`. The host reports a refused `__check_auth` to the controller's
    /// caller only as an aborted call; this reads the guardian's own error.
    pub fn check_auth(
        &self,
        w: &World,
        account: &Account,
        guardian: &EmailGuardian,
        attempt: u64,
        domain: EvidenceDomain,
        approval: &EmailApproval,
    ) -> Result<(), EmailGuardianError> {
        let digest = w.digest(&w.statement(account, attempt, domain));
        let contexts = soroban_sdk::vec![
            &w.env,
            Context::Contract(ContractContext {
                contract: w.controller.clone(),
                fn_name: Symbol::new(&w.env, "submit_guardian"),
                args: soroban_sdk::vec![&w.env, digest.into_val(&w.env)],
            }),
        ];
        w.env
            .try_invoke_contract_check_auth::<EmailGuardianError>(
                &guardian.address,
                &BytesN::from_array(&w.env, &[0u8; 32]),
                approval.clone().into_val(&w.env),
                &contexts,
            )
            .map_err(|e| e.expect("a guardian error"))
    }

    /// `submit_guardian` for `account`'s attempt in `domain`, authorized by
    /// `guardian` with `approval`.
    pub fn try_submit(
        &self,
        w: &World,
        account: &Account,
        guardian: &EmailGuardian,
        attempt: u64,
        domain: EvidenceDomain,
        approval: &EmailApproval,
    ) -> RecoveryResult<()> {
        let digest = w.digest(&w.statement(account, attempt, domain));
        let root = w.invocation(&w.controller, "submit_guardian", std::vec![w.sc(digest)]);
        let entry = self.entry(w, guardian, root, approval);
        w.with_auths(&[entry], || {
            w.ctl()
                .try_submit_guardian(&account.address, &attempt, &domain, &guardian.address)
                .map(|r| r.unwrap())
        })
    }

    /// `approve_change` for `account`'s `Reconfigure`/`Upgrade` subject,
    /// authorized by `guardian` with `approval`.
    pub fn try_approve_change(
        &self,
        w: &World,
        account: &Account,
        guardian: &EmailGuardian,
        subject: &StatementSubject,
        valid_until: u32,
        approval: &EmailApproval,
    ) -> RecoveryResult<()> {
        let statement = w
            .ctl()
            .change_statement(&account.address, subject, &valid_until);
        let root = w.invocation(
            &w.controller,
            "approve_change",
            std::vec![w.sc(w.digest(&statement))],
        );
        let entry = self.entry(w, guardian, root, approval);
        w.with_auths(&[entry], || {
            w.ctl()
                .try_approve_change(&account.address, subject, &valid_until, &guardian.address)
                .map(|r| r.unwrap())
        })
    }
}

/// `approval` with its statement replaced by `statement`'s encoding: the
/// bytes a splicing attacker submits with another approval's proof.
#[must_use]
pub fn with_statement(
    env: &Env,
    approval: &EmailApproval,
    statement: &RecoveryStatement,
) -> EmailApproval {
    EmailApproval {
        statement: statement.encode(env).unwrap(),
        ..approval.clone()
    }
}
