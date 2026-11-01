//! Email guardians on the Perch stack as Nido deploys it ([`crate::world`]).
//!
//! The guardian runs from its wasm (`just build-contracts`) with the
//! configuration a wallet would give it, and approves through a hand-built
//! authorization entry carrying an [`EmailApproval`], so the controller's
//! `require_auth_for_args((digest,))` runs the guardian's real
//! `__check_auth`.
//!
//! The DKIM key registry is the real contract from its wasm
//! (`contracts/dkim-registry`), governed in these tests by a 3-of-5 multisig
//! of generated addresses (revocation 2-of-5) and fed by the TEST-ONLY DNS
//! attester mock (`crates/dns-attestation-mock`) over the fixture key
//! records. The proof verifier is a TEST-ONLY stand-in with no cryptography:
//! [`TestOnlyVerifier`] accepts a "proof" exactly when it is [`test_proof`]
//! of the public inputs the guardian hands it, which is enough to show which
//! statement, commitment, and key root an approval binds. It is replaced by
//! the email circuit's verifier when that exists.

// A test harness: every helper either returns the contract's own result or
// panics on a failed setup step (which fails the test).
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

extern crate std;

use crate::world::{contract_at, Account, RecoveryResult, World};
use crate::{DKIM_REGISTRY_WASM, EMAIL_GUARDIAN_WASM};
use nido_dkim_registry::hash::Hasher;
use nido_dkim_registry::{
    DkimRegistryClient, RegistryConfig, LAUNCH_DOMAINS, TIMELOCK_ATTESTED_LEDGERS,
};
use nido_dns_attestation_mock::{
    fixture, key_hash, modulus_2048, observe, FixtureRecord, TestAttester,
};
use nido_email_guardian::{
    EmailApproval, EmailGuardianError, GuardianConfig, KeyPin, PUBLIC_INPUTS_LEN,
};
use perch_recovery::EvidenceDomain;
use perch_recovery_interface::zk::{split_hi_lo, ProofVerifierError};
use perch_recovery_interface::{RecoveryStatement, StatementSubject};
use perch_zk_primitives::contract_id;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
use soroban_sdk::xdr::{
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedInvocation,
    SorobanCredentials,
};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec};
use std::cell::Cell;
use std::format;

/// The size of a zero-knowledge `UltraHonk` proof, so payload sizes are real.
pub const TEST_PROOF_LEN: usize = 16_224;

/// TEST ONLY: the "proof" [`TestOnlyVerifier`] accepts for `public_inputs`:
/// `sha256("nido/email-recovery/test-only-verifier" || public_inputs)`,
/// zero-padded to a real proof's length.
pub fn test_proof(e: &Env, public_inputs: &Bytes) -> Bytes {
    let mut pre = Bytes::from_slice(e, b"nido/email-recovery/test-only-verifier");
    pre.append(public_inputs);
    let mut proof = Bytes::from_array(e, &e.crypto().sha256(&pre).to_array());
    proof.extend_from_slice(&[0u8; TEST_PROOF_LEN - 32]);
    proof
}

/// TEST ONLY: the circuit id [`TestOnlyVerifier`] reports.
pub fn test_circuit_id(e: &Env) -> BytesN<32> {
    e.crypto()
        .sha256(&Bytes::from_slice(e, b"nido/email-recovery/test-only-vk"))
        .to_bytes()
}

/// TEST ONLY: a verifier with no cryptography (see [`test_proof`]).
#[contract]
pub struct TestOnlyVerifier;

// `#[contractimpl]` entry points: the SDK ABI takes owned arguments.
#[allow(clippy::needless_pass_by_value)]
#[contractimpl]
impl TestOnlyVerifier {
    pub fn circuit_id(e: &Env) -> BytesN<32> {
        test_circuit_id(e)
    }

    pub fn verify_proof(
        e: Env,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), ProofVerifierError> {
        if public_inputs.len() != PUBLIC_INPUTS_LEN {
            return Err(ProofVerifierError::ProofParseError);
        }
        if proof_bytes == test_proof(&e, &public_inputs) {
            Ok(())
        } else {
            Err(ProofVerifierError::VerificationFailed)
        }
    }
}

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
            grace_ledgers: REGISTRY_GRACE,
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

    /// Attester `attester`'s observation of fixture `record` (the record as
    /// the attester resolved it) for proposal `id`, submitted by anyone.
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

    /// Propose fixture `name`'s key for its domain, approve it 3-of-5, and
    /// have two attesters see it live: an addition on the 72-hour path,
    /// not yet executed. Returns the proposal id and the key's leaf.
    pub fn propose_attested(&self, w: &World, name: &str) -> (u32, BytesN<32>) {
        let record = fixture(name);
        let n = modulus_2048(&record.parse().unwrap()).expect("an RSA-2048 fixture");
        let id = self.propose_add(w, 0, &record.domain, &n);
        self.approve(w, 1, id);
        self.approve(w, 2, id);
        self.attest(w, id, 0, &record);
        self.attest(w, id, 1, &record);
        let kh = BytesN::from_array(&w.env, &key_hash(&n));
        let leaf = Hasher::new(&w.env).leaf(record.domain.as_bytes(), &kh);
        (id, leaf)
    }

    /// Revoke `(domain, key_hash)` with members 3 and 4.
    pub fn revoke(&self, w: &World, domain: &str, key_hash: &BytesN<32>) {
        let id = self.propose_revoke(w, 3, domain, key_hash);
        self.approve(w, 4, id);
    }
}

/// The test registry's grace period: 24 hours.
pub const REGISTRY_GRACE: u32 = 17_280;

/// The circuit's public inputs as `docs/email-recovery/spec.md` lays them
/// out: `C || digest_hi || digest_lo || key_root`.
pub fn public_inputs(
    e: &Env,
    commitment: &BytesN<32>,
    digest: &BytesN<32>,
    root: &BytesN<32>,
) -> Bytes {
    let (hi, lo) = split_hi_lo(&digest.to_array());
    let mut out = Bytes::from_array(e, &commitment.to_array());
    out.extend_from_array(&hi);
    out.extend_from_array(&lo);
    out.extend_from_array(&root.to_array());
    out
}

/// A field element from a label: `sha256(label)` with its top byte cleared.
pub fn field(e: &Env, label: &str) -> BytesN<32> {
    let mut x = e
        .crypto()
        .sha256(&Bytes::from_slice(e, label.as_bytes()))
        .to_array();
    x[0] = 0;
    BytesN::from_array(e, &x)
}

/// One account's email guardian.
#[derive(Clone)]
pub struct EmailGuardian {
    pub address: Address,
    pub commitment: BytesN<32>,
}

/// The test-only verifier and the registry one world's email guardians
/// share. At creation the registry admits one key (fixture `rsa2048-a`, for
/// `gmail.com`) through the attested path, which advances the world 72
/// hours; `root` is the root it produced.
pub struct EmailInfra {
    pub verifier: Address,
    pub registry: TestRegistry,
    pub root: BytesN<32>,
    nonce: Cell<i64>,
}

impl EmailInfra {
    #[must_use]
    pub fn new(w: &World) -> Self {
        let verifier = contract_at(&w.env, "email/test-only-verifier");
        w.env.register_at(&verifier, TestOnlyVerifier, ());
        let registry = TestRegistry::deploy(w, "infra");
        let (id, _) = registry.propose_attested(w, "rsa2048-a");
        w.advance(TIMELOCK_ATTESTED_LEDGERS);
        let root = registry.client(w).execute(&id);
        Self {
            verifier,
            registry,
            root,
            nonce: Cell::new(0),
        }
    }

    /// Deploy `label`'s guardian for `account` from the guardian wasm, with
    /// commitment `commitment` and the `ALLOW_*` bits `allowed_actions`.
    pub fn guardian(
        &self,
        w: &World,
        account: &Account,
        label: &str,
        commitment: &BytesN<32>,
        allowed_actions: u32,
    ) -> EmailGuardian {
        self.guardian_with_pin(w, account, label, commitment, allowed_actions, None)
    }

    /// [`Self::guardian`] with an optional key pin (spec §7.4).
    pub fn guardian_with_pin(
        &self,
        w: &World,
        account: &Account,
        label: &str,
        commitment: &BytesN<32>,
        allowed_actions: u32,
        pin: Option<KeyPin>,
    ) -> EmailGuardian {
        let address = contract_at(&w.env, &format!("email-guardian/{label}"));
        let mut key_pin = Vec::new(&w.env);
        if let Some(pin) = pin {
            key_pin.push_back(pin);
        }
        let config = GuardianConfig {
            account: account.address.clone(),
            controller: w.controller.clone(),
            commitment: commitment.clone(),
            registry: self.registry.address.clone(),
            key_pin,
            allowed_actions,
            verifier: self.verifier.clone(),
            circuit_id: test_circuit_id(&w.env),
        };
        w.env.register_at(&address, EMAIL_GUARDIAN_WASM, (config,));
        EmailGuardian {
            address,
            commitment: commitment.clone(),
        }
    }

    /// What the browser prover hands the wallet for `statement`: its bytes,
    /// the registry root, and a proof for `guardian`'s public inputs.
    pub fn approval(
        &self,
        w: &World,
        guardian: &EmailGuardian,
        statement: &RecoveryStatement,
    ) -> EmailApproval {
        self.approval_against(w, guardian, statement, &self.root)
    }

    /// [`Self::approval`] with a proof made against key root `root`.
    pub fn approval_against(
        &self,
        w: &World,
        guardian: &EmailGuardian,
        statement: &RecoveryStatement,
        root: &BytesN<32>,
    ) -> EmailApproval {
        let bytes = statement.encode(&w.env).unwrap();
        let digest = w.env.crypto().sha256(&bytes).to_bytes();
        EmailApproval {
            statement: bytes,
            key_root: root.clone(),
            proof: test_proof(
                &w.env,
                &public_inputs(&w.env, &guardian.commitment, &digest, root),
            ),
        }
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
