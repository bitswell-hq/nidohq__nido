//! Email guardians on the Perch stack as Nido deploys it ([`crate::world`]).
//!
//! The guardian runs from its wasm (`just build-contracts`) with the
//! configuration a wallet would give it, and approves through a hand-built
//! authorization entry carrying an [`EmailApproval`], so the controller's
//! `require_auth_for_args((digest,))` runs the guardian's real
//! `__check_auth`.
//!
//! The proof verifier and the DKIM key registry are TEST-ONLY stand-ins with
//! no cryptography and no governance: [`TestOnlyVerifier`] accepts a "proof"
//! exactly when it is [`test_proof`] of the public inputs the guardian hands
//! it, which is enough to show which statement, commitment, and key root an
//! approval binds. They are replaced by the email circuit's verifier and the
//! registry contract when those exist.

// A test harness: every helper either returns the contract's own result or
// panics on a failed setup step (which fails the test).
#![allow(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

extern crate std;

use crate::world::{contract_at, Account, RecoveryResult, World};
use crate::EMAIL_GUARDIAN_WASM;
use nido_email_guardian::{EmailApproval, EmailGuardianError, GuardianConfig, PUBLIC_INPUTS_LEN};
use perch_recovery::EvidenceDomain;
use perch_recovery_interface::zk::{split_hi_lo, ProofVerifierError};
use perch_recovery_interface::{RecoveryStatement, StatementSubject};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::xdr::{
    SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedInvocation,
    SorobanCredentials,
};
use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, Env, IntoVal, Symbol, Vec};
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

/// TEST ONLY: a registry whose accepted roots are set directly.
#[contract]
pub struct TestOnlyRegistry;

// `#[contractimpl]` entry points: the SDK ABI takes owned arguments.
#[allow(clippy::needless_pass_by_value)]
#[contractimpl]
impl TestOnlyRegistry {
    pub fn set_accepted(e: Env, root: BytesN<32>, accepted: bool) {
        e.storage().instance().set(&root, &accepted);
    }

    pub fn is_accepted_root(e: Env, root: BytesN<32>) -> bool {
        e.storage().instance().get(&root).unwrap_or(false)
    }
}

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

/// The test-only verifier and registry one world's email guardians share,
/// with one key root the registry accepts.
pub struct EmailInfra {
    pub verifier: Address,
    pub registry: Address,
    pub root: BytesN<32>,
    nonce: Cell<i64>,
}

impl EmailInfra {
    #[must_use]
    pub fn new(w: &World) -> Self {
        let verifier = contract_at(&w.env, "email/test-only-verifier");
        w.env.register_at(&verifier, TestOnlyVerifier, ());
        let registry = contract_at(&w.env, "email/test-only-registry");
        w.env.register_at(&registry, TestOnlyRegistry, ());
        let root = field(&w.env, "nido-it/email/registry-root");
        TestOnlyRegistryClient::new(&w.env, &registry).set_accepted(&root, &true);
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
        let address = contract_at(&w.env, &format!("email-guardian/{label}"));
        let config = GuardianConfig {
            account: account.address.clone(),
            controller: w.controller.clone(),
            commitment: commitment.clone(),
            registry: self.registry.clone(),
            key_pin: Vec::new(&w.env),
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
        let bytes = statement.encode(&w.env).unwrap();
        let digest = w.env.crypto().sha256(&bytes).to_bytes();
        EmailApproval {
            statement: bytes,
            key_root: self.root.clone(),
            proof: test_proof(
                &w.env,
                &public_inputs(&w.env, &guardian.commitment, &digest, &self.root),
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
