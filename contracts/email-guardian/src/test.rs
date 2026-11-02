//! Unit tests: every acceptance and refusal path of the constructor and
//! `__check_auth`, against Perch's own statement encoder.
//!
//! The verifier and registry here are TEST-ONLY stand-ins (no cryptography,
//! no governance): [`TestOnlyVerifier`] accepts a "proof" exactly when it is
//! [`test_proof`] of the public inputs it is given, which is enough to show
//! which public inputs the guardian builds. The guardian's own code path is
//! the production one.

extern crate std;

use crate::{
    parse_statement, EmailApproval, EmailGuardian, EmailGuardianClient, EmailGuardianError,
    GuardianConfig, KeyPin, ALLOW_ALL, ALLOW_CANCEL, ALLOW_LOST_KEY, MAX_PIN_LIFETIME_SECONDS,
    PUBLIC_INPUTS_LEN,
};
use perch_recovery_interface::zk::{split_hi_lo, ProofVerifierError, BN254_SCALAR_MODULUS};
use perch_recovery_interface::{
    AttemptSubject, CancelSubject, ConfigBinding, ConfigChange, RecoveryStatement,
    StatementSubject, StatementTiming, UpgradeSubject,
};
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{
    contract, contractimpl, symbol_short, vec, Address, Bytes, BytesN, Env, IntoVal, Symbol, Vec,
};

const NETWORK: &str = "Test SDF Network ; September 2015";
const START: u32 = 1_000;
const START_TS: u64 = 1_793_500_000;
/// The size of a zero-knowledge `UltraHonk` proof, so payload sizes are real.
const TEST_PROOF_LEN: usize = 16_224;

// ---------------------------------------------------------------------------
// TEST-ONLY stand-ins
// ---------------------------------------------------------------------------

/// TEST ONLY: the "proof" this test verifier accepts for `public_inputs`:
/// `sha256("nido/email-recovery/test-only-verifier" || public_inputs)`,
/// zero-padded to a real proof's length.
fn test_proof(e: &Env, public_inputs: &Bytes) -> Bytes {
    let mut pre = Bytes::from_slice(e, b"nido/email-recovery/test-only-verifier");
    pre.append(public_inputs);
    let mut proof = Bytes::from_array(e, &e.crypto().sha256(&pre).to_array());
    proof.extend_from_slice(&[0u8; TEST_PROOF_LEN - 32]);
    proof
}

fn test_circuit_id(e: &Env) -> BytesN<32> {
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

    pub fn set_broken(e: Env, broken: bool) {
        e.storage()
            .instance()
            .set(&symbol_short!("broken"), &broken);
    }

    pub fn is_accepted_root(e: Env, root: BytesN<32>) -> bool {
        if e.storage()
            .instance()
            .get(&symbol_short!("broken"))
            .unwrap_or(false)
        {
            panic!("registry unavailable");
        }
        e.storage().instance().get(&root).unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Setup {
    e: Env,
    guardian: Address,
    account: Address,
    controller: Address,
    registry: Address,
    verifier: Address,
    commitment: BytesN<32>,
    root: BytesN<32>,
}

fn fe(e: &Env, byte: u8) -> BytesN<32> {
    let mut x = [byte; 32];
    x[0] = 0; // below the field modulus
    BytesN::from_array(e, &x)
}

fn env() -> Env {
    let e = Env::default();
    let network_id = e
        .crypto()
        .sha256(&Bytes::from_slice(&e, NETWORK.as_bytes()))
        .to_array();
    e.ledger().with_mut(|l| {
        l.sequence_number = START;
        l.timestamp = START_TS;
        l.network_id = network_id;
    });
    e
}

fn config(s: &Setup, allowed_actions: u32, key_pin: Option<KeyPin>) -> GuardianConfig {
    let key_pin = match key_pin {
        Some(pin) => vec![&s.e, pin],
        None => Vec::new(&s.e),
    };
    GuardianConfig {
        account: s.account.clone(),
        controller: s.controller.clone(),
        commitment: s.commitment.clone(),
        registry: s.registry.clone(),
        key_pin,
        allowed_actions,
        verifier: s.verifier.clone(),
        circuit_id: test_circuit_id(&s.e),
    }
}

/// Everything but the guardian; [`deploy`] adds it.
fn parts() -> Setup {
    let e = env();
    let registry = e.register(TestOnlyRegistry, ());
    let verifier = e.register(TestOnlyVerifier, ());
    let root = fe(&e, 0x42);
    TestOnlyRegistryClient::new(&e, &registry).set_accepted(&root, &true);
    Setup {
        guardian: Address::generate(&e),
        account: Address::generate(&e),
        controller: Address::generate(&e),
        commitment: fe(&e, 0xc0),
        registry,
        verifier,
        root,
        e,
    }
}

fn deploy(mut s: Setup, allowed_actions: u32, key_pin: Option<KeyPin>) -> Setup {
    let config = config(&s, allowed_actions, key_pin);
    s.guardian = s.e.register(EmailGuardian, (config,));
    s
}

fn setup() -> Setup {
    deploy(parts(), ALLOW_ALL, None)
}

fn statement_for(s: &Setup, account: &Address, action: u8, valid_until: u32) -> RecoveryStatement {
    let e = &s.e;
    let attempt = AttemptSubject {
        attempt_id: 7,
        source_doc_hash: fe(e, 0x22),
        target_doc_hash: fe(e, 0x33),
        replacements_hash: fe(e, 0x44),
    };
    RecoveryStatement {
        network_id: e.ledger().network_id(),
        account: account.clone(),
        controller: s.controller.clone(),
        config: ConfigBinding {
            epoch: 3,
            config_hash: fe(e, 0x11),
        },
        timing: StatementTiming {
            delay_ledgers: 120_960,
            expiry_ledgers: 17_280,
            valid_until_ledger: valid_until,
        },
        subject: match action {
            1 => StatementSubject::LostKey(attempt),
            2 => StatementSubject::Compromise(attempt),
            3 => StatementSubject::Cancel(CancelSubject {
                attempt_id: 7,
                attempt_statement: fe(e, 0x55),
            }),
            4 => StatementSubject::Reconfigure(ConfigChange::Set(fe(e, 0x66))),
            _ => StatementSubject::Upgrade(UpgradeSubject {
                request_id: 2,
                wasm_hash: fe(e, 0x77),
            }),
        },
    }
}

fn statement(s: &Setup, action: u8) -> Bytes {
    statement_for(s, &s.account, action, START + 100)
        .encode(&s.e)
        .unwrap()
}

fn digest(e: &Env, statement: &Bytes) -> BytesN<32> {
    e.crypto().sha256(statement).to_bytes()
}

/// The circuit's public inputs as the spec lays them out, built here
/// independently of the guardian.
fn spec_public_inputs(
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

/// An approval whose proof is valid for this guardian's own public inputs.
fn approval(s: &Setup, statement: &Bytes, root: &BytesN<32>) -> EmailApproval {
    let inputs = spec_public_inputs(&s.e, &s.commitment, &digest(&s.e, statement), root);
    EmailApproval {
        statement: statement.clone(),
        key_root: root.clone(),
        proof: test_proof(&s.e, &inputs),
    }
}

fn entry(action: u8) -> &'static str {
    if action >= 4 {
        "approve_change"
    } else {
        "submit_guardian"
    }
}

fn context(s: &Setup, contract: &Address, fn_name: &str, digest: &BytesN<32>) -> Vec<Context> {
    vec![
        &s.e,
        Context::Contract(ContractContext {
            contract: contract.clone(),
            fn_name: Symbol::new(&s.e, fn_name),
            args: vec![&s.e, digest.into_val(&s.e)],
        }),
    ]
}

fn check_with(
    s: &Setup,
    approval: &EmailApproval,
    contexts: &Vec<Context>,
) -> Result<(), EmailGuardianError> {
    let payload = BytesN::from_array(&s.e, &[9u8; 32]);
    s.e.try_invoke_contract_check_auth::<EmailGuardianError>(
        &s.guardian,
        &payload,
        approval.clone().into_val(&s.e),
        contexts,
    )
    .map_err(|err| err.expect("a guardian error"))
}

/// `__check_auth` for `approval` under the controller context its statement
/// arrives in.
fn check(s: &Setup, approval: &EmailApproval) -> Result<(), EmailGuardianError> {
    let action = parse_statement(&approval.statement.iter().collect::<std::vec::Vec<u8>>())
        .map_or(1, |v| v.action);
    let ctx = context(
        s,
        &s.controller,
        entry(action),
        &digest(&s.e, &approval.statement),
    );
    check_with(s, approval, &ctx)
}

// ---------------------------------------------------------------------------
// Acceptance
// ---------------------------------------------------------------------------

#[test]
fn approves_every_action_through_its_entry_point() {
    let s = setup();
    for action in 1..=5u8 {
        let st = statement(&s, action);
        assert_eq!(
            check(&s, &approval(&s, &st, &s.root)),
            Ok(()),
            "action {action}"
        );
    }
}

#[test]
fn statement_parser_reads_perch_encodings() {
    let s = setup();
    let account_id = perch_recovery_interface::address_payload(&s.e, &s.account)
        .unwrap()
        .1;
    for action in 1..=5u8 {
        let bytes = statement(&s, action);
        let v = parse_statement(&bytes.iter().collect::<std::vec::Vec<u8>>()).unwrap();
        assert_eq!(v.action, action);
        assert_eq!(v.account, account_id);
        assert_eq!(v.network_id, s.e.ledger().network_id().to_array());
        assert_eq!(v.valid_until_ledger, START + 100);
    }
}

#[test]
fn config_view_returns_the_construction_arguments() {
    let s = setup();
    let config = EmailGuardianClient::new(&s.e, &s.guardian).config();
    assert_eq!(config, crate::test::config(&s, ALLOW_ALL, None));
    assert_eq!(EmailGuardianClient::new(&s.e, &s.guardian).version(), 1);
}

// ---------------------------------------------------------------------------
// Refusals, in check order
// ---------------------------------------------------------------------------

#[test]
fn refuses_anything_but_one_controller_call_carrying_a_digest() {
    let s = setup();
    let st = statement(&s, 1);
    let a = approval(&s, &st, &s.root);
    let d = digest(&s.e, &st);
    let other = Address::generate(&s.e);
    let one = context(&s, &s.controller, "submit_guardian", &d);
    let mut two = one.clone();
    two.append(&one);
    let no_args = vec![
        &s.e,
        Context::Contract(ContractContext {
            contract: s.controller.clone(),
            fn_name: Symbol::new(&s.e, "submit_guardian"),
            args: vec![&s.e],
        }),
    ];
    let not_a_digest = vec![
        &s.e,
        Context::Contract(ContractContext {
            contract: s.controller.clone(),
            fn_name: Symbol::new(&s.e, "submit_guardian"),
            args: vec![&s.e, 7u32.into_val(&s.e)],
        }),
    ];
    for contexts in [
        vec![&s.e],
        two,
        context(&s, &other, "submit_guardian", &d),
        no_args,
        not_a_digest,
    ] {
        assert_eq!(
            check_with(&s, &a, &contexts),
            Err(EmailGuardianError::UnexpectedContext)
        );
    }
}

#[test]
fn refuses_a_statement_that_is_not_the_digest_preimage() {
    let s = setup();
    let a = approval(&s, &statement(&s, 1), &s.root);
    let other = digest(&s.e, &statement(&s, 2));
    let ctx = context(&s, &s.controller, "submit_guardian", &other);
    assert_eq!(
        check_with(&s, &a, &ctx),
        Err(EmailGuardianError::DigestMismatch)
    );
}

#[test]
fn refuses_bytes_that_are_not_a_statement() {
    let s = setup();
    let mut bytes = statement(&s, 1);
    bytes.set(24, 1); // version 1
    assert_eq!(
        check(&s, &approval(&s, &bytes, &s.root)),
        Err(EmailGuardianError::MalformedStatement)
    );
    let truncated = statement(&s, 1).slice(0..214);
    assert_eq!(
        check(&s, &approval(&s, &truncated, &s.root)),
        Err(EmailGuardianError::MalformedStatement)
    );
}

#[test]
fn refuses_a_statement_for_another_network() {
    let s = setup();
    let mut st = statement_for(&s, &s.account, 1, START + 100);
    st.network_id = fe(&s.e, 0x99);
    let bytes = st.encode(&s.e).unwrap();
    assert_eq!(
        check(&s, &approval(&s, &bytes, &s.root)),
        Err(EmailGuardianError::WrongNetwork)
    );
}

#[test]
fn refuses_a_statement_for_another_account() {
    let s = setup();
    let other = Address::generate(&s.e);
    let bytes = statement_for(&s, &other, 1, START + 100)
        .encode(&s.e)
        .unwrap();
    assert_eq!(
        check(&s, &approval(&s, &bytes, &s.root)),
        Err(EmailGuardianError::WrongAccount)
    );
}

#[test]
fn refuses_a_statement_for_another_controller() {
    let s = setup();
    let mut st = statement_for(&s, &s.account, 1, START + 100);
    st.controller = Address::generate(&s.e);
    let bytes = st.encode(&s.e).unwrap();
    assert_eq!(
        check(&s, &approval(&s, &bytes, &s.root)),
        Err(EmailGuardianError::WrongController)
    );
}

#[test]
fn refuses_a_disallowed_action() {
    let s = deploy(parts(), ALLOW_LOST_KEY | ALLOW_CANCEL, None);
    for (action, ok) in [(1, true), (2, false), (3, true), (4, false), (5, false)] {
        let r = check(&s, &approval(&s, &statement(&s, action), &s.root));
        if ok {
            assert_eq!(r, Ok(()), "action {action}");
        } else {
            assert_eq!(
                r,
                Err(EmailGuardianError::ActionNotAllowed),
                "action {action}"
            );
        }
    }
}

#[test]
fn refuses_an_action_through_the_other_entry_point() {
    let s = setup();
    for (action, wrong) in [
        (1u8, "approve_change"),
        (3, "approve_change"),
        (4, "submit_guardian"),
    ] {
        let st = statement(&s, action);
        let ctx = context(&s, &s.controller, wrong, &digest(&s.e, &st));
        assert_eq!(
            check_with(&s, &approval(&s, &st, &s.root), &ctx),
            Err(EmailGuardianError::WrongEntryPoint)
        );
    }
}

#[test]
fn refuses_an_expired_statement() {
    let s = setup();
    let st = statement(&s, 1); // valid until START + 100
    let a = approval(&s, &st, &s.root);
    s.e.ledger().set_sequence_number(START + 100);
    assert_eq!(check(&s, &a), Ok(()), "valid through valid_until_ledger");
    s.e.ledger().set_sequence_number(START + 101);
    assert_eq!(check(&s, &a), Err(EmailGuardianError::StatementExpired));
}

#[test]
fn refuses_a_non_canonical_root() {
    let s = setup();
    let root = BytesN::from_array(&s.e, &BN254_SCALAR_MODULUS);
    assert_eq!(
        check(&s, &approval(&s, &statement(&s, 1), &root)),
        Err(EmailGuardianError::NonCanonicalRoot)
    );
}

#[test]
fn refuses_a_root_the_registry_does_not_accept() {
    let s = setup();
    let unknown = fe(&s.e, 0x43);
    assert_eq!(
        check(&s, &approval(&s, &statement(&s, 1), &unknown)),
        Err(EmailGuardianError::UnknownRoot)
    );
    // A root the registry stops accepting (superseded past its grace, or
    // revoked) is refused from then on.
    let a = approval(&s, &statement(&s, 1), &s.root);
    assert_eq!(check(&s, &a), Ok(()));
    TestOnlyRegistryClient::new(&s.e, &s.registry).set_accepted(&s.root, &false);
    assert_eq!(check(&s, &a), Err(EmailGuardianError::UnknownRoot));
}

#[test]
fn reports_an_unavailable_registry() {
    let s = setup();
    TestOnlyRegistryClient::new(&s.e, &s.registry).set_broken(&true);
    assert_eq!(
        check(&s, &approval(&s, &statement(&s, 1), &s.root)),
        Err(EmailGuardianError::RegistryUnavailable)
    );
}

#[test]
fn accepts_the_pin_root_without_the_registry_until_it_expires() {
    let p = parts();
    let pin_root = fe(&p.e, 0x50);
    let pin = KeyPin {
        root: pin_root.clone(),
        valid_until: START_TS + 1_000,
    };
    let s = deploy(p, ALLOW_ALL, Some(pin));
    // The registry is down and has never heard of the pin root.
    TestOnlyRegistryClient::new(&s.e, &s.registry).set_broken(&true);
    let mut st = statement_for(&s, &s.account, 1, START + 1_000);
    let bytes = st.clone().encode(&s.e).unwrap();
    let a = approval(&s, &bytes, &pin_root);
    // The pin's expiry is close time: the ledger count in between does not
    // matter (the statement's own expiry stays Perch's ledger number).
    s.e.ledger().set_sequence_number(START + 1);
    s.e.ledger().set_timestamp(START_TS + 1_000);
    assert_eq!(check(&s, &a), Ok(()), "valid through valid_until");

    // Past the pin's expiry the root must come from the registry.
    s.e.ledger().set_timestamp(START_TS + 1_001);
    assert_eq!(check(&s, &a), Err(EmailGuardianError::RegistryUnavailable));
    TestOnlyRegistryClient::new(&s.e, &s.registry).set_broken(&false);
    assert_eq!(check(&s, &a), Err(EmailGuardianError::UnknownRoot));

    // Registry roots stay usable alongside the pin.
    st.timing.valid_until_ledger = START + 1_000;
    let b = approval(&s, &st.encode(&s.e).unwrap(), &s.root);
    assert_eq!(check(&s, &b), Ok(()));
}

#[test]
fn refuses_a_proof_against_another_pin() {
    let p = parts();
    let pin = KeyPin {
        root: fe(&p.e, 0x50),
        valid_until: START_TS + 1_000,
    };
    let s = deploy(p, ALLOW_ALL, Some(pin));
    // A proof made against some other key tree (another account's pin, or a
    // tree with a key of the prover's choosing).
    let foreign_pin = fe(&s.e, 0x51);
    assert_eq!(
        check(&s, &approval(&s, &statement(&s, 1), &foreign_pin)),
        Err(EmailGuardianError::UnknownRoot)
    );
}

#[test]
fn builds_public_inputs_from_its_own_values_only() {
    let s = setup();
    let st = statement(&s, 1);
    let d = digest(&s.e, &st);
    // Proofs valid for public inputs other than this guardian's: another
    // commitment (the prover's own address), another digest, another root.
    for inputs in [
        spec_public_inputs(&s.e, &fe(&s.e, 0xc1), &d, &s.root),
        spec_public_inputs(
            &s.e,
            &s.commitment,
            &digest(&s.e, &statement(&s, 2)),
            &s.root,
        ),
        spec_public_inputs(&s.e, &s.commitment, &d, &fe(&s.e, 0x43)),
    ] {
        let a = EmailApproval {
            statement: st.clone(),
            key_root: s.root.clone(),
            proof: test_proof(&s.e, &inputs),
        };
        assert_eq!(check(&s, &a), Err(EmailGuardianError::ProofRejected));
    }
    // And the one it builds is exactly the spec's layout.
    assert_eq!(check(&s, &approval(&s, &st, &s.root)), Ok(()));
}

#[test]
fn refuses_a_tampered_proof() {
    let s = setup();
    let mut a = approval(&s, &statement(&s, 1), &s.root);
    a.proof.set(0, a.proof.get(0).unwrap() ^ 1);
    assert_eq!(check(&s, &a), Err(EmailGuardianError::ProofRejected));
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn construction_refuses_a_non_contract_account() {
    let mut p = parts();
    p.account = Address::from_str(
        &p.e,
        "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ",
    );
    let _ = deploy(p, ALLOW_ALL, None);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn construction_refuses_the_account_as_its_own_controller() {
    let mut p = parts();
    p.controller = p.account.clone();
    let _ = deploy(p, ALLOW_ALL, None);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn construction_refuses_a_zero_commitment() {
    let mut p = parts();
    p.commitment = BytesN::from_array(&p.e, &[0u8; 32]);
    let _ = deploy(p, ALLOW_ALL, None);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn construction_refuses_a_non_canonical_commitment() {
    let mut p = parts();
    p.commitment = BytesN::from_array(&p.e, &BN254_SCALAR_MODULUS);
    let _ = deploy(p, ALLOW_ALL, None);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn construction_refuses_a_pin_longer_than_the_maximum_lifetime() {
    let p = parts();
    let pin = KeyPin {
        root: fe(&p.e, 0x50),
        valid_until: START_TS + MAX_PIN_LIFETIME_SECONDS + 1,
    };
    let _ = deploy(p, ALLOW_ALL, Some(pin));
}

#[test]
fn construction_accepts_a_pin_of_exactly_the_maximum_lifetime() {
    let p = parts();
    let pin = KeyPin {
        root: fe(&p.e, 0x50),
        valid_until: START_TS + MAX_PIN_LIFETIME_SECONDS,
    };
    let _ = deploy(p, ALLOW_ALL, Some(pin));
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn construction_refuses_an_expired_pin() {
    let p = parts();
    let pin = KeyPin {
        root: fe(&p.e, 0x50),
        valid_until: START_TS - 1,
    };
    let _ = deploy(p, ALLOW_ALL, Some(pin));
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn construction_refuses_an_empty_action_set() {
    let _ = deploy(parts(), 0, None);
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn construction_refuses_an_unknown_action_bit() {
    let _ = deploy(parts(), ALLOW_ALL | (1 << 5), None);
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn construction_refuses_a_verifier_for_another_circuit() {
    let p = parts();
    let mut config = config(&p, ALLOW_ALL, None);
    config.circuit_id = fe(&p.e, 0x01);
    let _ = p.e.register(EmailGuardian, (config,));
}

// ---------------------------------------------------------------------------
// Spec constants
// ---------------------------------------------------------------------------

/// `x - r` when `x >= r`, else `x` (big-endian, 32 bytes).
fn reduce_once(x: &mut [u8; 32]) -> bool {
    if x[..] < BN254_SCALAR_MODULUS[..] {
        return false;
    }
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(x[i]) - i16::from(BN254_SCALAR_MODULUS[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        x[i] = u8::try_from(d).unwrap();
    }
    true
}

/// The domain tags in `docs/email-recovery/spec.md`: `BE(sha256(label)) mod
/// r`, the rule Perch's own tags follow.
#[test]
fn spec_domain_tags_follow_the_label_rule() {
    let e = Env::default();
    let table = [
        (
            "nido/email-recovery/v1/commit",
            "28c44578265e026b7cecaa4b01b79fef9a1d1e4340e270596de3a724f044ee56",
        ),
        (
            "nido/email-recovery/v1/blind",
            "2e13b680b3b2cbdab71f094fdf34f9ccd940c01ac6158ebc826ee5bdb05d0726",
        ),
        (
            "nido/email-recovery/v1/enroll",
            "2bfe80f315441c3aadf9e7de0ab78fae545af772c0671cf5a512eb1ae713c9e7",
        ),
        (
            "nido/email-recovery/v1/key",
            "1f6d4c7ed15d3b9480457cf9ff55d0ffff201158605d66399703659bf4d765f5",
        ),
        (
            "nido/email-recovery/v1/leaf",
            "1ddd7b4c7e2eba95d7da44139642c575589aa685188088b0555d3d4fbb5b1f7e",
        ),
        (
            "nido/email-recovery/v1/pin-salt",
            "03d73ecb3a706d8271405c0c77fb8020c22717b7db10c5eb91f480ea1456bff6",
        ),
        // Perch's DOM_AUTH, as a check of the rule itself.
        (
            "perch/recovery/zk/v2/auth",
            "04e4c99c7477379c7e47c9380170e3fb1e7c565afe67dd56216df99861f1fb3c",
        ),
    ];
    for (label, want) in table {
        let mut x = e
            .crypto()
            .sha256(&Bytes::from_slice(&e, label.as_bytes()))
            .to_array();
        while reduce_once(&mut x) {}
        let mut want_bytes = [0u8; 32];
        for (i, byte) in want_bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&want[2 * i..2 * i + 2], 16).unwrap();
        }
        assert_eq!(x, want_bytes, "{label}");
    }
}
