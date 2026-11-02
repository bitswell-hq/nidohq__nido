//! Unit tests: every rule of `docs/email-recovery/spec.md` §7.3 and §7.5 as
//! this contract implements it, with a 3-of-5 multisig (revocation 2-of-5),
//! a 2-of-3 attester set, and a 24-hour grace period. Attester keys are
//! TEST ONLY (fixed seeds). Moduli are synthetic 2048-bit values except in
//! `noir_vectors`, which uses the fixture keys the Noir vectors use.

// Short names for the fixture (`t`), modulus (`n`), and attestation parts
// (`k`, `a`, `s`) keep the rule tests readable.
#![allow(clippy::many_single_char_names)]

extern crate std;

use crate::attestation::{self, Attestation, MAX_LEN};
use crate::hash::{Hasher, MODULUS_BYTES};
use crate::{
    root_of, DkimRegistry, DkimRegistryClient, DkimRegistryError as Error, DnsAttested,
    KeyActivated, KeyProposed, KeyRetired, KeyRevoked, ProposalApproved, ProposalKind,
    RegistryConfig, MAX_LIVE_ROOTS, PROPOSAL_LIFETIME_SECONDS, REGISTRY_DEPTH,
    TIMELOCK_ATTESTED_SECONDS, TIMELOCK_SECONDS,
};
use ed25519_dalek::{Signer, SigningKey};
use perch_zk_primitives::contract_id;
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{Address, Bytes, BytesN, Env, Event, IntoVal, Vec};
use std::vec::Vec as StdVec;

const START: u32 = 1_000;
const START_TS: u64 = 1_793_500_000;
const GRACE: u64 = 86_400;

struct T {
    e: Env,
    id: Address,
    c: DkimRegistryClient<'static>,
    members: StdVec<Address>,
    outsider: Address,
    attesters: StdVec<SigningKey>,
}

fn attester_key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i + 1; 32])
}

fn bytes(e: &Env, s: &str) -> Bytes {
    Bytes::from_slice(e, s.as_bytes())
}

fn base_config(e: &Env, members: &[Address], attesters: &[SigningKey]) -> RegistryConfig {
    let mut m = Vec::new(e);
    for a in members {
        m.push_back(a.clone());
    }
    let mut at = Vec::new(e);
    for k in attesters {
        at.push_back(BytesN::from_array(e, &k.verifying_key().to_bytes()));
    }
    let mut domains = Vec::new(e);
    for d in ["gmail.com", "outlook.com", "fastmail.com", "yahoo.com"] {
        domains.push_back(bytes(e, d));
    }
    RegistryConfig {
        members: m,
        threshold: 3,
        revoke_threshold: 2,
        attesters: at,
        attest_threshold: 2,
        grace_seconds: GRACE,
        domains,
    }
}

fn env() -> Env {
    ledger(Env::default())
}

/// For construction refusals: one environment per refused configuration,
/// with nothing worth a snapshot.
fn env_without_snapshot() -> Env {
    ledger(Env::new_with_config(
        soroban_sdk::testutils::EnvTestConfig {
            capture_snapshot_at_drop: false,
        },
    ))
}

fn ledger(e: Env) -> Env {
    e.ledger().with_mut(|l| {
        l.sequence_number = START;
        l.timestamp = START_TS;
        l.min_persistent_entry_ttl = 1_000_000;
        l.max_entry_ttl = 10_000_000;
    });
    e
}

fn setup_with(f: impl FnOnce(&mut RegistryConfig)) -> T {
    let e = env();
    e.mock_all_auths();
    let members: StdVec<Address> = (0..5).map(|_| Address::generate(&e)).collect();
    let attesters: StdVec<SigningKey> = (0..3).map(attester_key).collect();
    let mut config = base_config(&e, &members, &attesters);
    f(&mut config);
    let id = e.register(DkimRegistry, (config,));
    let c = DkimRegistryClient::new(&e, &id);
    let outsider = Address::generate(&e);
    T {
        e,
        id,
        c,
        members,
        outsider,
        attesters,
    }
}

fn setup() -> T {
    setup_with(|_| {})
}

/// A synthetic 2048-bit modulus: 256 bytes, top bit set.
fn modulus(e: &Env, seed: u8) -> Bytes {
    let mut n = [seed; MODULUS_BYTES];
    n[0] = 0x80 | seed;
    n[255] |= 1;
    Bytes::from_array(e, &n)
}

fn key_hash_of(e: &Env, n: &Bytes) -> BytesN<32> {
    let mut buf = [0u8; MODULUS_BYTES];
    n.copy_into_slice(&mut buf);
    Hasher::new(e).key_hash(&buf)
}

fn leaf_of(e: &Env, domain: &str, key_hash: &BytesN<32>) -> BytesN<32> {
    Hasher::new(e).leaf(domain.as_bytes(), key_hash)
}

impl T {
    /// Move the close time forward by `seconds`, in a single ledger: every
    /// window the registry keeps is measured on the close time, so the
    /// number of ledgers in between is irrelevant to it.
    fn advance(&self, seconds: u64) {
        self.e.ledger().with_mut(|l| {
            l.sequence_number += 1;
            l.timestamp += seconds;
        });
    }

    fn now(&self) -> u64 {
        self.e.ledger().timestamp()
    }

    fn registry_id(&self) -> [u8; 32] {
        contract_id(&self.e, &self.id).unwrap().to_array()
    }

    /// Signed attestation bytes from attester `i` about `(domain, key_hash)`.
    #[allow(clippy::too_many_arguments)]
    fn signed(
        &self,
        i: usize,
        registry: [u8; 32],
        domain: &str,
        key_hash: &BytesN<32>,
        live: bool,
        observed_at: u64,
    ) -> (BytesN<32>, Bytes, BytesN<64>) {
        let a = Attestation::new(
            registry,
            domain.as_bytes(),
            b"test",
            key_hash.to_array(),
            live,
            observed_at,
            &[b"8.8.8.8", b"1.1.1.1"],
        )
        .unwrap();
        let mut buf = [0u8; MAX_LEN];
        let len = attestation::encode(&a, &mut buf).unwrap();
        self.sign_raw(i, &buf[..len])
    }

    fn sign_raw(&self, i: usize, msg: &[u8]) -> (BytesN<32>, Bytes, BytesN<64>) {
        let key = &self.attesters[i];
        (
            BytesN::from_array(&self.e, &key.verifying_key().to_bytes()),
            Bytes::from_slice(&self.e, msg),
            BytesN::from_array(&self.e, &key.sign(msg).to_bytes()),
        )
    }

    fn try_attest(&self, id: u32, i: usize, live: bool) -> Result<(), Error> {
        let p = self.c.proposal(&id).unwrap();
        let mut d = [0u8; 62];
        let len = p.domain.len() as usize;
        p.domain.copy_into_slice(&mut d[..len]);
        let domain = core::str::from_utf8(&d[..len]).unwrap();
        let (k, a, s) = self.signed(
            i,
            self.registry_id(),
            domain,
            &p.key_hash,
            live,
            self.e.ledger().timestamp(),
        );
        self.c
            .try_attest(&id, &k, &a, &s)
            .map(|r| r.unwrap())
            .map_err(|e| e.unwrap())
    }

    fn attest(&self, id: u32, i: usize, live: bool) {
        self.try_attest(id, i, live).unwrap();
    }

    /// An addition proposed by member 0 and approved by members 1 and 2.
    fn approved_add(&self, domain: &str, n: &Bytes) -> u32 {
        let id = self
            .c
            .propose_add(&self.members[0], &bytes(&self.e, domain), n);
        self.c.approve(&self.members[1], &id);
        self.c.approve(&self.members[2], &id);
        id
    }

    /// An addition through the attested path, executed once its 72 hours
    /// have passed. Returns `(proposal id, key hash, new root)`.
    fn admit(&self, domain: &str, seed: u8) -> (u32, BytesN<32>, BytesN<32>) {
        let n = modulus(&self.e, seed);
        let id = self.approved_add(domain, &n);
        self.attest(id, 0, true);
        self.attest(id, 1, true);
        self.advance(TIMELOCK_ATTESTED_SECONDS);
        let root = self.c.execute(&id);
        (id, key_hash_of(&self.e, &n), root)
    }

    fn retire(&self, domain: &str, key_hash: &BytesN<32>) -> BytesN<32> {
        let id = self
            .c
            .propose_retire(&self.members[0], &bytes(&self.e, domain), key_hash);
        self.c.approve(&self.members[1], &id);
        self.c.approve(&self.members[2], &id);
        self.attest(id, 0, false);
        self.attest(id, 2, false);
        self.c.execute(&id)
    }

    /// A revocation by members 3 and 4 (the emergency threshold).
    fn revoke(&self, domain: &str, key_hash: &BytesN<32>) -> u32 {
        let id = self
            .c
            .propose_revoke(&self.members[3], &bytes(&self.e, domain), key_hash);
        self.c.approve(&self.members[4], &id);
        id
    }

    fn accepted(&self, root: &BytesN<32>) -> bool {
        self.c.is_accepted_root(root)
    }

    fn published(&self) -> StdVec<soroban_sdk::xdr::ContractEvent> {
        self.e
            .events()
            .all()
            .filter_by_contract(&self.id)
            .events()
            .to_vec()
    }
}

// --- construction --------------------------------------------------------------

fn construct(f: impl FnOnce(&Env, &mut RegistryConfig)) -> Result<(), Error> {
    let e = env_without_snapshot();
    let members: StdVec<Address> = (0..5).map(|_| Address::generate(&e)).collect();
    let attesters: StdVec<SigningKey> = (0..3).map(attester_key).collect();
    let mut config = base_config(&e, &members, &attesters);
    f(&e, &mut config);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.register(DkimRegistry, (config,));
    }));
    let Err(panic) = outcome else {
        return Ok(());
    };
    // The constructor refuses with `panic_with_error!`; the host reports it
    // as "Error(Contract, #code)".
    let message = panic
        .downcast_ref::<std::string::String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).into()))
        .unwrap_or_default();
    let at = message.find("Error(Contract, #").expect("a contract error") + 17;
    let code: u32 = message[at..].split(')').next().unwrap().parse().unwrap();
    Err(Error::try_from(soroban_sdk::Error::from_contract_error(code)).unwrap())
}

#[test]
fn construction_accepts_the_proposed_defaults() {
    assert_eq!(construct(|_, _| {}), Ok(()));
}

#[test]
fn construction_refuses_bad_member_sets_and_thresholds() {
    assert_eq!(
        construct(|e, c| c.members = Vec::new(e)),
        Err(Error::InvalidMembers)
    );
    assert_eq!(
        construct(|_, c| c.members.push_back(c.members.get_unchecked(0))),
        Err(Error::InvalidMembers)
    );
    assert_eq!(
        construct(|e, c| {
            for _ in 0..16 {
                c.members.push_back(Address::generate(e));
            }
        }),
        Err(Error::InvalidMembers)
    );
    assert_eq!(
        construct(|_, c| c.threshold = 6),
        Err(Error::InvalidThreshold)
    );
    assert_eq!(
        construct(|_, c| c.revoke_threshold = 0),
        Err(Error::InvalidThreshold)
    );
    assert_eq!(
        construct(|_, c| c.revoke_threshold = 4),
        Err(Error::InvalidThreshold),
        "revocation may not need more than an addition"
    );
}

#[test]
fn construction_refuses_bad_attester_sets_grace_and_domains() {
    assert_eq!(
        construct(|e, c| c.attesters = Vec::new(e)),
        Err(Error::InvalidAttesters)
    );
    assert_eq!(
        construct(|_, c| c.attesters.push_back(c.attesters.get_unchecked(1))),
        Err(Error::InvalidAttesters)
    );
    assert_eq!(
        construct(|_, c| c.attest_threshold = 0),
        Err(Error::InvalidAttestThreshold)
    );
    assert_eq!(
        construct(|_, c| c.attest_threshold = 4),
        Err(Error::InvalidAttestThreshold)
    );
    assert_eq!(
        construct(|_, c| c.grace_seconds = 604_801),
        Err(Error::InvalidGrace)
    );
    assert_eq!(construct(|_, c| c.grace_seconds = 604_800), Ok(()));
    for bad in [
        "Gmail.com",
        "localhost",
        "-gmail.com",
        "gmail-.com",
        "gmail..com",
        "gmail.com.",
        "user@gmail.com",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
    ] {
        assert_eq!(
            construct(|e, c| c.domains.push_back(bytes(e, bad))),
            Err(Error::InvalidDomains),
            "{bad}"
        );
    }
    assert_eq!(
        construct(|e, c| c.domains.push_back(bytes(e, "gmail.com"))),
        Err(Error::InvalidDomains),
        "duplicate"
    );
    assert_eq!(
        construct(|e, c| c.domains = Vec::new(e)),
        Err(Error::InvalidDomains)
    );
}

// --- key admission ---------------------------------------------------------------

#[test]
fn only_members_propose_and_approve() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let gmail = bytes(&t.e, "gmail.com");
    assert_eq!(
        t.c.try_propose_add(&t.outsider, &gmail, &n),
        Err(Ok(Error::NotAMember))
    );
    let id = t.c.propose_add(&t.members[0], &gmail, &n);
    assert_eq!(
        t.c.try_approve(&t.outsider, &id),
        Err(Ok(Error::NotAMember))
    );
    let kh = key_hash_of(&t.e, &n);
    assert_eq!(
        t.c.try_propose_retire(&t.outsider, &gmail, &kh),
        Err(Ok(Error::NotAMember))
    );
    assert_eq!(
        t.c.try_propose_revoke(&t.outsider, &gmail, &kh),
        Err(Ok(Error::NotAMember))
    );
}

#[test]
fn members_must_authorize_their_own_calls() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let gmail = bytes(&t.e, "gmail.com");
    t.e.set_auths(&[]);
    assert!(
        t.c.try_propose_add(&t.members[0], &gmail, &n).is_err(),
        "no authorization"
    );
    t.e.mock_auths(&[MockAuth {
        address: &t.members[0],
        invoke: &MockAuthInvoke {
            contract: &t.id,
            fn_name: "propose_add",
            args: (t.members[0].clone(), gmail.clone(), n.clone()).into_val(&t.e),
            sub_invokes: &[],
        },
    }]);
    let id = t.c.propose_add(&t.members[0], &gmail, &n);
    t.e.set_auths(&[]);
    assert!(
        t.c.try_approve(&t.members[1], &id).is_err(),
        "member 1 did not sign"
    );
}

#[test]
fn additions_only_for_allowlisted_domains() {
    let t = setup();
    let n = modulus(&t.e, 1);
    for d in [
        "proton.me",
        "example.com",
        "GMAIL.COM",
        "gmail.com.evil.com",
    ] {
        assert_eq!(
            t.c.try_propose_add(&t.members[0], &bytes(&t.e, d), &n),
            Err(Ok(Error::DomainNotAllowed)),
            "{d}"
        );
    }
    let kh = key_hash_of(&t.e, &n);
    assert_eq!(
        t.c.try_propose_revoke(&t.members[0], &bytes(&t.e, "proton.me"), &kh),
        Err(Ok(Error::DomainNotAllowed))
    );
}

#[test]
fn additions_only_for_rsa_2048_moduli() {
    let t = setup();
    let gmail = bytes(&t.e, "gmail.com");
    let mut top_clear = [0x7fu8; 256];
    top_clear[255] = 1;
    let mut leading_zero = [0x80u8; 257];
    leading_zero[0] = 0;
    for n in [
        Bytes::from_array(&t.e, &[0x80u8; 128]), // RSA-1024
        Bytes::from_array(&t.e, &[0x80u8; 512]), // RSA-4096
        Bytes::from_array(&t.e, &top_clear),     // 2047 bits
        Bytes::from_array(&t.e, &leading_zero),  // a DER-style sign byte
        Bytes::new(&t.e),
    ] {
        assert_eq!(
            t.c.try_propose_add(&t.members[0], &gmail, &n),
            Err(Ok(Error::KeyNotRsa2048)),
            "{} bytes",
            n.len()
        );
        assert_eq!(t.c.try_key_hash(&n), Err(Ok(Error::KeyNotRsa2048)));
    }
}

/// The registry derives the key hash from the modulus itself: a proposal
/// cannot name a hash, the stored leaf is the one §7.2 defines for that
/// modulus, and attestations for any other hash are refused.
#[test]
fn the_key_hash_is_computed_never_supplied() {
    let t = setup();
    let n = modulus(&t.e, 7);
    let id = t.approved_add("gmail.com", &n);
    let kh = key_hash_of(&t.e, &n);
    assert_eq!(t.c.proposal(&id).unwrap().key_hash, kh);
    assert_eq!(t.c.key_hash(&n), kh);

    // An attester vouching for a different hash does not count for it.
    let other = key_hash_of(&t.e, &modulus(&t.e, 8));
    let (k, a, s) = t.signed(0, t.registry_id(), "gmail.com", &other, true, START_TS);
    assert_eq!(
        t.c.try_attest(&id, &k, &a, &s),
        Err(Ok(Error::AttestationMismatch))
    );
    // Nor does an attestation for the right hash under another domain.
    let (k, a, s) = t.signed(0, t.registry_id(), "yahoo.com", &kh, true, START_TS);
    assert_eq!(
        t.c.try_attest(&id, &k, &a, &s),
        Err(Ok(Error::AttestationMismatch))
    );

    t.advance(TIMELOCK_SECONDS);
    let root = t.c.execute(&id);
    let leaf = leaf_of(&t.e, "gmail.com", &kh);
    assert_eq!(t.c.siblings(&1).get_unchecked(0), leaf);
    assert_eq!(root, root_of(&t.e, &[leaf]));
    // A retirement or revocation naming a hash the tree does not hold
    // changes nothing.
    assert_eq!(
        t.c.try_propose_retire(&t.members[0], &bytes(&t.e, "gmail.com"), &other),
        Err(Ok(Error::KeyNotPresent))
    );
}

#[test]
fn a_key_is_admitted_once() {
    let t = setup();
    let (_, kh, _) = t.admit("gmail.com", 1);
    assert_eq!(
        t.c.try_propose_add(&t.members[0], &bytes(&t.e, "gmail.com"), &modulus(&t.e, 1)),
        Err(Ok(Error::KeyAlreadyPresent))
    );
    // The same key under another allowlisted domain is another leaf.
    let id = t.approved_add("outlook.com", &modulus(&t.e, 1));
    assert_eq!(t.c.proposal(&id).unwrap().key_hash, kh);
}

// --- multisig --------------------------------------------------------------------

#[test]
fn an_addition_needs_k_of_n_approvals() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let id =
        t.c.propose_add(&t.members[0], &bytes(&t.e, "gmail.com"), &n);
    assert_eq!(
        t.c.try_approve(&t.members[0], &id),
        Err(Ok(Error::AlreadyApproved))
    );
    t.c.approve(&t.members[1], &id);
    assert_eq!(t.c.proposal(&id).unwrap().approved_at, None);
    t.advance(TIMELOCK_SECONDS);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::NotApproved)), "2 of 5");
    assert_eq!(t.c.eligible_at(&id), None);

    t.c.approve(&t.members[4], &id);
    let p = t.c.proposal(&id).unwrap();
    assert_eq!(p.approvals, 0b10011);
    assert_eq!(p.approved_at, Some(t.now()));
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::TimelockActive)));
    // Further approvals are recorded but change nothing.
    t.c.approve(&t.members[2], &id);
    assert_eq!(t.c.proposal(&id).unwrap().approved_at, p.approved_at);
}

#[test]
fn a_revocation_needs_only_the_emergency_threshold() {
    let t = setup();
    let (_, kh, root) = t.admit("gmail.com", 1);
    let id =
        t.c.propose_revoke(&t.members[3], &bytes(&t.e, "gmail.com"), &kh);
    assert!(t.accepted(&root), "one approval does not revoke");
    t.c.approve(&t.members[4], &id);
    assert!(!t.accepted(&root));
    assert!(t.c.proposal(&id).unwrap().executed);
    assert_eq!(
        t.c.try_approve(&t.members[0], &id),
        Err(Ok(Error::ProposalClosed))
    );
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::ProposalClosed)));
}

#[test]
fn proposals_lapse_after_their_lifetime() {
    let t = setup();
    let id =
        t.c.propose_add(&t.members[0], &bytes(&t.e, "gmail.com"), &modulus(&t.e, 1));
    t.advance(PROPOSAL_LIFETIME_SECONDS);
    t.c.approve(&t.members[1], &id);
    t.advance(1);
    assert_eq!(
        t.c.try_approve(&t.members[2], &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::ProposalExpired)));
    assert_eq!(t.try_attest(id, 0, true), Err(Error::ProposalExpired));
    assert_eq!(t.c.try_execute(&999), Err(Ok(Error::UnknownProposal)));
}

// --- timelocks -------------------------------------------------------------------

#[test]
fn an_attested_addition_activates_after_exactly_72_hours() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let id = t.approved_add("gmail.com", &n);
    t.attest(id, 0, true);
    assert_eq!(t.c.proposal(&id).unwrap().attested_at, None, "1 of 3");
    t.attest(id, 2, true);
    let from = t.now();
    assert_eq!(t.c.proposal(&id).unwrap().attested_at, Some(from));
    assert_eq!(t.c.eligible_at(&id), Some(from + TIMELOCK_ATTESTED_SECONDS));

    t.advance(TIMELOCK_ATTESTED_SECONDS - 1);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::TimelockActive)));
    t.advance(1);
    let root = t.c.execute(&id);
    let event = KeyActivated {
        domain: bytes(&t.e, "gmail.com"),
        id,
        key_hash: key_hash_of(&t.e, &n),
        index: 0,
        root: root.clone(),
        previous_root: crate::empty_root(&t.e),
        attested: true,
    };
    assert!(t.published().contains(&event.to_xdr(&t.e, &t.id)));
    assert!(t.accepted(&root));
}

#[test]
fn the_72_hours_run_from_the_later_of_approval_and_attestation() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let id =
        t.c.propose_add(&t.members[0], &bytes(&t.e, "gmail.com"), &n);
    // Attested first, approved a day later: the clock starts at approval.
    t.attest(id, 0, true);
    t.attest(id, 1, true);
    t.advance(86_400);
    t.c.approve(&t.members[1], &id);
    t.c.approve(&t.members[2], &id);
    let approved = t.now();
    assert_eq!(
        t.c.eligible_at(&id),
        Some(approved + TIMELOCK_ATTESTED_SECONDS)
    );

    // Approved first, attested two days later: the clock starts at the
    // attestation that reached the threshold.
    let id = t.approved_add("outlook.com", &modulus(&t.e, 2));
    t.advance(172_800);
    t.attest(id, 0, true);
    t.attest(id, 1, true);
    assert_eq!(
        t.c.eligible_at(&id),
        Some(t.now() + TIMELOCK_ATTESTED_SECONDS)
    );

    // Attested so late that the 7-day path comes first.
    let id = t.approved_add("fastmail.com", &modulus(&t.e, 3));
    let approved = t.now();
    t.advance(500_000);
    t.attest(id, 0, true);
    t.attest(id, 1, true);
    assert_eq!(t.c.eligible_at(&id), Some(approved + TIMELOCK_SECONDS));
}

#[test]
fn any_other_addition_activates_after_exactly_7_days() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let id = t.approved_add("gmail.com", &n);
    // One live observation and one of a blank record: below the threshold
    // of live observations.
    t.attest(id, 0, true);
    t.attest(id, 1, false);
    let approved = t.c.proposal(&id).unwrap().approved_at.unwrap();
    assert_eq!(t.c.eligible_at(&id), Some(approved + TIMELOCK_SECONDS));

    t.advance(TIMELOCK_SECONDS - 1);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::TimelockActive)));
    t.advance(1);
    let root = t.c.execute(&id);
    let event = KeyActivated {
        domain: bytes(&t.e, "gmail.com"),
        id,
        key_hash: key_hash_of(&t.e, &n),
        index: 0,
        root: root.clone(),
        previous_root: crate::empty_root(&t.e),
        attested: false,
    };
    assert!(t.published().contains(&event.to_xdr(&t.e, &t.id)));
    assert!(t.accepted(&root));
}

#[test]
fn timelocks_and_grace_follow_close_time_not_ledger_count() {
    let t = setup();
    let ledgers = |n: u32, seconds: u64| {
        t.e.ledger().with_mut(|l| {
            l.sequence_number += n;
            l.timestamp += seconds;
        });
    };
    // Ledgers closing at a quarter of a second: four times the ledgers of
    // 72 hours at 5-second ledgers, one second short of 72 hours.
    let n = modulus(&t.e, 1);
    let id = t.approved_add("gmail.com", &n);
    t.attest(id, 0, true);
    t.attest(id, 1, true);
    ledgers(4 * 51_840, TIMELOCK_ATTESTED_SECONDS - 1);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::TimelockActive)));
    ledgers(1, 1);
    let first = t.c.execute(&id);

    // The same holds for the 7-day path.
    let id = t.approved_add("outlook.com", &modulus(&t.e, 2));
    ledgers(4 * 120_960, TIMELOCK_SECONDS - 1);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::TimelockActive)));
    ledgers(1, 1);
    t.c.execute(&id);

    // A superseded root keeps its whole grace period in seconds.
    ledgers(4 * 17_280, GRACE);
    assert!(t.accepted(&first), "at superseded + grace");
    ledgers(1, 1);
    assert!(!t.accepted(&first));
}

// --- acceptance and grace --------------------------------------------------------

#[test]
fn the_empty_tree_and_unknown_roots_are_never_accepted() {
    let t = setup();
    assert!(!t.accepted(&crate::empty_root(&t.e)));
    assert!(!t.accepted(&t.c.root()));
    let (_, kh, _) = t.admit("gmail.com", 1);
    assert!(!t.accepted(&leaf_of(&t.e, "gmail.com", &kh)));
    assert!(!t.accepted(&BytesN::from_array(&t.e, &[0u8; 32])));
}

#[test]
fn a_superseded_root_is_accepted_through_its_grace_period() {
    let t = setup();
    let (_, _, first) = t.admit("gmail.com", 1);
    let (_, _, second) = t.admit("outlook.com", 2);
    let superseded = t.now();
    assert!(t.accepted(&first) && t.accepted(&second));
    t.advance(GRACE);
    assert!(t.accepted(&first), "at superseded + grace");
    t.advance(1);
    assert!(!t.accepted(&first), "one ledger later");
    assert!(t.accepted(&second), "the current root has no expiry");
    assert_eq!(
        t.c.state().live_roots.get_unchecked(0).superseded_at,
        Some(superseded)
    );
}

#[test]
fn at_most_max_live_roots_are_kept_and_the_oldest_loses_its_grace() {
    // A burst of additions approved and executed in the same ledger, so
    // every superseded root is still inside its grace period.
    let t = setup_with(|c| {
        c.threshold = 1;
        c.revoke_threshold = 1;
    });
    let mut ids = StdVec::new();
    for seed in 1..=u8::try_from(MAX_LIVE_ROOTS).unwrap() + 1 {
        let n = modulus(&t.e, seed);
        let id =
            t.c.propose_add(&t.members[0], &bytes(&t.e, "gmail.com"), &n);
        t.attest(id, 0, true);
        t.attest(id, 1, true);
        ids.push(id);
    }
    t.advance(TIMELOCK_ATTESTED_SECONDS);
    let mut roots = StdVec::new();
    for id in &ids {
        roots.push(t.c.execute(id));
    }
    assert_eq!(t.c.state().live_roots.len(), MAX_LIVE_ROOTS);
    assert!(!t.accepted(&roots[0]), "dropped early");
    for r in &roots[1..] {
        assert!(t.accepted(r));
    }
}

// --- retirement ------------------------------------------------------------------

#[test]
fn a_retired_key_leaves_the_tree_after_the_grace_period() {
    let t = setup();
    let (_, kh_a, _) = t.admit("gmail.com", 1);
    let (_, kh_b, with_both) = t.admit("outlook.com", 2);

    let id =
        t.c.propose_retire(&t.members[0], &bytes(&t.e, "gmail.com"), &kh_a);
    t.c.approve(&t.members[1], &id);
    t.c.approve(&t.members[2], &id);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::NotAttested)));
    t.attest(id, 0, false);
    // Live observations do not count toward a retirement.
    t.attest(id, 1, true);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::NotAttested)));
    t.attest(id, 2, false);
    let without_a = t.c.execute(&id);
    let gmail = bytes(&t.e, "gmail.com");
    let event = KeyRetired {
        domain: gmail.clone(),
        id,
        key_hash: kh_a.clone(),
        index: 0,
        root: without_a.clone(),
        previous_root: with_both.clone(),
        previous_accepted_until: t.now() + GRACE,
    };
    assert!(t.published().contains(&event.to_xdr(&t.e, &t.id)));

    let rec = t.c.leaf(&gmail, &kh_a).unwrap();
    assert!(!rec.present);
    assert_eq!(t.c.leaf_at(&0), None);
    assert_eq!(
        without_a,
        root_of(
            &t.e,
            &[
                BytesN::from_array(&t.e, &[0u8; 32]),
                leaf_of(&t.e, "outlook.com", &kh_b)
            ]
        )
    );

    assert!(t.accepted(&with_both) && t.accepted(&without_a));
    t.advance(GRACE);
    assert!(t.accepted(&with_both));
    t.advance(1);
    assert!(!t.accepted(&with_both), "the retired key's last root");
    assert!(t.accepted(&without_a));
    assert_eq!(
        t.c.try_propose_retire(&t.members[0], &gmail, &kh_a),
        Err(Ok(Error::KeyNotPresent))
    );
}

#[test]
fn a_retired_key_can_be_admitted_again() {
    let t = setup();
    let (_, kh, _) = t.admit("gmail.com", 1);
    t.retire("gmail.com", &kh);
    let (_, _, root) = t.admit("gmail.com", 1);
    assert!(t.accepted(&root));
    let rec = t.c.leaf(&bytes(&t.e, "gmail.com"), &kh).unwrap();
    assert_eq!(rec.index, 1, "indices are never reused");
    assert_eq!(rec.spans.len(), 2);
}

// --- revocation ------------------------------------------------------------------

#[test]
fn revocation_refuses_every_root_containing_the_key_at_once() {
    // Admissions here are 72 hours apart; keep every root in its grace.
    let t = setup_with(|c| c.grace_seconds = crate::MAX_GRACE_SECONDS);
    let (_, kh_a, only_a) = t.admit("gmail.com", 1);
    let (_, _, a_and_b) = t.admit("outlook.com", 2);
    // A third change that does not touch A, inside the grace of the others.
    let (_, kh_c, a_b_c) = t.admit("fastmail.com", 3);
    t.retire("fastmail.com", &kh_c);
    let a_b = t.c.root();
    assert_eq!(a_b, a_and_b, "retiring C restores the earlier tree");
    for r in [&only_a, &a_and_b, &a_b_c] {
        assert!(t.accepted(r));
    }

    let id = t.revoke("gmail.com", &kh_a);
    let published = t.published();
    for r in [&only_a, &a_and_b, &a_b_c] {
        assert!(!t.accepted(r), "grace does not survive revocation");
    }
    let now_root = t.c.root();
    assert!(t.accepted(&now_root));
    assert_ne!(now_root, a_b);
    let rec = t.c.leaf(&bytes(&t.e, "gmail.com"), &kh_a).unwrap();
    assert!(!rec.present);
    assert_eq!(rec.revoked_by, id);
    // Every occurrence of a root holding A, oldest first: the tree with A
    // alone, A and B, A, B and C, and A and B again after C's retirement.
    let mut refused = Vec::new(&t.e);
    for r in [&only_a, &a_and_b, &a_b_c, &a_and_b] {
        refused.push_back(r.clone());
    }
    let event = KeyRevoked {
        domain: bytes(&t.e, "gmail.com"),
        id,
        key_hash: kh_a,
        root: now_root,
        refused_roots: refused,
    };
    assert!(published.contains(&event.to_xdr(&t.e, &t.id)));
}

#[test]
fn revocation_leaves_roots_without_the_key_in_their_grace() {
    let t = setup();
    let (_, _, only_a) = t.admit("gmail.com", 1);
    let (_, kh_b, a_and_b) = t.admit("outlook.com", 2);
    t.revoke("outlook.com", &kh_b);
    assert!(!t.accepted(&a_and_b));
    assert!(t.accepted(&only_a), "never contained B; still in grace");
    assert_eq!(t.c.root(), only_a, "removing B restores the tree before it");
}

#[test]
fn revocation_reaches_roots_of_an_already_retired_key() {
    let t = setup();
    let (_, kh_a, with_a) = t.admit("gmail.com", 1);
    t.retire("gmail.com", &kh_a);
    assert!(t.accepted(&with_a), "in grace after retirement");
    t.revoke("gmail.com", &kh_a);
    assert!(!t.accepted(&with_a));
}

#[test]
fn revocation_stops_a_pending_addition() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let id = t.approved_add("gmail.com", &n);
    t.attest(id, 0, true);
    t.attest(id, 1, true);
    // Two members see a key nobody published and revoke it.
    t.revoke("gmail.com", &key_hash_of(&t.e, &n));
    t.advance(TIMELOCK_SECONDS);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::KeyRevoked)));
}

#[test]
fn a_revoked_key_returns_only_through_a_new_addition_on_the_7_day_path() {
    let t = setup();
    let (_, kh, _) = t.admit("gmail.com", 1);
    t.revoke("gmail.com", &kh);
    let id = t.approved_add("gmail.com", &modulus(&t.e, 1));
    t.attest(id, 0, true);
    t.attest(id, 1, true);
    let approved = t.now();
    assert_eq!(t.c.eligible_at(&id), Some(approved + TIMELOCK_SECONDS));
    t.advance(TIMELOCK_ATTESTED_SECONDS);
    assert_eq!(t.c.try_execute(&id), Err(Ok(Error::TimelockActive)));
    t.advance(TIMELOCK_SECONDS - TIMELOCK_ATTESTED_SECONDS);
    let root = t.c.execute(&id);
    assert!(t.accepted(&root));
}

// --- attestations ------------------------------------------------------------------

#[test]
fn attestation_refusals() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let id = t.approved_add("gmail.com", &n);
    let kh = key_hash_of(&t.e, &n);
    let me = t.registry_id();

    // Not an attester: a valid signature by an unknown key.
    let stranger = attester_key(9);
    let (_, a, _) = t.signed(0, me, "gmail.com", &kh, true, START_TS);
    let mut raw = [0u8; MAX_LEN];
    let len = a.len() as usize;
    a.copy_into_slice(&mut raw[..len]);
    let sig = BytesN::from_array(&t.e, &stranger.sign(&raw[..len]).to_bytes());
    let key = BytesN::from_array(&t.e, &stranger.verifying_key().to_bytes());
    assert_eq!(
        t.c.try_attest(&id, &key, &a, &sig),
        Err(Ok(Error::NotAnAttester))
    );

    // Another registry, a stale or future observation.
    let (k, a, s) = t.signed(0, [7u8; 32], "gmail.com", &kh, true, START_TS);
    assert_eq!(
        t.c.try_attest(&id, &k, &a, &s),
        Err(Ok(Error::WrongRegistry))
    );
    let (k, a, s) = t.signed(0, me, "gmail.com", &kh, true, START_TS - 86_401);
    assert_eq!(
        t.c.try_attest(&id, &k, &a, &s),
        Err(Ok(Error::StaleAttestation))
    );
    let (k, a, s) = t.signed(0, me, "gmail.com", &kh, true, START_TS - 86_400);
    assert_eq!(
        t.c.try_attest(&id, &k, &a, &s),
        Ok(Ok(())),
        "exactly 24 hours old"
    );
    let (k, a, s) = t.signed(1, me, "gmail.com", &kh, true, START_TS + 301);
    assert_eq!(
        t.c.try_attest(&id, &k, &a, &s),
        Err(Ok(Error::StaleAttestation))
    );

    // An observation no newer than the attester's recorded one, live or not.
    for live in [true, false] {
        let (k, a, s) = t.signed(0, me, "gmail.com", &kh, live, START_TS - 86_400);
        assert_eq!(
            t.c.try_attest(&id, &k, &a, &s),
            Err(Ok(Error::AlreadyAttested))
        );
    }

    // A bad signature traps in the host.
    let (k, a, _) = t.signed(1, me, "gmail.com", &kh, true, START_TS);
    let bad = BytesN::from_array(&t.e, &[0u8; 64]);
    assert!(t.c.try_attest(&id, &k, &a, &bad).is_err());
    // A signature over other bytes too.
    let (_, _, s_other) = t.signed(1, me, "gmail.com", &kh, false, START_TS);
    assert!(t.c.try_attest(&id, &k, &a, &s_other).is_err());

    // Revocations take none.
    let rid =
        t.c.propose_revoke(&t.members[3], &bytes(&t.e, "gmail.com"), &kh);
    assert_eq!(t.try_attest(rid, 1, true), Err(Error::NotAttestable));
}

/// Each attester's latest observation is the one that counts, and the
/// 72-hour clock runs only while the threshold of latest observations holds.
#[test]
fn an_attesters_latest_observation_counts() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let id = t.approved_add("gmail.com", &n);
    let kh = key_hash_of(&t.e, &n);
    let me = t.registry_id();
    let observe = |i: usize, live: bool, at: u64| {
        let (k, a, s) = t.signed(i, me, "gmail.com", &kh, live, at);
        t.c.try_attest(&id, &k, &a, &s)
    };

    // Attester 0 first finds no record (DNS not yet propagated) ...
    observe(0, false, START_TS - 600).unwrap().unwrap();
    observe(1, true, START_TS - 600).unwrap().unwrap();
    assert_eq!(t.c.proposal(&id).unwrap().attested_at, None);
    // ... and an older reading cannot displace a newer one.
    assert_eq!(
        observe(0, true, START_TS - 601),
        Err(Ok(Error::AlreadyAttested))
    );
    // Its later reading replaces the first: two live observations now.
    observe(0, true, START_TS - 300).unwrap().unwrap();
    let p = t.c.proposal(&id).unwrap();
    assert_eq!((p.live, p.blank), (0b011, 0));
    assert_eq!(p.attested_at, Some(t.now()));

    // The key disappears for attester 1: below the threshold, the clock stops.
    t.advance(500);
    observe(1, false, t.e.ledger().timestamp())
        .unwrap()
        .unwrap();
    assert_eq!(t.c.proposal(&id).unwrap().attested_at, None);
    let approved = t.c.proposal(&id).unwrap().approved_at.unwrap();
    assert_eq!(t.c.eligible_at(&id), Some(approved + TIMELOCK_SECONDS));

    // Seen again: the 72 hours restart from now.
    t.advance(500);
    observe(1, true, t.e.ledger().timestamp()).unwrap().unwrap();
    assert_eq!(t.c.proposal(&id).unwrap().attested_at, Some(t.now()));
    assert_eq!(
        t.c.eligible_at(&id),
        Some(t.now() + TIMELOCK_ATTESTED_SECONDS)
    );
}

/// An observation at Unix time 0 (a ledger whose close time is 0) is still
/// an attester's first observation.
#[test]
fn a_first_observation_at_time_zero_counts() {
    let t = setup();
    t.e.ledger().with_mut(|l| l.timestamp = 0);
    let n = modulus(&t.e, 1);
    let id = t.approved_add("gmail.com", &n);
    t.attest(id, 0, true);
    t.attest(id, 1, true);
    assert_eq!(t.c.proposal(&id).unwrap().live, 0b011);
    assert_eq!(t.try_attest(id, 0, true), Err(Error::AlreadyAttested));
}

#[test]
fn malformed_attestations_are_refused() {
    let t = setup();
    let n = modulus(&t.e, 1);
    let id = t.approved_add("gmail.com", &n);
    let kh = key_hash_of(&t.e, &n);
    let (_, good, _) = t.signed(0, t.registry_id(), "gmail.com", &kh, true, START_TS);
    let mut buf = [0u8; MAX_LEN];
    let len = good.len() as usize;
    good.copy_into_slice(&mut buf[..len]);
    let good = &buf[..len];

    let mut cases: StdVec<StdVec<u8>> = StdVec::new();
    let mut m = good.to_vec();
    m[0] ^= 1; // tag
    cases.push(m);
    let mut m = good.to_vec();
    m[100] = 1; // domain padding
    cases.push(m);
    let mut m = good.to_vec();
    m[70] = 0; // empty domain
    cases.push(m);
    let mut m = good.to_vec();
    m[134] = b'T'; // uppercase selector
    cases.push(m);
    let mut m = good.to_vec();
    m[229] = 2; // observed_live
    cases.push(m);
    let mut m = good.to_vec();
    m[238] = 0; // no resolvers
    cases.push(m);
    let mut m = good.to_vec();
    m.push(0); // trailing byte
    cases.push(m);
    cases.push(good[..len - 1].to_vec()); // truncated
    let mut m = good.to_vec();
    m[240] = b' '; // non-printable resolver byte
    cases.push(m);

    for (i, case) in cases.iter().enumerate() {
        let (k, a, s) = t.sign_raw(0, case);
        assert_eq!(
            t.c.try_attest(&id, &k, &a, &s),
            Err(Ok(Error::MalformedAttestation)),
            "case {i}"
        );
    }
    assert!(attestation::parse(good).is_some());
}

// --- events ----------------------------------------------------------------------

#[test]
fn every_change_emits_an_event() {
    let t = setup();
    let gmail = bytes(&t.e, "gmail.com");
    let n = modulus(&t.e, 1);
    let kh = key_hash_of(&t.e, &n);

    let id = t.c.propose_add(&t.members[0], &gmail, &n);
    let ev = t.published();
    assert!(ev.contains(
        &KeyProposed {
            domain: gmail.clone(),
            id,
            kind: ProposalKind::Add,
            key_hash: kh.clone(),
            modulus: n.clone(),
            proposer: t.members[0].clone(),
        }
        .to_xdr(&t.e, &t.id)
    ));
    assert!(ev.contains(
        &ProposalApproved {
            id,
            member: t.members[0].clone(),
            approvals: 1,
            approved: false,
        }
        .to_xdr(&t.e, &t.id)
    ));

    t.c.approve(&t.members[1], &id);
    t.c.approve(&t.members[2], &id);
    assert!(t.published().contains(
        &ProposalApproved {
            id,
            member: t.members[2].clone(),
            approvals: 3,
            approved: true,
        }
        .to_xdr(&t.e, &t.id)
    ));

    t.attest(id, 1, true);
    let mut resolvers = Vec::new(&t.e);
    resolvers.push_back(bytes(&t.e, "8.8.8.8"));
    resolvers.push_back(bytes(&t.e, "1.1.1.1"));
    assert!(t.published().contains(
        &DnsAttested {
            domain: gmail.clone(),
            id,
            attester: BytesN::from_array(&t.e, &t.attesters[1].verifying_key().to_bytes()),
            selector: bytes(&t.e, "test"),
            key_hash: kh.clone(),
            observed_live: true,
            observed_at: START_TS,
            resolvers,
        }
        .to_xdr(&t.e, &t.id)
    ));

    // Activation and retirement events are pinned by the timelock and
    // retirement tests; revocation's here.
    t.advance(TIMELOCK_SECONDS);
    let with_key = t.c.execute(&id);
    let rid = t.c.propose_revoke(&t.members[3], &gmail, &kh);
    t.c.approve(&t.members[4], &rid);
    let mut refused = Vec::new(&t.e);
    refused.push_back(with_key);
    assert!(t.published().contains(
        &KeyRevoked {
            domain: gmail,
            id: rid,
            key_hash: kh,
            root: crate::empty_root(&t.e),
            refused_roots: refused,
        }
        .to_xdr(&t.e, &t.id)
    ));
}

// --- hashing -----------------------------------------------------------------------

/// Bytes of `name` in `vectors/src/inputs.nr`.
fn noir_bytes(name: &str) -> StdVec<u8> {
    let src = include_str!("../vectors/src/inputs.nr");
    let start = src.find(&std::format!("pub global {name}:")).unwrap();
    let body = &src[start..];
    let body = &body[body.find("= [").unwrap() + 3..body.find("];").unwrap()];
    body.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| u8::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .collect()
}

fn fe(e: &Env, hex: &str) -> BytesN<32> {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    BytesN::from_array(e, &out)
}

/// The contract's key hashes, leaves, and roots, reached through its own
/// proposals, equal the values `vectors/src/lib.nr` computes with
/// noir-lang/poseidon v0.2.0 (the email circuit's Poseidon2).
#[test]
fn noir_vectors() {
    let t = setup();
    let fixture = |name: &str| Bytes::from_slice(&t.e, &noir_bytes(name));
    let (a, b, c) = (
        fixture("MODULUS_A"),
        fixture("MODULUS_B"),
        fixture("MODULUS_C"),
    );
    let ka = fe(
        &t.e,
        "25a7dd9c7d1722237f60c18f7e981754bacb873259d63ffc9114caacdb4bcdae",
    );
    let kb = fe(
        &t.e,
        "0612361cdce4d414bbcb22c64e24fe37a2e1e546d506d19176c5a0237d0aaa00",
    );
    let kc = fe(
        &t.e,
        "12abba657357fe88dfc265e30573e1924ba02888c9338454f097b739c9519115",
    );
    assert_eq!(t.c.key_hash(&a), ka);
    assert_eq!(t.c.key_hash(&b), kb);
    assert_eq!(t.c.key_hash(&c), kc);

    let la = fe(
        &t.e,
        "27f86eaf8edb3e0731742dcb5d4224053934a67a158915aef1cceaaf0d769169",
    );
    let lb = fe(
        &t.e,
        "13507fa59f3214cee8a827a2b87eaab25f32ac2b62e14586173376a423b953b9",
    );
    let lc = fe(
        &t.e,
        "212a001de51855c45d590f4c72f7d7575c841fcc1cc515553e2faedcf956c9b8",
    );
    assert_eq!(leaf_of(&t.e, "gmail.com", &ka), la);
    assert_eq!(leaf_of(&t.e, "outlook.com", &kb), lb);
    assert_eq!(leaf_of(&t.e, "fastmail.com", &kc), lc);

    let step = |domain: &str, n: &Bytes| {
        let id = t.approved_add(domain, n);
        t.advance(TIMELOCK_SECONDS);
        t.c.execute(&id)
    };
    assert_eq!(
        step("gmail.com", &a),
        fe(
            &t.e,
            "22da6e7490012cd3daa3edab29388c9ab80ffeea19aa956f35ad9da0600d8319"
        )
    );
    step("outlook.com", &b);
    assert_eq!(
        step("fastmail.com", &c),
        fe(
            &t.e,
            "08fd83d83b64b3be8f9af81baeca40cbd5ea0ce9960e877254df996a1d4c927c"
        )
    );
    assert_eq!(
        t.retire("outlook.com", &kb),
        fe(
            &t.e,
            "23cce8ab300369c2220682360665ee0218df244953b2753de7e011d716181a3c"
        )
    );

    // The circuit's membership check (spec §6.2 C6) from the contract's
    // witness: fold leaf 2 up its siblings.
    let siblings = t.c.siblings(&2);
    assert_eq!(siblings.len(), REGISTRY_DEPTH);
    let mut h = Hasher::new(&t.e);
    let mut cur = lc;
    for (level, s) in siblings.iter().enumerate() {
        cur = if (2u32 >> level) & 1 == 0 {
            h.node(&cur, &s)
        } else {
            h.node(&s, &cur)
        };
    }
    assert_eq!(cur, t.c.root());

    // A key pin over A (spec §7.4), salted with the vectors' account code.
    let mut code = [0u8; 32];
    code[16..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    let salt = h.pin_salt(&BytesN::from_array(&t.e, &code));
    assert_eq!(
        root_of(&t.e, &[salt, la]),
        fe(
            &t.e,
            "06809f5b34b6b7e95400ba494bbf58b9e2e7e5c9457bbc537560af4b3cb36a1f"
        )
    );
    assert_eq!(
        crate::empty_root(&t.e),
        fe(
            &t.e,
            "14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3"
        )
    );
}

/// The interior node is Perch's, and the first 17 entries of Perch's
/// empty-subtree table are this tree's `Z_0..Z_16`.
#[test]
fn the_tree_hashes_as_perchs_pool() {
    let e = env();
    let mut ours = Hasher::new(&e);
    let mut perch = perch_zk_primitives::Hasher::new(&e);
    let l = fe(
        &e,
        "27f86eaf8edb3e0731742dcb5d4224053934a67a158915aef1cceaaf0d769169",
    );
    let r = fe(
        &e,
        "13507fa59f3214cee8a827a2b87eaab25f32ac2b62e14586173376a423b953b9",
    );
    assert_eq!(ours.node(&l, &r), perch.node(&l, &r));
    let zeros = perch.zero_hashes(REGISTRY_DEPTH);
    for (i, z) in zeros.iter().enumerate() {
        assert_eq!(z.to_array(), perch_zk_primitives::ZERO_HASHES[i], "Z_{i}");
    }
    assert_eq!(root_of(&e, &[]), crate::empty_root(&e));
}

#[test]
fn limbs_are_120_bits_least_significant_first() {
    let mut n = [0u8; 256];
    for (i, b) in n.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let l = crate::hash::limbs(&n);
    // Limb 0: the last 15 bytes (241..=255), right-aligned.
    assert_eq!(&l[0][17..], &n[241..]);
    assert!(l[0][..17].iter().all(|&b| b == 0));
    // Limb 16: bytes 1..=15.
    assert_eq!(&l[16][17..], &n[1..16]);
    // Limb 17: the top byte alone.
    assert_eq!(l[17][31], n[0]);
    assert!(l[17][..31].iter().all(|&b| b == 0));
}

#[test]
fn views_and_keep_alives() {
    let t = setup();
    assert_eq!(t.c.version(), crate::VERSION);
    assert_eq!(t.c.config().threshold, 3);
    let (id, kh, root) = t.admit("gmail.com", 1);
    let leaf_id = crate::LeafId {
        domain: bytes(&t.e, "gmail.com"),
        key_hash: kh,
    };
    assert_eq!(t.c.leaf_at(&0), Some(leaf_id));
    assert_eq!(t.c.leaf_at(&1), None);
    assert!(t.c.proposal(&id).unwrap().executed);
    assert_eq!(t.c.proposal(&999), None);
    assert_eq!(t.c.eligible_at(&999), None);
    let st = t.c.state();
    assert_eq!((st.seq, st.next_index, st.next_proposal), (1, 1, 2));
    t.c.renew();
    t.c.renew_path(&0);
    t.c.renew_path(&5);
    assert_eq!(t.c.root(), root);
}
