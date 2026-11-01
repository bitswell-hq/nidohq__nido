//! The email guardian as one guardian of Perch's recovery, on Nido's stack:
//! a factory-minted Perch account, Perch's controller from its deployed
//! wasm, guardian accounts with passkeys, and the email guardian from its own
//! wasm, all under enforcing authorization (`docs/email-recovery/spec.md`,
//! "One-factor safety").
//!
//! The key registry is the real contract from its wasm, fed by the DNS
//! attester mock; the proof verifier is the test-only stand-in of
//! [`nido_integration_tests::email`]: these tests pin how approvals are
//! counted, bound, and refused, and which key roots they may use, not the
//! email circuit.
//!
//! An approval the guardian refuses fails the host's authorization check, so
//! the controller call fails with a host error rather than a
//! `RecoveryError`; the guardian's own error codes are pinned by its unit
//! tests.

use nido_dkim_registry::hash::Hasher;
use nido_dkim_registry::{root_of, DkimRegistryError, TIMELOCK_ATTESTED_LEDGERS};
use nido_dns_attestation_mock::{fixture, key_hash, modulus_2048};
use nido_email_guardian::{EmailApproval, EmailGuardianError, KeyPin, ALLOW_ALL};
use nido_integration_tests::email::{field, EmailGuardian, EmailInfra};
use nido_integration_tests::world::{
    err, world, Account, Mode, Passkey, Profile, Recovery, World, DELAY, EXPIRY,
};
use perch_account::PerchAccountError;
use perch_recovery::EvidenceDomain::{self, Cancel, Initiate};
use perch_recovery::RecoveryError;
use perch_recovery_interface::statement::ConfigChange;
use perch_recovery_interface::{RecoveryAction, StatementSubject};
use soroban_sdk::xdr::{Limits, WriteXdr};
use soroban_sdk::{Bytes, BytesN};

/// An account whose recovery lists its email guardian first, then `friends`
/// guardian accounts, with `quorum`.
struct Setup {
    account: Account,
    email: EmailGuardian,
    friends: std::vec::Vec<Account>,
    recovery: Recovery,
}

fn enroll(
    w: &World,
    infra: &EmailInfra,
    label: &str,
    profile: Profile,
    friends: usize,
    quorum: u32,
    commitment: &BytesN<32>,
) -> Setup {
    enroll_with_pin(w, infra, label, profile, friends, quorum, commitment, None)
}

#[allow(clippy::too_many_arguments)]
fn enroll_with_pin(
    w: &World,
    infra: &EmailInfra,
    label: &str,
    profile: Profile,
    friends: usize,
    quorum: u32,
    commitment: &BytesN<32>,
    pin: Option<KeyPin>,
) -> Setup {
    let account = w.mint(
        label,
        Passkey::labelled(&format!("{label}/owner")),
        vec![("device", Passkey::labelled(&format!("{label}/device")))],
    );
    let email = infra.guardian_with_pin(w, &account, label, commitment, ALLOW_ALL, pin);
    let friends: std::vec::Vec<Account> = (0..friends)
        .map(|i| {
            w.guardian(
                &format!("{label}/friend-{i}"),
                Passkey::labelled(&format!("{label}/friend-{i}")),
            )
        })
        .collect();
    let mut guardians = vec![email.address.clone()];
    guardians.extend(friends.iter().map(|f| f.address.clone()));
    let recovery = Recovery {
        profile,
        mode: Mode::Guardian,
        guardians,
        quorum,
        enrollment: None,
        baseline: None,
        replaceable: vec!["owner"],
        delay: DELAY,
        expiry: EXPIRY,
        max_cancels: 3,
    };
    w.apply(&account, &w.doc(&account, Some(recovery.clone())), 0)
        .expect("enrollment with the email guardian");
    Setup {
        account,
        email,
        friends,
        recovery,
    }
}

/// A lost-key attempt replacing the owner passkey; returns its id and the
/// target a completer submits.
fn begin(w: &World, s: &Setup, label: &str) -> (u64, Bytes) {
    let new_owner = Passkey::labelled(&format!("{label}/new-owner"));
    let replacements = w.replacements(&new_owner, None);
    let source = w.account(&s.account).applied_doc().unwrap();
    let attempt = w
        .begin_lost_key(&s.account, &replacements)
        .expect("permissionless begin");
    let target = w.target_bytes(&s.account, RecoveryAction::LostKey, &source, &replacements);
    (attempt, target)
}

fn email_approval(w: &World, infra: &EmailInfra, s: &Setup, attempt: u64) -> EmailApproval {
    infra.approval(w, &s.email, &w.statement(&s.account, attempt, Initiate))
}

fn authorized(w: &World, s: &Setup) -> Option<u64> {
    w.ctl().activity_gate(&s.account.address).authorized_attempt
}

fn votes(w: &World, s: &Setup, attempt: u64) -> std::vec::Vec<soroban_sdk::Address> {
    w.ctl()
        .attempt(&s.account.address, &attempt)
        .unwrap()
        .guardians
        .iter()
        .collect()
}

/// `approval` for `account`'s attempt in `domain` is refused by `guardian`
/// with `why`: the controller call aborts on the failed authorization, and
/// the guardian's own `__check_auth` reports `why`.
#[allow(clippy::too_many_arguments)]
fn refused(
    w: &World,
    infra: &EmailInfra,
    s: &Setup,
    guardian: &EmailGuardian,
    attempt: u64,
    domain: EvidenceDomain,
    approval: &EmailApproval,
    why: EmailGuardianError,
) {
    let r = infra.try_submit(w, &s.account, guardian, attempt, domain, approval);
    assert!(
        matches!(r, Err(Err(soroban_sdk::InvokeError::Abort))),
        "expected an aborted authorization, got {r:?}"
    );
    assert_eq!(
        infra.check_auth(w, &s.account, guardian, attempt, domain, approval),
        Err(why)
    );
}

/// An email approval is recorded as one guardian vote: alone it does not
/// reach a 2-of-3 quorum, with one other guardian it authorizes the attempt,
/// and the completion still waits out the delay.
#[test]
fn email_approval_counts_as_exactly_one_guardian_vote() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-one-vote";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Loss,
        2,
        2,
        &field(&w.env, "c/one-vote"),
    );
    let (attempt, target) = begin(&w, &s, label);

    infra
        .try_submit(
            &w,
            &s.account,
            &s.email,
            attempt,
            Initiate,
            &email_approval(&w, &infra, &s, attempt),
        )
        .expect("the email approval is accepted");
    assert_eq!(votes(&w, &s, attempt), vec![s.email.address.clone()]);
    assert_eq!(authorized(&w, &s), None, "one vote of a 2-of-3 quorum");

    w.try_guardian(&s.account, &s.friends[0], attempt, Initiate)
        .unwrap();
    assert_eq!(authorized(&w, &s), Some(attempt));

    assert!(w.complete(&s.account, &target).is_err(), "inside the delay");
    w.advance(DELAY);
    w.complete(&s.account, &target)
        .expect("completion after the delay");
    assert_eq!(
        w.ctl().attempt(&s.account.address, &attempt).unwrap().state,
        perch_recovery::AttemptState::Completed
    );
}

/// Submitting the same approval again, in a fresh authorization entry, is
/// refused: the controller counts a guardian once per attempt and domain.
#[test]
fn the_same_email_approval_is_not_counted_twice() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-twice";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Loss,
        2,
        3,
        &field(&w.env, "c/twice"),
    );
    let (attempt, _) = begin(&w, &s, label);
    let approval = email_approval(&w, &infra, &s, attempt);

    infra
        .try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)
        .unwrap();
    assert_eq!(
        err(infra.try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)),
        RecoveryError::AlreadyCounted
    );
    assert_eq!(votes(&w, &s, attempt), vec![s.email.address.clone()]);
}

/// An approval binds one attempt: its statement bytes do not hash to another
/// attempt's digest, and its proof does not verify for another attempt's
/// statement. Nor does an initiation approval serve the cancel domain.
#[test]
fn an_email_approval_cannot_be_replayed_into_another_attempt() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-replay-attempt";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Loss,
        2,
        2,
        &field(&w.env, "c/replay-attempt"),
    );
    let (first, _) = begin(&w, &s, label);
    let (second, _) = begin(&w, &s, &format!("{label}/second"));
    assert_ne!(first, second);
    let for_first = email_approval(&w, &infra, &s, first);

    // The first attempt's approval, as is, for the second attempt.
    let mismatch = EmailGuardianError::DigestMismatch;
    refused(
        &w, &infra, &s, &s.email, second, Initiate, &for_first, mismatch,
    );
    // The second attempt's statement with the first attempt's proof.
    let mut spliced = email_approval(&w, &infra, &s, second);
    spliced.proof = for_first.proof.clone();
    let rejected = EmailGuardianError::ProofRejected;
    refused(
        &w, &infra, &s, &s.email, second, Initiate, &spliced, rejected,
    );
    // The initiation approval in the cancel domain of the same attempt.
    refused(
        &w, &infra, &s, &s.email, first, Cancel, &for_first, mismatch,
    );

    assert!(votes(&w, &s, second).is_empty());
    infra
        .try_submit(&w, &s.account, &s.email, first, Initiate, &for_first)
        .expect("still good for its own attempt");
}

/// An approval binds one account. Two accounts whose guardians even share a
/// commitment (the same address enrolled twice with the same code): A's
/// approval does not count for B through B's guardian, and A's guardian is
/// not B's guardian at all.
#[test]
fn an_email_approval_cannot_be_replayed_into_another_account() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let shared = field(&w.env, "c/shared");
    let a = enroll(&w, &infra, "email-replay-a", Profile::Loss, 2, 2, &shared);
    let b = enroll(&w, &infra, "email-replay-b", Profile::Loss, 2, 2, &shared);
    let (attempt_a, _) = begin(&w, &a, "email-replay-a");
    let (attempt_b, _) = begin(&w, &b, "email-replay-b");
    let for_a = email_approval(&w, &infra, &a, attempt_a);

    // A's statement is not the preimage of B's digest (and names A, which
    // the account check would catch next).
    let mismatch = EmailGuardianError::DigestMismatch;
    refused(
        &w, &infra, &b, &b.email, attempt_b, Initiate, &for_a, mismatch,
    );
    // B's statement with A's proof: the proof binds A's digest.
    let mut spliced = email_approval(&w, &infra, &b, attempt_b);
    spliced.proof = for_a.proof.clone();
    let rejected = EmailGuardianError::ProofRejected;
    refused(
        &w, &infra, &b, &b.email, attempt_b, Initiate, &spliced, rejected,
    );
    assert_eq!(
        err(infra.try_submit(&w, &b.account, &a.email, attempt_b, Initiate, &for_a)),
        RecoveryError::NotAGuardian
    );

    assert!(votes(&w, &b, attempt_b).is_empty());
    infra
        .try_submit(&w, &a.account, &a.email, attempt_a, Initiate, &for_a)
        .expect("still good for its own account");
}

/// Email approvals alone never complete a recovery. With a 2-of-2 quorum the
/// email vote cannot authorize. With the email guardian as the only guardian
/// (quorum 1, `Loss`), it authorizes, but the completion still waits out the
/// delay, the owner can cancel inside it, and a new attempt needs a new
/// approval.
#[test]
fn email_approvals_alone_never_complete_a_recovery() {
    let w = world();
    let infra = EmailInfra::new(&w);

    let label = "email-alone-quorum";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Loss,
        1,
        2,
        &field(&w.env, "c/alone-quorum"),
    );
    let (attempt, target) = begin(&w, &s, label);
    infra
        .try_submit(
            &w,
            &s.account,
            &s.email,
            attempt,
            Initiate,
            &email_approval(&w, &infra, &s, attempt),
        )
        .unwrap();
    assert_eq!(authorized(&w, &s), None);
    w.advance(DELAY);
    assert!(
        w.complete(&s.account, &target).is_err(),
        "no quorum, no completion"
    );

    let label = "email-alone-delay";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Loss,
        0,
        1,
        &field(&w.env, "c/alone-delay"),
    );
    let (attempt, target) = begin(&w, &s, label);
    let approval = email_approval(&w, &infra, &s, attempt);
    infra
        .try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)
        .unwrap();
    assert_eq!(authorized(&w, &s), Some(attempt));
    w.advance(DELAY - 1);
    assert!(w.complete(&s.account, &target).is_err(), "inside the delay");
    w.owner_cancel(&s.account, attempt)
        .expect("the owner vetoes inside the delay");
    w.advance(1);
    assert!(
        w.complete(&s.account, &target).is_err(),
        "a cancelled attempt never completes"
    );

    // A fresh attempt: the old approval is bound to the cancelled one.
    let (next, next_target) = begin(&w, &s, &format!("{label}/next"));
    let mismatch = EmailGuardianError::DigestMismatch;
    refused(
        &w, &infra, &s, &s.email, next, Initiate, &approval, mismatch,
    );
    infra
        .try_submit(
            &w,
            &s.account,
            &s.email,
            next,
            Initiate,
            &email_approval(&w, &infra, &s, next),
        )
        .unwrap();
    assert!(
        w.complete(&s.account, &next_target).is_err(),
        "inside the delay"
    );
    w.advance(DELAY);
    w.complete(&s.account, &next_target)
        .expect("completion once the delay has passed");
}

/// `Protected`: a reconfiguration needs the current condition, and the email
/// guardian's `approve_change` counts as one of its votes there too.
#[test]
fn email_approval_counts_toward_a_protected_reconfiguration() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-reconfigure";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Protected,
        1,
        2,
        &field(&w.env, "c/reconfigure"),
    );
    let mut next = s.recovery.clone();
    next.delay = DELAY + 1;
    let doc = w.doc(&s.account, Some(next));
    let subject = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&doc)));
    let until = w.ledger() + 50;

    let statement = w
        .ctl()
        .change_statement(&s.account.address, &subject, &until);
    let approval = infra.approval(&w, &s.email, &statement);
    infra
        .try_approve_change(&w, &s.account, &s.email, &subject, until, &approval)
        .expect("the email approval is recorded");
    assert_eq!(
        err(w.apply(&s.account, &doc, until)),
        PerchAccountError::Recovery(RecoveryError::ConditionNotMet),
        "one vote of a 2-of-2 quorum"
    );
    w.try_approve_change(&s.account, &s.friends[0], &subject, until)
        .unwrap();
    w.apply(&s.account, &doc, until)
        .expect("owner plus a full quorum reconfigures");
    assert_eq!(
        w.ctl().config(&s.account.address).unwrap().delay_ledgers,
        DELAY + 1
    );
}

/// Resources of one `submit_guardian` carrying an email approval, with the
/// test-only verifier and the registry from its wasm: a plumbing figure for
/// the guardian's own checks, the registry's root check, the controller, and
/// the auth-entry size. Real proof verification is not in it.
#[test]
fn email_approval_plumbing_cost() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-cost";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Protected,
        2,
        2,
        &field(&w.env, "c/cost"),
    );
    let (attempt, _) = begin(&w, &s, label);
    let approval = email_approval(&w, &infra, &s, attempt);
    let digest = w.digest(&w.statement(&s.account, attempt, Initiate));
    let root = w.invocation(&w.controller, "submit_guardian", vec![w.sc(digest)]);
    let entry = infra.entry(&w, &s.email, root, &approval);
    let entry_bytes = entry.to_xdr(Limits::none()).unwrap().len();

    w.with_auths(&[entry], || {
        w.ctl()
            .submit_guardian(&s.account.address, &attempt, &Initiate, &s.email.address);
    });
    let r = w.env.cost_estimate().resources();
    println!(
        "{{\"case\":\"submit_guardian with an email approval (test-only verifier, registry from its wasm)\",\"instructions\":{},\"mem_bytes\":{},\"read_entries\":{},\"write_entries\":{},\"write_bytes\":{},\"auth_entry_bytes\":{entry_bytes}}}",
        r.instructions,
        r.mem_bytes,
        r.memory_read_entries + r.disk_read_entries,
        r.write_entries,
        r.write_bytes,
    );
    assert_eq!(votes(&w, &s, attempt), vec![s.email.address.clone()]);
}

/// The key hash and leaf of fixture `name`'s key.
fn fixture_key(w: &World, name: &str) -> (BytesN<32>, BytesN<32>) {
    let record = fixture(name);
    let n = modulus_2048(&record.parse().unwrap()).unwrap();
    let kh = BytesN::from_array(&w.env, &key_hash(&n));
    let leaf = Hasher::new(&w.env).leaf(record.domain.as_bytes(), &kh);
    (kh, leaf)
}

/// A key the registry admits through the attested path: an approval proven
/// against the root that will hold it is refused until the 72-hour timelock
/// has passed and accepted from the ledger the addition executes in.
#[test]
fn a_key_added_through_the_attested_path_is_refused_before_72_hours_and_accepted_after() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let registry = infra.registry.client(&w);
    let label = "email-new-key";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Loss,
        1,
        2,
        &field(&w.env, "c/new-key"),
    );

    let (id, new_leaf) = infra.registry.propose_attested(&w, "rsa2048-b");
    // The root a prover computes from the pending addition: the current leaf
    // at index 0, the new one at index 1.
    let (_, first_leaf) = fixture_key(&w, "rsa2048-a");
    let next_root = root_of(&w.env, &[first_leaf, new_leaf]);
    assert!(!registry.is_accepted_root(&next_root));

    w.advance(TIMELOCK_ATTESTED_LEDGERS - 1);
    assert_eq!(
        registry.try_execute(&id),
        Err(Ok(DkimRegistryError::TimelockActive))
    );
    let (attempt, _) = begin(&w, &s, label);
    let statement = w.statement(&s.account, attempt, Initiate);
    let approval = infra.approval_against(&w, &s.email, &statement, &next_root);
    let unknown = EmailGuardianError::UnknownRoot;
    refused(
        &w, &infra, &s, &s.email, attempt, Initiate, &approval, unknown,
    );

    w.advance(1);
    assert_eq!(registry.execute(&id), next_root);
    infra
        .try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)
        .expect("accepted once the addition has executed");
    assert_eq!(votes(&w, &s, attempt), vec![s.email.address.clone()]);
    // The previous root is still in its grace period.
    let earlier = infra.approval(&w, &s.email, &statement);
    assert_eq!(
        infra.check_auth(&w, &s.account, &s.email, attempt, Initiate, &earlier),
        Ok(())
    );
}

/// Revoking a key refuses every root containing it in the same ledger: an
/// approval the guardian accepted a moment earlier is refused.
#[test]
fn a_revoked_keys_root_is_refused_at_once() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-revoked-key";
    let s = enroll(
        &w,
        &infra,
        label,
        Profile::Loss,
        1,
        2,
        &field(&w.env, "c/revoked"),
    );
    let (attempt, _) = begin(&w, &s, label);
    let approval = email_approval(&w, &infra, &s, attempt);
    assert_eq!(
        infra.check_auth(&w, &s.account, &s.email, attempt, Initiate, &approval),
        Ok(())
    );

    let (kh, _) = fixture_key(&w, "rsa2048-a");
    infra.registry.revoke(&w, "gmail.com", &kh);
    assert!(!infra.registry.client(&w).is_accepted_root(&infra.root));
    let unknown = EmailGuardianError::UnknownRoot;
    refused(
        &w, &infra, &s, &s.email, attempt, Initiate, &approval, unknown,
    );
    assert!(votes(&w, &s, attempt).is_empty());
}

/// The pin is the guardian's own: a pinned key the registry never admitted
/// is accepted, revoking it in the registry does not close the pin, and the
/// pin root is refused once the pin expires (spec §7.4).
#[test]
fn the_pin_path_works_independently_of_the_registry() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-pinned";
    // The enrollment email was signed by fixture rsa2048-c's key, which the
    // registry has never seen.
    let (kh, leaf) = fixture_key(&w, "rsa2048-c");
    let code = field(&w.env, "nido-it/email/account-code");
    let salt = Hasher::new(&w.env).pin_salt(&code);
    let pin_root = root_of(&w.env, &[salt, leaf]);
    let until = w.ledger() + 1_000;
    let pin = KeyPin {
        root: pin_root.clone(),
        valid_until_ledger: until,
    };
    let s = enroll_with_pin(
        &w,
        &infra,
        label,
        Profile::Loss,
        1,
        2,
        &field(&w.env, "c/pinned"),
        Some(pin),
    );
    let registry = infra.registry.client(&w);
    assert!(!registry.is_accepted_root(&pin_root));

    let (attempt, _) = begin(&w, &s, label);
    let statement = w.statement(&s.account, attempt, Initiate);
    let approval = infra.approval_against(&w, &s.email, &statement, &pin_root);
    infra.registry.revoke(&w, "fastmail.com", &kh);
    infra
        .try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)
        .expect("the pin accepts a key the registry revoked");
    assert_eq!(votes(&w, &s, attempt), vec![s.email.address.clone()]);

    w.advance(until + 1 - w.ledger());
    let (next, _) = begin(&w, &s, &format!("{label}/next"));
    let statement = w.statement(&s.account, next, Initiate);
    let late = infra.approval_against(&w, &s.email, &statement, &pin_root);
    let unknown = EmailGuardianError::UnknownRoot;
    refused(&w, &infra, &s, &s.email, next, Initiate, &late, unknown);
}
