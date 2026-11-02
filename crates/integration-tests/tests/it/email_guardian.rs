//! The email guardian as one guardian of Perch's recovery, on Nido's stack:
//! a factory-minted Perch account, Perch's controller from its deployed
//! wasm, guardian accounts with passkeys, and the email guardian from its own
//! wasm, all under enforcing authorization (`docs/email-recovery/spec.md`,
//! "One-factor safety").
//!
//! Every approval carries a real proof of the email circuit over a
//! DKIM-signed recovery email from the TEST-ONLY provider mocks, checked by
//! the real verifier from its wasm; the key registry is the real contract
//! from its wasm, fed by the DNS attester mock
//! ([`nido_integration_tests::email`]). The committed proofs are
//! `fixtures/email/guardian-*` (`just gen-email-proofs`).
//!
//! An approval the guardian refuses fails the host's authorization check, so
//! the controller call fails with a host error rather than a
//! `RecoveryError`; the guardian's own error codes are pinned by its unit
//! tests.

use nido_dkim_registry::hash::Hasher;
use nido_dkim_registry::{root_of, DkimRegistryError, TIMELOCK_ATTESTED_LEDGERS};
use nido_email_guardian::{EmailApproval, EmailGuardianError, KeyPin, ALLOW_ALL};
use nido_integration_tests::email::{with_statement, EmailGuardian, EmailInfra, REGISTRY_GRACE};
use nido_integration_tests::email_proof::{provider_key, Inbox, KeyPath};
use nido_integration_tests::world::{
    err, world, Account, Mode, Passkey, Profile, Recovery, World, DELAY, EXPIRY,
};
use perch_account::PerchAccountError;
use perch_recovery::EvidenceDomain::{self, Cancel, Initiate};
use perch_recovery::RecoveryError;
use perch_recovery_interface::statement::ConfigChange;
use perch_recovery_interface::{RecoveryAction, StatementSubject};
use soroban_sdk::{Bytes, BytesN};

/// An account whose recovery lists its email guardian first, then `friends`
/// guardian accounts, with `quorum`.
struct Setup {
    account: Account,
    email: EmailGuardian,
    friends: std::vec::Vec<Account>,
    recovery: Recovery,
}

/// A Gmail inbox for `label`, signed with Gmail's current key.
fn gmail(label: &str) -> Inbox {
    Inbox::new(
        label,
        &format!("{}@gmail.com", label.replace('-', ".")),
        Some("Test User"),
    )
}

fn enroll(
    w: &World,
    infra: &EmailInfra,
    label: &str,
    profile: Profile,
    friends: usize,
    quorum: u32,
    inbox: &Inbox,
) -> Setup {
    enroll_with_pin(w, infra, label, profile, friends, quorum, inbox, None)
}

#[allow(clippy::too_many_arguments)]
fn enroll_with_pin(
    w: &World,
    infra: &EmailInfra,
    label: &str,
    profile: Profile,
    friends: usize,
    quorum: u32,
    inbox: &Inbox,
    pin: Option<KeyPin>,
) -> Setup {
    let account = w.mint(
        label,
        Passkey::labelled(&format!("{label}/owner")),
        vec![("device", Passkey::labelled(&format!("{label}/device")))],
    );
    let email = infra.guardian_with_pin(w, &account, label, inbox, ALLOW_ALL, pin);
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

/// The email approval of `s`'s attempt, proven against the registry's
/// current root (fixture `name`).
fn email_approval(
    w: &World,
    infra: &EmailInfra,
    s: &Setup,
    attempt: u64,
    name: &str,
    description: &str,
) -> EmailApproval {
    infra.registry_approval(
        w,
        &s.email,
        name,
        description,
        &w.statement(&s.account, attempt, Initiate),
    )
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
    let s = enroll(&w, &infra, label, Profile::Loss, 2, 2, &gmail(label));
    let (attempt, target) = begin(&w, &s, label);

    let approval = email_approval(
        &w,
        &infra,
        &s,
        attempt,
        "guardian-one-vote",
        "one email approval is one vote of a 2-of-3 quorum",
    );
    infra
        .try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)
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
    let s = enroll(&w, &infra, label, Profile::Loss, 2, 3, &gmail(label));
    let (attempt, _) = begin(&w, &s, label);
    let approval = email_approval(
        &w,
        &infra,
        &s,
        attempt,
        "guardian-twice",
        "an approval submitted twice counts once",
    );

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
    let s = enroll(&w, &infra, label, Profile::Loss, 2, 2, &gmail(label));
    let (first, _) = begin(&w, &s, label);
    let (second, _) = begin(&w, &s, &format!("{label}/second"));
    assert_ne!(first, second);
    let for_first = email_approval(
        &w,
        &infra,
        &s,
        first,
        "guardian-replay-attempt",
        "an approval of one attempt, replayed into another",
    );

    // The first attempt's approval, as is, for the second attempt.
    let mismatch = EmailGuardianError::DigestMismatch;
    refused(
        &w, &infra, &s, &s.email, second, Initiate, &for_first, mismatch,
    );
    // The second attempt's statement with the first attempt's proof.
    let spliced = with_statement(
        &w.env,
        &for_first,
        &w.statement(&s.account, second, Initiate),
    );
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
    let shared = gmail("email-replay-shared");
    let a = enroll(&w, &infra, "email-replay-a", Profile::Loss, 2, 2, &shared);
    let b = enroll(&w, &infra, "email-replay-b", Profile::Loss, 2, 2, &shared);
    assert_eq!(a.email.commitment, b.email.commitment);
    let (attempt_a, _) = begin(&w, &a, "email-replay-a");
    let (attempt_b, _) = begin(&w, &b, "email-replay-b");
    let for_a = email_approval(
        &w,
        &infra,
        &a,
        attempt_a,
        "guardian-replay-account",
        "an approval for account A, replayed into account B with the same commitment",
    );

    // A's statement is not the preimage of B's digest (and names A, which
    // the account check would catch next).
    let mismatch = EmailGuardianError::DigestMismatch;
    refused(
        &w, &infra, &b, &b.email, attempt_b, Initiate, &for_a, mismatch,
    );
    // B's statement with A's proof: the proof binds A's digest.
    let spliced = with_statement(
        &w.env,
        &for_a,
        &w.statement(&b.account, attempt_b, Initiate),
    );
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
    let s = enroll(&w, &infra, label, Profile::Loss, 1, 2, &gmail(label));
    let (attempt, target) = begin(&w, &s, label);
    let approval = email_approval(
        &w,
        &infra,
        &s,
        attempt,
        "guardian-alone-quorum",
        "the email vote alone under a 2-of-2 quorum",
    );
    infra
        .try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)
        .unwrap();
    assert_eq!(authorized(&w, &s), None);
    w.advance(DELAY);
    assert!(
        w.complete(&s.account, &target).is_err(),
        "no quorum, no completion"
    );

    let label = "email-alone-delay";
    let s = enroll(&w, &infra, label, Profile::Loss, 0, 1, &gmail(label));
    let (attempt, target) = begin(&w, &s, label);
    let approval = email_approval(
        &w,
        &infra,
        &s,
        attempt,
        "guardian-alone-delay",
        "the email guardian as the only guardian: the attempt the owner cancels",
    );
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
    let fresh = email_approval(
        &w,
        &infra,
        &s,
        next,
        "guardian-alone-next",
        "the email guardian as the only guardian: the next attempt, completed after the delay",
    );
    infra
        .try_submit(&w, &s.account, &s.email, next, Initiate, &fresh)
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
    let s = enroll(&w, &infra, label, Profile::Protected, 1, 2, &gmail(label));
    let mut next = s.recovery.clone();
    next.delay = DELAY + 1;
    let doc = w.doc(&s.account, Some(next));
    let subject = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&doc)));
    let until = w.ledger() + 50;

    let statement = w
        .ctl()
        .change_statement(&s.account.address, &subject, &until);
    let approval = infra.registry_approval(
        &w,
        &s.email,
        "guardian-reconfigure",
        "the email vote toward a Protected reconfiguration",
        &statement,
    );
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

/// A key the registry admits through the attested path: an approval proven
/// against the root that will hold it is refused until the 72-hour timelock
/// has passed and accepted from the ledger the addition executes in.
///
/// The inbox's mail is signed with Gmail's key at its previous selector
/// (still published), which the registry does not hold until this addition;
/// the earlier root holds Gmail's current key, and the same inbox's email
/// signed with that key is accepted against it during its grace period.
#[test]
fn a_key_added_through_the_attested_path_is_refused_before_72_hours_and_accepted_after() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let registry = infra.registry.client(&w);
    let label = "email-new-key";
    let inbox = gmail(label).signed_by("gmail-previous");
    let s = enroll(&w, &infra, label, Profile::Loss, 1, 2, &inbox);

    let previous = provider_key("gmail.com", "gmail-previous");
    let id = infra.registry.propose_attested_key(&w, &previous);
    // The tree a prover computes from the pending addition: the launch
    // leaves, then the new one.
    let mut leaves = EmailInfra::launch_leaves();
    leaves.push(previous.leaf());
    let next = KeyPath::of(&leaves, leaves.len() - 1);
    let next_root = BytesN::from_array(&w.env, &next.root);
    assert!(!registry.is_accepted_root(&next_root));

    w.advance(TIMELOCK_ATTESTED_LEDGERS - 1);
    assert_eq!(
        registry.try_execute(&id),
        Err(Ok(DkimRegistryError::TimelockActive))
    );
    let (attempt, _) = begin(&w, &s, label);
    let statement = w.statement(&s.account, attempt, Initiate);
    let approval = infra.approval(
        &w,
        &s.email,
        "guardian-new-key",
        "an approval proven against the root a pending addition produces",
        &statement,
        &next,
    );
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
    let earlier_path = KeyPath::of(&EmailInfra::launch_leaves(), 0);
    assert_eq!(earlier_path.root, infra.root.to_array());
    let current = EmailGuardian {
        inbox: s.email.inbox.clone().signed_by("current"),
        ..s.email.clone()
    };
    let earlier = infra.approval(
        &w,
        &current,
        "guardian-new-key-earlier",
        "the same inbox's approval under Gmail's current key, against the previous root in its grace period",
        &statement,
        &earlier_path,
    );
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
    let s = enroll(&w, &infra, label, Profile::Loss, 1, 2, &gmail(label));
    let (attempt, _) = begin(&w, &s, label);
    let approval = email_approval(
        &w,
        &infra,
        &s,
        attempt,
        "guardian-revoked",
        "an approval whose key is revoked before it is submitted",
    );
    assert_eq!(
        infra.check_auth(&w, &s.account, &s.email, attempt, Initiate, &approval),
        Ok(())
    );

    let kh = BytesN::from_array(&w.env, &provider_key("gmail.com", "current").key_hash());
    infra.registry.revoke(&w, "gmail.com", &kh);
    assert!(!infra.registry.client(&w).is_accepted_root(&infra.root));
    let unknown = EmailGuardianError::UnknownRoot;
    refused(
        &w, &infra, &s, &s.email, attempt, Initiate, &approval, unknown,
    );
    assert!(votes(&w, &s, attempt).is_empty());
}

/// A root the registry never produced is refused before the proof is
/// checked: a tree an attacker builds with the launch keys and one more
/// leaf, and the empty tree.
#[test]
fn a_root_the_registry_does_not_accept_is_refused() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-foreign-root";
    let s = enroll(&w, &infra, label, Profile::Loss, 1, 2, &gmail(label));
    let (attempt, _) = begin(&w, &s, label);
    let approval = email_approval(
        &w,
        &infra,
        &s,
        attempt,
        "guardian-foreign-root",
        "an approval whose key root is replaced by roots the registry never produced",
    );
    let mut leaves = EmailInfra::launch_leaves();
    leaves.push(provider_key("gmail.com", "gmail-previous").leaf());
    let foreign = KeyPath::of(&leaves, 0).root;
    for root in [foreign, perch_zk_primitives::ZERO_HASHES[16]] {
        let moved = EmailApproval {
            key_root: BytesN::from_array(&w.env, &root),
            ..approval.clone()
        };
        let unknown = EmailGuardianError::UnknownRoot;
        refused(&w, &infra, &s, &s.email, attempt, Initiate, &moved, unknown);
    }
    infra
        .try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)
        .expect("the registry's own root is accepted");
}

/// The pin is the guardian's own: a pinned key the registry never admitted
/// is accepted, revoking it in the registry does not close the pin, and the
/// pin root is refused once the pin expires (spec §7.4).
#[test]
fn the_pin_path_works_independently_of_the_registry() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "email-pinned";
    // The enrollment email was signed with Gmail's key at its previous
    // selector, which the registry has never admitted.
    let inbox = gmail(label).signed_by("gmail-previous");
    let previous = provider_key("gmail.com", "gmail-previous");
    let kh = BytesN::from_array(&w.env, &previous.key_hash());
    let code = BytesN::from_array(&w.env, &inbox.account_code);
    let salt = Hasher::new(&w.env).pin_salt(&code);
    let leaf = BytesN::from_array(&w.env, &previous.leaf());
    let pin_root = root_of(&w.env, &[salt.clone(), leaf.clone()]);
    let pin_path = KeyPath::of(&[salt.to_array(), leaf.to_array()], 1);
    assert_eq!(
        pin_path.root,
        pin_root.to_array(),
        "the wallet's pin tree is the registry's formula"
    );
    let until = w.ledger() + 1_000;
    let pin = KeyPin {
        root: pin_root.clone(),
        valid_until_ledger: until,
    };
    let s = enroll_with_pin(&w, &infra, label, Profile::Loss, 1, 2, &inbox, Some(pin));
    let registry = infra.registry.client(&w);
    assert!(!registry.is_accepted_root(&pin_root));

    let (attempt, _) = begin(&w, &s, label);
    let statement = w.statement(&s.account, attempt, Initiate);
    let approval = infra.approval(
        &w,
        &s.email,
        "guardian-pinned",
        "an approval proven against the guardian's key pin",
        &statement,
        &pin_path,
    );
    infra.registry.revoke(&w, "gmail.com", &kh);
    infra
        .try_submit(&w, &s.account, &s.email, attempt, Initiate, &approval)
        .expect("the pin accepts a key the registry revoked");
    assert_eq!(votes(&w, &s, attempt), vec![s.email.address.clone()]);

    w.advance(until + 1 - w.ledger());
    let (next, _) = begin(&w, &s, &format!("{label}/next"));
    let late = with_statement(&w.env, &approval, &w.statement(&s.account, next, Initiate));
    let unknown = EmailGuardianError::UnknownRoot;
    refused(&w, &infra, &s, &s.email, next, Initiate, &late, unknown);
}

// --- the attack suite's registry scenarios on the test host ----------------
//
// research/email-recovery/eval runs the attack suite on a local network,
// where a ledger closes about once a second, so the registry's timelocks
// (51,840 and 120,960 ledgers) and its 17,280-ledger grace cannot elapse in
// a run. The three scenarios whose precondition is an elapsed timelock run
// here instead, on the registry's production wasm with its real timelocks
// and grace, the ledger advanced, and a real proof in every approval. With
// `NIDO_EMAIL_ATTACK_ROWS=<file>` each appends its result row to the file.

/// Append `scenario`'s result row (from test `test`) to
/// `$NIDO_EMAIL_ATTACK_ROWS`, if set.
fn attack_row(
    test: &str,
    scenario: &str,
    property: u8,
    expected: &str,
    observed: &str,
    layer: &str,
    note: &str,
) {
    if let Ok(path) = std::env::var("NIDO_EMAIL_ATTACK_ROWS") {
        use std::io::Write as _;
        let row = serde_json::json!({
            "class": "registry",
            "scenario": scenario,
            "test": test,
            "property": property,
            "expected": expected,
            "observed": observed,
            "layer": layer,
            "network": "test host",
            "note": note,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("the rows file");
        writeln!(f, "{row}").expect("a row");
    }
}

/// `check_auth`'s verdict as the suite's table words it.
fn verdict(r: Result<(), EmailGuardianError>) -> String {
    match r {
        Ok(()) => "accepted".into(),
        Err(e) => format!("refused: {e:?}"),
    }
}

/// A threshold of registry members adds a key the attacker holds (Gmail's
/// TEST-ONLY previous key stands for it), unattested, so on the 7-day path;
/// it executes once the timelock has passed. Returns the key.
fn plant_and_activate(
    w: &World,
    infra: &EmailInfra,
) -> nido_integration_tests::email_proof::ProviderKey {
    let planted = provider_key("gmail.com", "gmail-previous");
    let registry = infra.registry.client(w);
    let id = infra
        .registry
        .propose_add(w, 0, "gmail.com", &planted.modulus());
    infra.registry.approve(w, 1, id);
    infra.registry.approve(w, 2, id);
    assert_eq!(
        registry.eligible_at(&id),
        Some(w.ledger() + nido_dkim_registry::TIMELOCK_LEDGERS)
    );
    w.advance(nido_dkim_registry::TIMELOCK_LEDGERS - 1);
    assert_eq!(
        registry.try_execute(&id),
        Err(Ok(DkimRegistryError::TimelockActive))
    );
    w.advance(1);
    let root = registry.execute(&id);
    assert!(registry.is_accepted_root(&root));
    planted
}

/// A planted key that has activated still cannot approve for an account
/// whose `account_code` the attacker does not hold: the attacker's real
/// proof (the victim's address under a guessed code, signed by the planted
/// key, against the registry's current root) is refused by the verifier.
#[test]
fn registry_planted_key_after_activation_without_account_code() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "attack-planted";
    let s = enroll(&w, &infra, label, Profile::Loss, 1, 2, &gmail(label));
    let planted = plant_and_activate(&w, &infra);
    let (attempt, _) = begin(&w, &s, label);
    let statement = w.statement(&s.account, attempt, Initiate);
    let path = infra.registry_path(&w, &planted);
    let guess = Inbox::new(
        "attack-planted/guess",
        &s.email.inbox.address,
        Some("Test User"),
    )
    .signed_by("gmail-previous");
    assert_ne!(guess.account_code, s.email.inbox.account_code);
    let attacker = EmailGuardian {
        inbox: guess,
        ..s.email.clone()
    };
    let approval = infra.approval(
        &w,
        &attacker,
        "attack-planted-guess",
        "the victim's address under a guessed account code, signed by a planted key the registry activated",
        &statement,
        &path,
    );
    let got = infra.check_auth(&w, &s.account, &s.email, attempt, Initiate, &approval);
    attack_row(
        "registry_planted_key_after_activation_without_account_code",
        "registry-planted-key-after-activation",
        1,
        "refused: ProofRejected",
        &verdict(got),
        "guardian check 12",
        "a planted key active after its 7-day timelock; the attacker's proof opens another commitment",
    );
    refused(
        &w,
        &infra,
        &s,
        &s.email,
        attempt,
        Initiate,
        &approval,
        EmailGuardianError::ProofRejected,
    );
    assert!(votes(&w, &s, attempt).is_empty());
}

/// Revoking a planted key once it is active cuts it off at once: an
/// approval under it that the guardian accepts (the attacker here also holds
/// the account code) is refused from the revocation's ledger.
#[test]
fn registry_revoked_active_key() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "attack-revoked";
    let s = enroll(&w, &infra, label, Profile::Loss, 1, 2, &gmail(label));
    let planted = plant_and_activate(&w, &infra);
    let (attempt, _) = begin(&w, &s, label);
    let statement = w.statement(&s.account, attempt, Initiate);
    let path = infra.registry_path(&w, &planted);
    let holder = EmailGuardian {
        inbox: s.email.inbox.clone().signed_by("gmail-previous"),
        ..s.email.clone()
    };
    let approval = infra.approval(
        &w,
        &holder,
        "attack-revoked-active",
        "an approval under a planted key the registry activated, with the account code",
        &statement,
        &path,
    );
    assert_eq!(
        infra.check_auth(&w, &s.account, &s.email, attempt, Initiate, &approval),
        Ok(())
    );
    let kh = BytesN::from_array(&w.env, &planted.key_hash());
    infra.registry.revoke(&w, "gmail.com", &kh);
    let got = infra.check_auth(&w, &s.account, &s.email, attempt, Initiate, &approval);
    attack_row(
        "registry_revoked_active_key",
        "registry-revoked-active-key",
        1,
        "refused: UnknownRoot",
        &verdict(got),
        "guardian check 11 (registry: revocation)",
        "accepted before; two members revoke the key; refused in the revocation's ledger",
    );
    refused(
        &w,
        &infra,
        &s,
        &s.email,
        attempt,
        Initiate,
        &approval,
        EmailGuardianError::UnknownRoot,
    );
}

/// A superseded root stays acceptable through its grace period, inclusive,
/// and is refused one ledger after it.
#[test]
fn registry_grace_expiry() {
    let w = world();
    let infra = EmailInfra::new(&w);
    let registry = infra.registry.client(&w);
    let label = "attack-grace";
    let s = enroll(&w, &infra, label, Profile::Loss, 1, 2, &gmail(label));
    let previous_root = infra.root.clone();
    // Another key activates through the attested path: the launch root is superseded at `superseded`.
    let id = infra
        .registry
        .propose_attested_key(&w, &provider_key("gmail.com", "gmail-previous"));
    w.advance(TIMELOCK_ATTESTED_LEDGERS);
    registry.execute(&id);
    let superseded = w.ledger();
    assert!(registry.is_accepted_root(&previous_root));
    // An attempt late in the grace period, proven against the previous root.
    w.advance(REGISTRY_GRACE - 50);
    let (attempt, _) = begin(&w, &s, label);
    let statement = w.statement(&s.account, attempt, Initiate);
    let approval = infra.approval(
        &w,
        &s.email,
        "attack-grace",
        "an approval proven against a superseded root, near the end of its grace period",
        &statement,
        &KeyPath::of(&EmailInfra::launch_leaves(), 0),
    );
    w.advance(superseded + REGISTRY_GRACE - w.ledger());
    assert_eq!(
        infra.check_auth(&w, &s.account, &s.email, attempt, Initiate, &approval),
        Ok(())
    );
    w.advance(1);
    let got = infra.check_auth(&w, &s.account, &s.email, attempt, Initiate, &approval);
    attack_row(
        "registry_grace_expiry",
        "registry-grace-expiry",
        1,
        "refused: UnknownRoot",
        &verdict(got),
        "guardian check 11 (registry: grace)",
        "accepted on the last ledger of the 17,280-ledger grace; refused on the next",
    );
    refused(
        &w,
        &infra,
        &s,
        &s.email,
        attempt,
        Initiate,
        &approval,
        EmailGuardianError::UnknownRoot,
    );
}
