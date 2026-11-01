//! One real email approval per launch domain, on Perch's controller with
//! the real DKIM key registry and the real verifier, all from their wasm.
//!
//! For each domain of the registry's allowlist, the provider mock of
//! `@nidohq/email-mocks` signs a recovery email from an inbox at that domain
//! (its TEST-ONLY key and signing format), and the committed proof
//! `fixtures/email/provider-<domain>/` proves it against the registry's
//! root, which holds every launch key admitted through the attested path.
//! `long_address_at_web_de_counts_one_vote` does the same for an address of
//! the longest length the spec allows (124 bytes) with a long display name,
//! at the provider whose signed header block is largest (WEB.DE signs the
//! address twice). Each test shows:
//!
//! - the verifier accepts the proof for the public inputs the guardian
//!   builds, and refuses it with any one of them changed;
//! - `submit_guardian` carrying the approval counts it as exactly one
//!   guardian vote.
//!
//! and prints the resources of that `submit_guardian` (one JSON object per
//! provider; `-- --nocapture`) two ways:
//!
//! - `host`: the test host's `cost_estimate()` for the invocation, under the
//!   SDK's mainnet resource limits, which the host enforces on every
//!   invocation (400,000,000 instructions);
//! - `tx`: the same call re-executed as a transaction by
//!   [`nido_integration_tests::transaction::measure`] (a fresh host over a
//!   ledger snapshot, the signed authorization entry enforced, so the
//!   guardian's `__check_auth` and the proof verification run), with the
//!   recorded footprint, the signed envelope's size, and its resource fee
//!   without rent.

use nido_email_guardian::ALLOW_ALL;
use nido_integration_tests::email::EmailInfra;
use nido_integration_tests::email_proof::{public_inputs, Inbox};
use nido_integration_tests::transaction;
use nido_integration_tests::world::{world, Mode, Passkey, Profile, Recovery, DELAY, EXPIRY};
use perch_recovery::EvidenceDomain::Initiate;
use perch_recovery_interface::zk::{ProofVerifierClient, ProofVerifierError};
use soroban_sdk::xdr::{Limits, WriteXdr};
use soroban_sdk::Bytes;

/// The approval of a lost-key attempt by an inbox at `domain`, checked by
/// the verifier directly, then submitted and measured.
fn provider_approval_counts_one_vote(domain: &str, display_name: Option<&str>) {
    let label = format!("provider-{}", domain.replace('.', "-"));
    approval_counts_one_vote(&label, &format!("first.last@{domain}"), display_name);
}

/// [`provider_approval_counts_one_vote`] for any address; `label` names the
/// fixture.
#[allow(clippy::too_many_lines)] // one approval's whole flow, in order
fn approval_counts_one_vote(label: &str, address: &str, display_name: Option<&str>) {
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = label.to_string();
    let inbox = Inbox::new(&label, address, display_name);
    let domain = inbox.domain().to_string();
    let account = w.mint(
        &label,
        Passkey::labelled(&format!("{label}/owner")),
        vec![("device", Passkey::labelled(&format!("{label}/device")))],
    );
    let email = infra.guardian(&w, &account, &label, &inbox, ALLOW_ALL);
    let friends: Vec<_> = (0..2)
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
        profile: Profile::Loss,
        mode: Mode::Guardian,
        guardians,
        quorum: 2,
        enrollment: None,
        baseline: None,
        replaceable: vec!["owner"],
        delay: DELAY,
        expiry: EXPIRY,
        max_cancels: 3,
    };
    w.apply(&account, &w.doc(&account, Some(recovery)), 0)
        .expect("enrollment with the email guardian");

    let new_owner = Passkey::labelled(&format!("{label}/new-owner"));
    let replacements = w.replacements(&new_owner, None);
    let attempt = w
        .begin_lost_key(&account, &replacements)
        .expect("permissionless begin");
    let statement = w.statement(&account, attempt, Initiate);
    let approval = infra.registry_approval(
        &w,
        &email,
        &label,
        &format!("a lost-key approval emailed from {address}"),
        &statement,
    );

    // The verifier on its own: the guardian's public inputs, then each one
    // changed in its lowest bit.
    let verifier = ProofVerifierClient::new(&w.env, &infra.verifier);
    let digest = w.digest(&statement).to_array();
    let inputs = public_inputs(
        &email.commitment.to_array(),
        &digest,
        &infra.root.to_array(),
    );
    let blob = |x: &[[u8; 32]; 4]| Bytes::from_slice(&w.env, &x.concat());
    verifier.verify_proof(&blob(&inputs), &approval.proof);
    for i in 0..4 {
        let mut tampered = inputs;
        tampered[i][31] ^= 1;
        assert_eq!(
            verifier.try_verify_proof(&blob(&tampered), &approval.proof),
            Err(Ok(ProofVerifierError::VerificationFailed)),
            "public input {i} changed"
        );
    }

    // submit_guardian with the approval: one vote of the 2-of-3 quorum.
    let digest = w.digest(&statement);
    let root = w.invocation(&w.controller, "submit_guardian", vec![w.sc(digest)]);
    let entry = infra.entry(&w, &email, root, &approval);
    let entry_bytes = entry.to_xdr(Limits::none()).unwrap().len();
    let tx = transaction::measure(
        &w,
        &w.controller,
        "submit_guardian",
        vec![
            w.sc(account.address.clone()),
            w.sc(attempt),
            w.sc(Initiate),
            w.sc(email.address.clone()),
        ],
        vec![entry.clone()],
    );
    w.with_auths(&[entry], || {
        w.ctl()
            .submit_guardian(&account.address, &attempt, &Initiate, &email.address);
    });
    let r = w.env.cost_estimate().resources();
    let fee = w.env.cost_estimate().fee();
    let fp = &tx.resources.footprint;
    println!(
        "{{\"case\":\"submit_guardian with an email approval\",\"label\":\"{label}\",\"domain\":\"{domain}\",\"address_bytes\":{},\"host\":{{\"instructions\":{},\"mem_bytes\":{},\"read_entries\":{},\"disk_read_entries\":{},\"write_entries\":{},\"disk_read_bytes\":{},\"write_bytes\":{},\"events_bytes\":{},\"fee_no_rent\":{}}},\"tx\":{{\"instructions\":{},\"read_only\":{},\"read_write\":{},\"disk_read_bytes\":{},\"write_bytes\":{},\"auth_entry_bytes\":{entry_bytes},\"envelope_bytes\":{},\"events_and_return_bytes\":{},\"fee_no_rent\":{}}}}}",
        address.len(),
        r.instructions,
        r.mem_bytes,
        r.memory_read_entries + r.disk_read_entries,
        r.disk_read_entries,
        r.write_entries,
        r.disk_read_bytes,
        r.write_bytes,
        r.contract_events_size_bytes,
        fee.total - fee.persistent_entry_rent - fee.temporary_entry_rent,
        tx.resources.instructions,
        fp.read_only.len(),
        fp.read_write.len(),
        tx.resources.disk_read_bytes,
        tx.resources.write_bytes,
        tx.envelope_bytes,
        tx.events_and_return_bytes,
        tx.non_refundable_fee + tx.refundable_fee,
    );
    assert!(
        r.instructions < 400_000_000 && i64::from(tx.resources.instructions) < 400_000_000,
        "within the network's per-transaction instruction limit"
    );
    let votes: Vec<_> = w
        .ctl()
        .attempt(&account.address, &attempt)
        .unwrap()
        .guardians
        .iter()
        .collect();
    assert_eq!(votes, vec![email.address.clone()], "exactly one vote");
    assert_eq!(
        w.ctl().activity_gate(&account.address).authorized_attempt,
        None,
        "one vote of a 2-of-3 quorum"
    );
}

macro_rules! providers {
    ($($name:ident => $domain:literal, $display:expr;)*) => {
        $(
            #[test]
            fn $name() {
                provider_approval_counts_one_vote($domain, $display);
            }
        )*
    };
}

/// The longest address the spec allows, 124 bytes, with a 299-byte display
/// name, at WEB.DE.
#[test]
fn long_address_at_web_de_counts_one_vote() {
    let local = "firstname.middlename.lastname.0123456789.abcdefghij.klmnopqrst.uvwxyz.0123456789.abcdefghij.klmnopqrst.uvwxyz.0123456";
    let address = format!("{local}@web.de");
    assert_eq!(address.len(), 124);
    let name = "Firstname Middlename Lastname ".repeat(10);
    let name = name.trim_end();
    assert_eq!(name.len(), 299);
    approval_counts_one_vote("long-address-web-de", &address, Some(name));
}

providers! {
    gmail_com_approval_counts_one_vote => "gmail.com", Some("First Last");
    outlook_com_approval_counts_one_vote => "outlook.com", Some("First Last");
    hotmail_com_approval_counts_one_vote => "hotmail.com", None;
    icloud_com_approval_counts_one_vote => "icloud.com", Some("First Last");
    yahoo_com_approval_counts_one_vote => "yahoo.com", Some("First Last");
    proton_me_approval_counts_one_vote => "proton.me", Some("First Last");
    protonmail_com_approval_counts_one_vote => "protonmail.com", None;
    fastmail_com_approval_counts_one_vote => "fastmail.com", Some("First Last");
    gmx_net_approval_counts_one_vote => "gmx.net", Some("First Last");
    gmx_de_approval_counts_one_vote => "gmx.de", None;
    web_de_approval_counts_one_vote => "web.de", Some("First Last");
}

/// The registry's allowlist and the committed provider keys agree, and the
/// harness's native commitment is the circuit's and the encoder's: the
/// vector `circuits/email-recovery/tests/src/recovery_tests.nr` and
/// `packages/email-recovery/test/recoveryInputs.test.ts` also pin.
#[test]
fn the_fixture_keys_and_hashing_match_the_circuit() {
    let keys = nido_integration_tests::email_proof::provider_keys();
    let current: Vec<&str> = keys
        .iter()
        .filter(|k| k.signer == "current")
        .map(|k| k.domain.as_str())
        .collect();
    assert_eq!(current, nido_dkim_registry::LAUNCH_DOMAINS.to_vec());
    for k in &keys {
        assert_eq!(k.modulus()[0] & 0x80, 0x80, "{}: an RSA-2048 key", k.domain);
    }
    let mut code = [0u8; 32];
    for (i, b) in code[16..].iter_mut().enumerate() {
        *b = u8::try_from(i + 1).unwrap();
    }
    assert_eq!(
        hex::encode(nido_integration_tests::email_proof::commitment(
            "alice.example@gmail.com",
            &code
        )),
        "2c0e895ffe502297a6cf6881711fd974dec6e17f396b4c56977781fd07d5b73c"
    );
}
