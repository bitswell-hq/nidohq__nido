//! The chain side of the alert service's end-to-end test
//! (`infra/email-alerts/test/e2e.test.ts`), on Nido's stack: Perch's
//! controller and account from their deployed wasm, the email guardian and
//! the enclave-image registry from their wasm, enforcing authorization.
//!
//! The test runs the registry's approval of the vault's enclave image (two
//! of three signers, the 14-day timelock, activation) and a lost-key
//! recovery of an account whose recovery lists an email guardian (begin, the
//! email approval, a second guardian's approval, the delay, completion). It
//! records every event the registry and the controller emit, as Stellar
//! RPC's `getEvents` returns them, and the account's `installed_rules()`
//! before and after the recovery, as `simulateTransaction` returns them.
//! The alert service's test replays exactly these.
//!
//! The record is `infra/email-alerts/test/fixtures/chain.json`. This test
//! fails if the chain no longer produces it; `NIDO_ALERT_FIXTURE=write`
//! rewrites it.

use nido_email_guardian::ALLOW_ALL;
use nido_enclave_image_registry::{EnclaveImageRegistryClient, TIMELOCK_LEDGERS};
use nido_integration_tests::email::EmailInfra;
use nido_integration_tests::email_proof::Inbox;
use nido_integration_tests::world::{
    contract_at, strkey, world, Account, Mode, Passkey, Profile, Recovery, World, DELAY, EXPIRY,
    NETWORK,
};
use nido_integration_tests::ENCLAVE_IMAGE_REGISTRY_WASM;
use perch_recovery::EvidenceDomain::Initiate;
use perch_recovery_interface::RecoveryAction;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};
use soroban_sdk::testutils::Events as _;
use soroban_sdk::xdr::{ContractEventBody, Limits, ScVal, WriteXdr};
use soroban_sdk::{vec, Address, BytesN, IntoVal, TryFromVal};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../infra/email-alerts/test/fixtures/chain.json"
);

/// The TEST-ONLY vault image of `@nidohq/email-mocks`' `testImage`: each PCR
/// is `SHA384("<label>/pcrN")`; the measurement is
/// `sha256("nido/email-recovery/v1/enclave-image" || PCR0 || PCR1 || PCR2)`.
fn image_measurement(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"nido/email-recovery/v1/enclave-image");
    for i in 0..3 {
        h.update(Sha384::digest(format!("{label}/pcr{i}")));
    }
    h.finalize().into()
}

/// Events as `getEvents` returns them, collected after each invocation.
struct Recorder {
    events: Vec<Value>,
    tx: u32,
}

impl Recorder {
    fn take(&mut self, w: &World) {
        let ledger = w.ledger();
        self.tx += 1;
        let tx_hash = hex::encode(Sha256::digest(format!("nido-it/alerts/tx/{}", self.tx)));
        for (index, ev) in w.env.events().all().events().iter().enumerate() {
            let ContractEventBody::V0(body) = &ev.body;
            let id = ev.contract_id.as_ref().expect("a contract event").0 .0;
            let contract = soroban_sdk::address_payload::AddressPayload::ContractIdHash(
                BytesN::from_array(&w.env, &id),
            )
            .to_address(&w.env);
            let toid = (u64::from(ledger) << 32) | (u64::from(self.tx) << 12);
            self.events.push(json!({
                "type": "contract",
                "ledger": ledger,
                "contractId": strkey(&contract),
                "id": format!("{toid:019}-{index:010}"),
                "operationIndex": 0,
                "transactionIndex": self.tx - 1,
                "topic": body.topics.iter().map(|t| t.to_xdr_base64(Limits::none()).unwrap()).collect::<Vec<_>>(),
                "value": body.data.to_xdr_base64(Limits::none()).unwrap(),
                "txHash": tx_hash,
            }));
        }
    }
}

/// `installed_rules()` as `simulateTransaction` returns it: the result `ScVal`, base64 XDR.
fn installed_rules(w: &World, account: &Account) -> String {
    let rules: soroban_sdk::Val = w.account(account).installed_rules().into_val(&w.env);
    ScVal::try_from_val(&w.env, &rules)
        .unwrap()
        .to_xdr_base64(Limits::none())
        .unwrap()
}

/// The vault image's approval in the registry: 2-of-3 signers, the
/// timelock, activation.
fn approve_vault_image(w: &World, rec: &mut Recorder) -> (Address, BytesN<32>) {
    let signers: Vec<Address> = (0..3)
        .map(|i| contract_at(&w.env, &format!("alerts/registry-signer-{i}")))
        .collect();
    let registry = contract_at(&w.env, "alerts/enclave-image-registry");
    w.env.register_at(
        &registry,
        ENCLAVE_IMAGE_REGISTRY_WASM,
        (
            vec![
                &w.env,
                signers[0].clone(),
                signers[1].clone(),
                signers[2].clone(),
            ],
            2u32,
        ),
    );
    let measurement = BytesN::from_array(&w.env, &image_measurement("nido-alert-vault-v1"));
    let reg = EnclaveImageRegistryClient::new(&w.env, &registry);
    w.env.mock_all_auths();
    reg.approve(&signers[0], &measurement);
    rec.take(w);
    reg.approve(&signers[1], &measurement);
    rec.take(w);
    w.advance(TIMELOCK_LEDGERS);
    reg.activate(&measurement);
    rec.take(w);
    assert!(reg.is_active(&measurement));
    w.env.set_auths(&[]);

    (registry, measurement)
}

/// Topic 0 of each recorded event.
fn event_names(events: &[Value]) -> Vec<String> {
    events
        .iter()
        .map(|e| {
            let t0 = &e["topic"][0];
            let v = <ScVal as soroban_sdk::xdr::ReadXdr>::from_xdr_base64(
                t0.as_str().unwrap(),
                Limits::none(),
            )
            .unwrap();
            match v {
                ScVal::Symbol(s) => s.to_string(),
                other => format!("{other:?}"),
            }
        })
        .collect()
}

#[test]
fn alert_fixture_matches_the_chain() {
    let w = world();
    let mut rec = Recorder {
        events: Vec::new(),
        tx: 0,
    };

    let (registry, measurement) = approve_vault_image(&w, &mut rec);

    // An account whose recovery lists its email guardian and one friend,
    // quorum 2, under `Loss`.
    let label = "alerts";
    let infra = EmailInfra::new(&w);
    let owner = Passkey::labelled(&format!("{label}/owner"));
    let account = w.mint(
        label,
        owner.clone(),
        std::vec![("device", Passkey::labelled(&format!("{label}/device")))],
    );
    let inbox = Inbox::new(label, "alerts.user@gmail.com", Some("Test User"));
    let email = infra.guardian(&w, &account, label, &inbox, ALLOW_ALL);
    let friend = w.guardian(
        &format!("{label}/friend"),
        Passkey::labelled(&format!("{label}/friend")),
    );
    let recovery = Recovery {
        profile: Profile::Loss,
        mode: Mode::Guardian,
        guardians: std::vec![email.address.clone(), friend.address.clone()],
        quorum: 2,
        enrollment: None,
        baseline: None,
        replaceable: std::vec!["owner"],
        delay: DELAY,
        expiry: EXPIRY,
        max_cancels: 3,
    };
    w.apply(&account, &w.doc(&account, Some(recovery)), 0)
        .expect("enrollment");
    rec.take(&w);
    let rules_before = installed_rules(&w, &account);
    let setup_events = rec.events.len();

    // The recovery: begin, the email approval, the friend's approval, the
    // delay, completion.
    w.advance(10);
    let new_owner = Passkey::labelled(&format!("{label}/new-owner"));
    let replacements = w.replacements(&new_owner, None);
    let source = w.account(&account).applied_doc().unwrap();
    let attempt = w.begin_lost_key(&account, &replacements).unwrap();
    rec.take(&w);
    let target = w.target_bytes(&account, RecoveryAction::LostKey, &source, &replacements);
    w.advance(1);
    let approval = infra.registry_approval(
        &w,
        &email,
        "alerts",
        "the email approval of the recovery the alert fixture records",
        &w.statement(&account, attempt, Initiate),
    );
    infra
        .try_submit(&w, &account, &email, attempt, Initiate, &approval)
        .expect("the email approval");
    rec.take(&w);
    w.advance(1);
    w.try_guardian(&account, &friend, attempt, Initiate)
        .unwrap();
    rec.take(&w);
    let authorized_at = w.ledger();
    w.advance(DELAY);
    w.complete(&account, &target).expect("completion");
    rec.take(&w);
    let rules_after = installed_rules(&w, &account);

    let names = event_names(&rec.events[setup_events..]);
    assert!(names.contains(&"attempt_begun".into()));
    assert!(names.contains(&"attempt_authorized".into()));
    assert!(names.contains(&"recovery_completed".into()));

    let fixture = json!({
        "about": "Recorded by crates/integration-tests/tests/it/email_alerts.rs; regenerate with NIDO_ALERT_FIXTURE=write. TEST-ONLY keys.",
        "networkPassphrase": NETWORK,
        "controller": strkey(&w.controller),
        "registry": strkey(&registry),
        "account": strkey(&account.address),
        "measurement": hex::encode(measurement.to_array()),
        "ownerPrivateKey": hex::encode(owner.key.to_bytes()),
        "ownerPublicKey": hex::encode(owner.pubkey()),
        "newOwnerPublicKey": hex::encode(new_owner.pubkey()),
        "attemptId": attempt.to_string(),
        "authorizedAtLedger": authorized_at,
        "setupEvents": setup_events,
        "events": rec.events,
        "installedRules": { "before": rules_before, "after": rules_after },
    });
    let text = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    if std::env::var("NIDO_ALERT_FIXTURE").as_deref() == Ok("write") {
        std::fs::write(FIXTURE, &text).unwrap();
    }
    let committed = std::fs::read_to_string(FIXTURE).expect(
        "infra/email-alerts/test/fixtures/chain.json; run with NIDO_ALERT_FIXTURE=write to create it",
    );
    assert!(
        committed == text,
        "the chain no longer produces the alert fixture; rerun with NIDO_ALERT_FIXTURE=write and review the diff"
    );
}
