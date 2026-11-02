//! An email-factor recovery after every ledger entry it reads has been
//! archived: the account enrolled, then left untouched for longer than the
//! network's maximum entry lifetime, so that Perch's contracts, the account,
//! its email guardian and helper, the verifier, the DKIM key registry and
//! all their code are archived when recovery starts.
//!
//! The flow is `email_proofs`' Gmail approval (the same world, labels and
//! committed proof `fixtures/email/provider-gmail-com/`), carried on to the
//! helper's vote, the delay and completion. After enrollment every entry the
//! ledger holds is taken as archived. Before each step runs in the world,
//! [`transaction::measure_archived`] re-executes it over the ledger with
//! every entry not yet restored by an earlier step archived, under mainnet's
//! settings (`research/email-recovery/eval/results/settings/mainnet.json`:
//! its cost model and entry lifetimes), and records what the host restores
//! as the step runs, with each entry's size and every rent change; and the
//! same step with nothing archived (`live`), under the same settings.
//!
//! With `NIDO_EMAIL_ARCHIVAL_OUT` set, the readings are written there as JSON
//! (`research/email-recovery/eval/archival.sh`), which
//! `research/email-recovery/eval/report.mjs` prices at mainnet's fees and
//! fits to mainnet's per-transaction limits.

use std::collections::BTreeSet;
use std::path::Path;

use nido_email_guardian::ALLOW_ALL;
use nido_integration_tests::email::EmailInfra;
use nido_integration_tests::email_proof::Inbox;
use nido_integration_tests::transaction::{self, Archived, NetworkSettings};
use nido_integration_tests::world::{
    world, Mode, Passkey, Profile, Recovery, World, DELAY, EXPIRY,
};
use perch_recovery::EvidenceDomain::Initiate;
use perch_recovery_interface::RecoveryAction;
use serde_json::{json, Value};
use soroban_sdk::xdr::{LedgerKey, Limits, WriteXdr};

const SETTINGS: &str = "../../research/email-recovery/eval/results/settings/mainnet.json";
const TESTNET_SETTINGS: &str = "../../research/email-recovery/eval/results/settings/testnet.json";

fn key_xdr(k: &LedgerKey) -> Vec<u8> {
    k.to_xdr(Limits::none()).unwrap()
}

/// A ledger key in a few words, as the evaluation's network records name them.
fn describe(w: &World, names: &[(&soroban_sdk::Address, &str)], k: &LedgerKey) -> String {
    match k {
        LedgerKey::ContractData(d) => {
            let address = soroban_sdk::Address::try_from_val(&w.env, &d.contract).unwrap();
            let owner = names
                .iter()
                .find(|(a, _)| **a == address)
                .map_or_else(|| "a contract".to_string(), |(_, n)| (*n).to_string());
            let what = match &d.key {
                soroban_sdk::xdr::ScVal::LedgerKeyContractInstance => "instance".to_string(),
                other => format!("{other:?}").chars().take(40).collect(),
            };
            format!(
                "{owner} {} {what}",
                if d.durability == soroban_sdk::xdr::ContractDataDurability::Persistent {
                    "persistent"
                } else {
                    "temporary"
                }
            )
        }
        LedgerKey::ContractCode(c) => format!("code {}", hex::encode(&c.hash.0[..4])),
        other => format!("{:?}", other.discriminant()),
    }
}

pub(crate) fn reading(
    w: &World,
    names: &[(&soroban_sdk::Address, &str)],
    step: &str,
    a: &Archived,
) -> Value {
    let r = &a.measured.resources;
    json!({
        "step": step,
        "ledger": a.ledger,
        "instructions": r.instructions,
        "diskReadBytes": r.disk_read_bytes,
        "writeBytes": r.write_bytes,
        "readOnly": r.footprint.read_only.len(),
        "readWrite": r.footprint.read_write.len(),
        "envelopeBytes": a.measured.envelope_bytes,
        "eventsBytes": a.measured.events_and_return_bytes,
        "restored": a.restored.iter().map(|e| json!({
            "key": describe(w, names, &e.key),
            "keyXdr": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_xdr(&e.key)),
            "code": matches!(e.key, LedgerKey::ContractCode(_)),
            "xdrBytes": e.xdr_bytes,
            "rentBytes": e.rent_bytes,
            "removed": e.removed,
        })).collect::<Vec<_>>(),
        "rentChanges": a.rent_changes.iter().map(|c| json!({
            "key": describe(w, names, &c.key),
            "keyXdr": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key_xdr(&c.key)),
            "persistent": c.persistent,
            "code": c.code,
            "oldSize": c.old_size,
            "newSize": c.new_size,
            "oldLiveUntil": c.old_live_until,
            "newLiveUntil": c.new_live_until,
        })).collect::<Vec<_>>(),
    })
}

use soroban_sdk::TryFromVal;

#[test]
#[allow(clippy::too_many_lines)] // one recovery's whole flow, in order
fn everything_archived_recovery() {
    let settings = NetworkSettings::read(Path::new(SETTINGS));
    // `email_proofs`' Gmail approval, step for step, so its fixture applies.
    let w = world();
    let infra = EmailInfra::new(&w);
    let label = "provider-gmail-com".to_string();
    let address = "first.last@gmail.com";
    let inbox = Inbox::new(&label, address, Some("First Last"));
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
        controller: w.controller.clone(),
        pool: w.pool.clone(),
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

    // Every entry the ledger holds now is archived when recovery starts.
    let at_rest: BTreeSet<Vec<u8>> = w
        .env
        .to_ledger_snapshot()
        .ledger_entries
        .iter()
        .map(|(k, _)| key_xdr(k))
        .collect();
    let mut restored: BTreeSet<Vec<u8>> = BTreeSet::new();
    let names = [
        (&w.controller, "recovery controller"),
        (&w.compiler, "doc compiler"),
        (&w.verifier, "WebAuthn verifier"),
        (&w.factory, "factory"),
        (&account.address, "account"),
        (&email.address, "email guardian"),
        (&infra.verifier, "email verifier"),
        (&infra.registry.address, "DKIM key registry"),
        (&friends[0].address, "helper"),
        (&friends[1].address, "second helper"),
    ];
    let mut steps = Vec::new();
    let mut live = Vec::new();
    let mut step = |name: &str,
                    contract: &soroban_sdk::Address,
                    function: &str,
                    args: Vec<soroban_sdk::xdr::ScVal>,
                    auth: Vec<soroban_sdk::xdr::SorobanAuthorizationEntry>,
                    restored: &mut BTreeSet<Vec<u8>>| {
        let archived = |k: &LedgerKey| {
            let x = key_xdr(k);
            at_rest.contains(&x) && !restored.contains(&x)
        };
        // The same step with nothing archived, under the same settings.
        let l = transaction::measure_archived(
            &w,
            contract,
            function,
            args.clone(),
            auth.clone(),
            &|_| false,
            &settings,
        );
        live.push(reading(&w, &names, name, &l));
        let a =
            transaction::measure_archived(&w, contract, function, args, auth, &archived, &settings);
        restored.extend(a.restored.iter().map(|e| key_xdr(&e.key)));
        steps.push(reading(&w, &names, name, &a));
    };

    let new_owner = Passkey::labelled(&format!("{label}/new-owner"));
    let replacements = w.replacements(&new_owner, None);
    let source = w.account(&account).applied_doc().unwrap();
    step(
        "begin_lost_key",
        &w.controller,
        "begin_lost_key",
        vec![w.sc(account.address.clone()), w.sc(replacements.clone())],
        vec![],
        &mut restored,
    );
    let attempt = w
        .begin_lost_key(&account, &replacements)
        .expect("permissionless begin");
    let target = w.target_bytes(&account, RecoveryAction::LostKey, &source, &replacements);

    let statement = w.statement(&account, attempt, Initiate);
    let approval = infra.registry_approval(
        &w,
        &email,
        &label,
        &format!("a lost-key approval emailed from {address}"),
        &statement,
    );
    let digest = w.digest(&statement);
    let vote_args = |guardian: &soroban_sdk::Address| {
        vec![
            w.sc(account.address.clone()),
            w.sc(attempt),
            w.sc(Initiate),
            w.sc(guardian.clone()),
        ]
    };
    let root = w.invocation(&w.controller, "submit_guardian", vec![w.sc(digest.clone())]);
    let entry = infra.entry(&w, &email, root.clone(), &approval);
    // The same vote with nothing archived, metered by this host under its
    // built-in cost model and under mainnet's and testnet's.
    let metered_under = |s: &NetworkSettings| {
        transaction::measure_archived(
            &w,
            &w.controller,
            "submit_guardian",
            vote_args(&email.address),
            vec![entry.clone()],
            &|_| false,
            s,
        )
        .measured
        .resources
        .instructions
    };
    let metering = json!({
        "builtIn": transaction::measure(&w, &w.controller, "submit_guardian", vote_args(&email.address), vec![entry.clone()]).resources.instructions,
        "mainnet": metered_under(&settings),
        "testnet": metered_under(&NetworkSettings::read(Path::new(TESTNET_SETTINGS))),
    });
    step(
        "submit_guardian (email)",
        &w.controller,
        "submit_guardian",
        vote_args(&email.address),
        vec![entry.clone()],
        &mut restored,
    );
    w.with_auths(&[entry], || {
        w.ctl()
            .submit_guardian(&account.address, &attempt, &Initiate, &email.address);
    });

    let helper = w.signed(&friends[0], "owner", "guardian", root);
    step(
        "submit_guardian (helper)",
        &w.controller,
        "submit_guardian",
        vote_args(&friends[0].address),
        vec![helper],
        &mut restored,
    );
    w.try_guardian(&account, &friends[0], attempt, Initiate)
        .expect("the helper's vote");
    assert!(
        w.ctl()
            .activity_gate(&account.address)
            .authorized_attempt
            .is_some(),
        "two votes authorize the attempt"
    );

    w.advance(DELAY);
    let root = w.invocation(
        &account.address,
        "apply_doc",
        vec![w.sc(target.clone()), w.sc(0u32), w.sc(None::<u64>)],
    );
    let entry = w.recovery_rule_entry(&account.address, root);
    step(
        "complete (apply_doc)",
        &account.address,
        "apply_doc",
        vec![w.sc(target.clone()), w.sc(0u32), w.sc(None::<u64>)],
        vec![entry],
        &mut restored,
    );
    w.complete(&account, &target).expect("completion");

    let out = json!({
        "about": "Generated by crates/integration-tests/tests/it/email_archival.rs (research/email-recovery/eval/archival.sh).",
        "settings": "research/email-recovery/eval/results/settings/mainnet.json",
        "costModel": { "networkCostTypes": settings.network_cost_types, "hostCostTypes": soroban_sdk::xdr::ContractCostType::variants().len(), "host": "soroban-env-host 27.0.1" },
        "entriesAtRest": at_rest.len(),
        "emailVoteMetering": metering,
        "steps": steps,
        "live": live,
    });
    let restored_total: usize = out["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["restored"].as_array().unwrap().len())
        .sum();
    assert!(restored_total > 0, "the recovery restores what it reads");
    if let Ok(path) = std::env::var("NIDO_EMAIL_ARCHIVAL_OUT") {
        std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    } else {
        println!("{out}");
    }
}
