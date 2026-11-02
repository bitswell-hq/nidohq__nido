//! An account's move to a new email guardian: the step a fix of the email
//! circuit takes for each account (spec §8.7). A guardian names its verifier
//! and `circuit_id` for its lifetime, so a fixed circuit reaches an account
//! only through a new guardian that a new recovery document lists in place of
//! the old one.
//!
//! For each profile, an account enrolled with an email guardian and two
//! helpers at quorum 2 deploys a new guardian (the same commitment and
//! registry, a 30-day pin over the account's salt and Gmail's key, the fixed
//! circuit's verifier) and applies the document that lists it instead of the
//! old one: under `Loss` the owner's `apply_doc` alone; under `Protected`
//! once the two helpers' `approve_change` votes meet the recovery condition.
//! Each transaction is re-executed under mainnet's settings with nothing
//! archived ([`transaction::measure_host_function_archived`]); with
//! `NIDO_EMAIL_MIGRATION_OUT` set the readings are written there as JSON
//! (`research/email-recovery/eval/migration.sh`), which
//! `research/email-recovery/eval/report.mjs` prices at mainnet's fees.
//!
//! The fixed circuit's verifier is a second instance of the email verifier:
//! a fixed circuit has its own key, so its verifier is a new wasm, deployed
//! once for every account, of this one's size and cost.

use std::path::Path;

use nido_dkim_registry::hash::Hasher;
use nido_dkim_registry::root_of;
use nido_email_guardian::{GuardianConfig, KeyPin, ALLOW_ALL};
use nido_integration_tests::email::EmailInfra;
use nido_integration_tests::email_proof::{provider_key, Inbox};
use nido_integration_tests::transaction::{self, NetworkSettings};
use nido_integration_tests::world::{
    contract_at, world, Mode, Passkey, Profile, Recovery, DELAY, EXPIRY,
};
use nido_integration_tests::{EMAIL_GUARDIAN_WASM, EMAIL_VERIFIER_WASM};
use perch_recovery_interface::statement::ConfigChange;
use perch_recovery_interface::StatementSubject;
use serde_json::{json, Value};
use soroban_sdk::xdr::{
    ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress, CreateContractArgsV2,
    Hash, HostFunction, ScAddress, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, Uint256,
};
use soroban_sdk::{BytesN, Vec};

use crate::email_archival::reading;

const SETTINGS: &str = "../../research/email-recovery/eval/results/settings/mainnet.json";

/// The wallet's source, which defines its pin lifetime once.
const WALLET_PIN_SOURCE: &str =
    include_str!("../../../../packages/email-recovery/src/enrollmentEmail.ts");

/// The wallet's pin lifetime (`PIN_LIFETIME_SECONDS`, spec §13 item 2), read
/// from its definition rather than copied.
fn pin_seconds() -> u64 {
    WALLET_PIN_SOURCE
        .split("export const PIN_LIFETIME_SECONDS = ")
        .nth(1)
        .and_then(|rest| rest.split(';').next())
        .map(|literal| literal.replace('_', ""))
        .and_then(|digits| digits.parse().ok())
        .expect("the wallet defines PIN_LIFETIME_SECONDS as an integer literal")
}

#[test]
fn pin_lifetime_is_the_wallets() {
    assert_eq!(pin_seconds(), 30 * 24 * 60 * 60);
}

#[allow(clippy::too_many_lines)] // one account's migration, step by step
fn migrate(profile: Profile, label: &str, salt: u8, settings: &NetworkSettings) -> Value {
    let w = world();
    let infra = EmailInfra::new(&w);
    let fixed_verifier = contract_at(&w.env, "email/verifier-fixed");
    w.env.register_at(&fixed_verifier, EMAIL_VERIFIER_WASM, ());

    let inbox = Inbox::new(label, "first.last@gmail.com", Some("First Last"));
    let account = w.mint(
        label,
        Passkey::labelled(&format!("{label}/owner")),
        vec![("device", Passkey::labelled(&format!("{label}/device")))],
    );
    let old = infra.guardian(&w, &account, label, &inbox, ALLOW_ALL);
    let friends: std::vec::Vec<_> = (0..2)
        .map(|i| {
            w.guardian(
                &format!("{label}/friend-{i}"),
                Passkey::labelled(&format!("{label}/friend-{i}")),
            )
        })
        .collect();
    let recovery = |email: &soroban_sdk::Address| {
        let mut guardians = vec![email.clone()];
        guardians.extend(friends.iter().map(|f| f.address.clone()));
        Recovery {
            profile,
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
        }
    };
    w.apply(&account, &w.doc(&account, Some(recovery(&old.address))), 0)
        .expect("enrollment with the email guardian");

    // The new guardian: the same commitment, a pin as the wallet builds it,
    // and the fixed circuit's verifier.
    let code = BytesN::from_array(&w.env, &inbox.account_code);
    let pin_salt = Hasher::new(&w.env).pin_salt(&code);
    let leaf = BytesN::from_array(&w.env, &provider_key("gmail.com", "current").leaf());
    let mut key_pin = Vec::new(&w.env);
    key_pin.push_back(KeyPin {
        root: root_of(&w.env, &[pin_salt, leaf]),
        valid_until: w.now() + pin_seconds(),
    });
    let config = GuardianConfig {
        account: account.address.clone(),
        controller: w.controller.clone(),
        commitment: old.commitment.clone(),
        registry: infra.registry.address.clone(),
        key_pin,
        allowed_actions: ALLOW_ALL,
        verifier: fixed_verifier.clone(),
        circuit_id: EmailInfra::circuit_id(&w),
    };

    let names = [
        (&w.controller, "recovery controller"),
        (&w.compiler, "doc compiler"),
        (&w.verifier, "WebAuthn verifier"),
        (&account.address, "account"),
        (&old.address, "old email guardian"),
        (&fixed_verifier, "fixed email verifier"),
        (&infra.registry.address, "DKIM key registry"),
        (&friends[0].address, "helper"),
        (&friends[1].address, "second helper"),
    ];
    let mut steps = std::vec::Vec::new();

    // 1. Deploy, from the wallet's submitter account, as the wallet does
    //    (spec §5.4 step 4).
    let wasm = w.env.deployer().upload_contract_wasm(EMAIL_GUARDIAN_WASM);
    let create = CreateContractArgsV2 {
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: ScAddress::Account(transaction::source_account()),
            salt: Uint256([salt; 32]),
        }),
        executable: ContractExecutable::Wasm(Hash(wasm.to_array())),
        constructor_args: vec![w.sc(config.clone())].try_into().unwrap(),
    };
    let submitter = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::CreateContractV2HostFn(create.clone()),
            sub_invocations: std::vec::Vec::new().try_into().unwrap(),
        },
    };
    let deployed = transaction::measure_host_function_archived(
        &w,
        HostFunction::CreateContractV2(create),
        vec![submitter],
        &|_| false,
        settings,
    );
    steps.push(reading(&w, &names, "deploy the new guardian", &deployed));
    let new = contract_at(&w.env, &format!("email-guardian/{label}/fixed"));
    w.env.register_at(&new, EMAIL_GUARDIAN_WASM, (config,));

    // 2. Under Protected, the recovery condition: both helpers approve the
    //    document's configuration.
    let doc = w.doc(&account, Some(recovery(&new)));
    let mut valid_until = 0;
    if profile == Profile::Protected {
        let subject = StatementSubject::Reconfigure(ConfigChange::Set(w.config_hash(&doc)));
        valid_until = w.ledger() + 50;
        let statement = w
            .ctl()
            .change_statement(&account.address, &subject, &valid_until);
        let digest = w.digest(&statement);
        for (i, friend) in friends.iter().enumerate() {
            let root = w.invocation(&w.controller, "approve_change", vec![w.sc(digest.clone())]);
            let entry = w.signed(friend, "owner", "guardian", root);
            let measured = transaction::measure_archived(
                &w,
                &w.controller,
                "approve_change",
                vec![
                    w.sc(account.address.clone()),
                    w.sc(subject.clone()),
                    w.sc(valid_until),
                    w.sc(friend.address.clone()),
                ],
                vec![entry],
                &|_| false,
                settings,
            );
            steps.push(reading(
                &w,
                &names,
                &format!("approve_change (helper {})", i + 1),
                &measured,
            ));
            w.try_approve_change(&account, friend, &subject, valid_until)
                .expect("the helper's approval");
        }
    }

    // 3. The owner applies the document that lists the new guardian.
    let bytes = doc.bytes(&w);
    let args = vec![w.sc(bytes), w.sc(valid_until), w.sc(None::<u64>)];
    let root = w.invocation(&account.address, "apply_doc", args.clone());
    let entry = w.signed(&account, "owner", "admin", root);
    let applied = transaction::measure_archived(
        &w,
        &account.address,
        "apply_doc",
        args,
        vec![entry],
        &|_| false,
        settings,
    );
    steps.push(reading(&w, &names, "apply_doc (owner)", &applied));
    w.apply(&account, &doc, valid_until)
        .expect("the document listing the new guardian");

    let config = w.ctl().config(&account.address).unwrap();
    let guardians = &config.guardians().unwrap().guardians;
    assert!(guardians.contains(&new), "the new guardian is listed");
    assert!(!guardians.contains(&old.address), "the old one is not");
    json!({ "profile": format!("{profile:?}"), "steps": steps })
}

#[test]
fn moving_to_a_new_email_guardian() {
    let settings = NetworkSettings::read(Path::new(SETTINGS));
    let out = json!({
        "about": "Generated by crates/integration-tests/tests/it/email_migration.rs (research/email-recovery/eval/migration.sh).",
        "settings": "research/email-recovery/eval/results/settings/mainnet.json",
        "profiles": [
            migrate(Profile::Loss, "migration-loss", 1, &settings),
            migrate(Profile::Protected, "migration-protected", 2, &settings),
        ],
    });
    if let Ok(path) = std::env::var("NIDO_EMAIL_MIGRATION_OUT") {
        std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    } else {
        println!("{out}");
    }
}
