//! Connected apps on scoped documents, one per app origin, as the wallet
//! applies them (`packages/passkey-sdk/src/perch/scopes.ts`,
//! `packages/frontend/src/lib/policy/appScopes.ts`): the app's keys and
//! rules go to its origin's scope with `apply_scope`, the admin document
//! keeps the account's own rules, and removing the app is `remove_scope`.
//!
//! Everything runs from wasm under enforcing authorization: the owner signs
//! every scope change through the admin rule with a real passkey assertion,
//! and an app's call is decided by the account's own `__check_auth` with the
//! app key's real assertion.

use nido_integration_tests::world::{
    app_scope_candidates, app_signer_id, contract_at, strkey, world, Account, Mode, Passkey,
    Profile, TargetClient, World, DELAY, NETWORK,
};
use perch_account::PerchAccountError;
use perch_doc_compiler::DocCompilerError;
use perch_recovery::EvidenceDomain;
use perch_recovery_interface::RecoveryAction;
use perch_smart_account::PerchAuthError;
use serde_json::Value;
use soroban_sdk::auth::Context;
use soroban_sdk::{Address, Bytes, BytesN, IntoVal, Val, Vec};

const GAME: &str = "https://game.example";
const OTHER: &str = "https://other.example";

/// One rule of an app's scoped document: `name` on `contract`, only
/// `functions` when given, with an optional `(limit, period)` cap on
/// `transfer`'s amount, signed by any one of the document's keys at `keys`.
struct Grant<'a> {
    name: &'a str,
    contract: &'a Address,
    functions: Option<&'a [&'a str]>,
    cap: Option<(i128, u32)>,
    keys: &'a [usize],
}

/// `origin`'s scoped document as the wallet builds it: each of `keys` named
/// `<origin>#<k8>`, and one rule per grant (`all` for one key, `threshold`
/// with `m = 1` for several).
fn app_doc(w: &World, origin: &str, keys: &[&Passkey], grants: &[Grant]) -> Bytes {
    let verifier = strkey(&w.verifier);
    let ids: std::vec::Vec<String> = keys
        .iter()
        .map(|k| app_signer_id(origin, &k.pubkey()))
        .collect();
    let signers: std::vec::Vec<String> = keys
        .iter()
        .zip(&ids)
        .map(|(k, id)| {
            format!(
                r#"{{"id":"{id}","verifier":"{verifier}","key":"{}"}}"#,
                hex::encode(k.pubkey())
            )
        })
        .collect();
    let rules: std::vec::Vec<String> = grants
        .iter()
        .map(|g| {
            let named: std::vec::Vec<String> = g.keys.iter().map(|&i| format!(r#""{}""#, ids[i])).collect();
            let principals = if named.len() == 1 {
                format!(r#"{{"type":"all","signers":[{}]}}"#, named[0])
            } else {
                format!(r#"{{"type":"threshold","m":1,"signers":[{}]}}"#, named.join(","))
            };
            let functions = g
                .functions
                .map(|f| {
                    let quoted: std::vec::Vec<String> = f.iter().map(|n| format!(r#""{n}""#)).collect();
                    format!(r#","functions":[{}]"#, quoted.join(","))
                })
                .unwrap_or_default();
            let cap = g
                .cap
                .map(|(limit, period)| format!(r#","cap":{{"limit":"{limit}","period-ledgers":{period}}}"#))
                .unwrap_or_default();
            format!(
                r#"{{"name":"{}","scope":{{"type":"contract","address":"{}"}},"principals":{principals}{functions}{cap}}}"#,
                g.name,
                strkey(g.contract)
            )
        })
        .collect();
    let json = format!(
        r#"{{"version":1,"network":"{NETWORK}","signers":[{}],"rules":[{}]}}"#,
        signers.join(","),
        rules.join(",")
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// The one-rule grant most tests use: `guess` may call `Target::protected`.
fn guess<'a>(w: &'a World, keys: &'a [usize]) -> Grant<'a> {
    Grant {
        name: "guess",
        contract: &w.target,
        functions: Some(&["protected"]),
        cap: None,
        keys,
    }
}

/// `Target::protected(account)`, as an authorization context.
fn protected(w: &World, account: &Address) -> Context {
    w.context(
        &w.target,
        "protected",
        soroban_sdk::vec![&w.env, account.into_val(&w.env)],
    )
}

/// `token.transfer(account, to, amount)`, as an authorization context.
fn transfer(w: &World, token: &Address, account: &Address, amount: i128) -> Context {
    let to = contract_at(&w.env, "payee");
    let args: Vec<Val> = soroban_sdk::vec![
        &w.env,
        account.into_val(&w.env),
        to.into_val(&w.env),
        amount.into_val(&w.env)
    ];
    w.context(token, "transfer", args)
}

fn auth(e: PerchAuthError) -> Result<(), soroban_sdk::Error> {
    Err(soroban_sdk::Error::from_contract_error(e as u32))
}

fn refused(
    e: PerchAccountError,
) -> Result<BytesN<32>, Result<PerchAccountError, soroban_sdk::InvokeError>> {
    Err(Ok(e))
}

/// `key` calls `Target::protected` end to end through `rule`: the host
/// runs the account's `__check_auth` on the real assertion.
fn calls(w: &World, account: &Account, key: &Passkey, rule: u32) -> bool {
    let root = w.invocation(
        &w.target,
        "protected",
        std::vec![w.sc(account.address.clone())],
    );
    let entry = w.passkey_entry(&account.address, &[key], rule, root);
    w.with_auths(&[entry], || {
        TargetClient::new(&w.env, &w.target)
            .try_protected(&account.address)
            .is_ok()
    })
}

fn minted(w: &World, label: &str) -> Account {
    w.mint(
        label,
        Passkey::labelled(&format!("{label}/owner")),
        std::vec![],
    )
}

/// The wallet's scope ids and signer ids (`app-scope-ids.json`, which the
/// SDK's tests derive with Node's crypto) are the ones derived here.
#[test]
fn app_scope_ids_match_the_wallets() {
    let vectors: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/passkey-sdk/src/perch/testdata/app-scope-ids.json"
    )))
    .unwrap();
    for v in vectors["vectors"].as_array().unwrap() {
        let want: std::vec::Vec<u32> = v["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| u32::try_from(c.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(
            app_scope_candidates(v["origin"].as_str().unwrap()).to_vec(),
            want
        );
    }
    for s in vectors["signer_ids"].as_array().unwrap() {
        let key = s["key"].as_str().map_or_else(
            || s["address"].as_str().unwrap().as_bytes().to_vec(),
            |k| hex::decode(k).unwrap(),
        );
        assert_eq!(
            app_signer_id(s["origin"].as_str().unwrap(), &key),
            s["id"].as_str().unwrap()
        );
    }
}

/// An app's call passes through its origin's scope, end to end, with no
/// admin document applied: the factory's constructor stores the admin rule
/// set `apply_scope` needs.
#[test]
fn an_app_call_passes_through_its_origin_scope() {
    let w = world();
    let account = minted(&w, "apps/through");
    let app = Passkey::labelled("apps/through/game");
    let scope = app_scope_candidates(GAME)[0];
    let doc = app_doc(&w, GAME, &[&app], &[guess(&w, &[0])]);
    w.apply_scope_as(&account, "owner", scope, &doc)
        .expect("the owner applies the app's scope");
    let rule = w.scoped_rule_id(&account.address, scope, "guess");
    assert!(calls(&w, &account, &app, rule));
    assert_eq!(
        w.check_auth(
            &account.address,
            &[&app],
            &[rule],
            &[protected(&w, &account.address)]
        ),
        Ok(())
    );
}

/// Outside its scope the app's key authorizes nothing: another contract,
/// another function, another origin's rule, and the admin rule are each
/// refused by the account's rule-eval.
#[test]
fn an_app_call_outside_its_scope_is_refused() {
    let w = world();
    let account = minted(&w, "apps/outside");
    let (game, other) = (
        Passkey::labelled("apps/outside/game"),
        Passkey::labelled("apps/outside/other"),
    );
    let (gs, os) = (
        app_scope_candidates(GAME)[0],
        app_scope_candidates(OTHER)[0],
    );
    w.apply_scope_as(
        &account,
        "owner",
        gs,
        &app_doc(&w, GAME, &[&game], &[guess(&w, &[0])]),
    )
    .unwrap();
    w.apply_scope_as(
        &account,
        "owner",
        os,
        &app_doc(&w, OTHER, &[&other], &[guess(&w, &[0])]),
    )
    .unwrap();
    let mine = w.scoped_rule_id(&account.address, gs, "guess");
    let theirs = w.scoped_rule_id(&account.address, os, "guess");
    let a = &account.address;

    let elsewhere = contract_at(&w.env, "elsewhere");
    let other_contract = w.context(
        &elsewhere,
        "protected",
        soroban_sdk::vec![&w.env, a.into_val(&w.env)],
    );
    let other_fn = w.context(
        &w.target,
        "drain",
        soroban_sdk::vec![&w.env, a.into_val(&w.env)],
    );
    let me = w.context(
        a,
        "apply_scope",
        soroban_sdk::vec![&w.env, gs.into_val(&w.env)],
    );
    assert_eq!(
        w.check_auth(a, &[&game], &[mine], &[other_contract]),
        auth(PerchAuthError::RuleEvalRefused)
    );
    assert_eq!(
        w.check_auth(a, &[&game], &[mine], &[other_fn]),
        auth(PerchAuthError::RuleEvalRefused)
    );
    assert_eq!(
        w.check_auth(a, &[&game], &[mine], &[me]),
        auth(PerchAuthError::RuleEvalRefused)
    );
    assert_eq!(
        w.check_auth(a, &[&game], &[theirs], &[protected(&w, a)]),
        auth(PerchAuthError::RuleEvalRefused)
    );
    let admin = w.rule_id(a, "admin");
    assert_eq!(
        w.check_auth(a, &[&game], &[admin], &[protected(&w, a)]),
        auth(PerchAuthError::RuleEvalRefused)
    );
    // Each app still passes through its own rule.
    assert!(calls(&w, &account, &game, mine));
    assert!(calls(&w, &account, &other, theirs));
}

/// A second session from the same origin joins its scope: the rule is any
/// one of the two keys (`threshold`, `m = 1`), either key's call passes,
/// and both are charged against the one spending record a capped rule
/// keeps. The document limit bounds an origin to 8 keys.
#[test]
fn a_second_session_joins_its_origins_scope_and_shares_the_cap() {
    let w = world();
    let account = minted(&w, "apps/join");
    let (k1, k2) = (
        Passkey::labelled("apps/join/1"),
        Passkey::labelled("apps/join/2"),
    );
    let scope = app_scope_candidates(GAME)[0];
    let token = contract_at(&w.env, "token");
    let stake = |keys: &'static [usize]| Grant {
        name: "stake",
        contract: &token,
        functions: Some(&["transfer"]),
        cap: Some((100, 17_280)),
        keys,
    };
    w.apply_scope_as(
        &account,
        "owner",
        scope,
        &app_doc(&w, GAME, &[&k1], &[guess(&w, &[0]), stake(&[0])]),
    )
    .unwrap();
    let joined = app_doc(&w, GAME, &[&k1, &k2], &[guess(&w, &[0, 1]), stake(&[0, 1])]);
    w.apply_scope_as(&account, "owner", scope, &joined)
        .expect("the second key joins");
    let (g, s) = (
        w.scoped_rule_id(&account.address, scope, "guess"),
        w.scoped_rule_id(&account.address, scope, "stake"),
    );
    assert!(calls(&w, &account, &k1, g));
    assert!(calls(&w, &account, &k2, g));

    let a = &account.address;
    assert_eq!(
        w.check_auth(a, &[&k1], &[s], &[transfer(&w, &token, a, 60)]),
        Ok(())
    );
    assert_eq!(
        w.check_auth(a, &[&k2], &[s], &[transfer(&w, &token, a, 60)]),
        auth(PerchAuthError::RuleEvalRefused),
        "the second key spends from the same record"
    );
    assert_eq!(
        w.check_auth(a, &[&k2], &[s], &[transfer(&w, &token, a, 40)]),
        Ok(())
    );

    let keys: std::vec::Vec<Passkey> = (0..9)
        .map(|i| Passkey::labelled(&format!("apps/join/k{i}")))
        .collect();
    let refs: std::vec::Vec<&Passkey> = keys.iter().collect();
    let all: std::vec::Vec<usize> = (0..8).collect();
    w.apply_scope_as(
        &account,
        "owner",
        scope,
        &app_doc(&w, GAME, &refs[..8], &[guess(&w, &all)]),
    )
    .expect("8 keys fit");
    let nine: std::vec::Vec<usize> = (0..9).collect();
    assert_eq!(
        w.apply_scope_as(
            &account,
            "owner",
            scope,
            &app_doc(&w, GAME, &refs, &[guess(&w, &nine)])
        ),
        refused(PerchAccountError::Compiler(DocCompilerError::DocTooLarge)),
        "a 9th key is over the document limit"
    );
}

/// Removing an app removes its scope: its call is refused, and the admin
/// document is as it was.
#[test]
fn removing_an_app_removes_its_scope() {
    let w = world();
    let account = minted(&w, "apps/remove");
    w.apply(&account, &w.doc(&account, None), 0).unwrap();
    let client = w.account(&account);
    let (hash, revision) = (client.applied_doc_hash(), client.revision());
    let app = Passkey::labelled("apps/remove/game");
    let scope = app_scope_candidates(GAME)[0];
    w.apply_scope_as(
        &account,
        "owner",
        scope,
        &app_doc(&w, GAME, &[&app], &[guess(&w, &[0])]),
    )
    .unwrap();
    let rule = w.scoped_rule_id(&account.address, scope, "guess");
    assert!(calls(&w, &account, &app, rule));

    w.remove_scope_as(&account, "owner", scope)
        .expect("the owner removes the app");
    assert!(client.scope(&scope).is_none());
    assert_eq!(client.scope_count(), 0);
    assert!(!calls(&w, &account, &app, rule));
    assert_eq!(
        (client.applied_doc_hash(), client.revision()),
        (hash, revision)
    );
    assert_eq!(
        w.remove_scope_as(&account, "owner", scope),
        Err(Ok(PerchAccountError::UnknownScope))
    );
}

/// The admin document stays small: connecting several apps changes none of
/// its rules, its hash, or its revision.
#[test]
fn the_admin_document_stays_small() {
    let w = world();
    let enrolled = w.enrolled("apps/small", Profile::Loss, Mode::Guardian);
    let account = &enrolled.account;
    let client = w.account(account);
    let before = (
        client.installed_rules(),
        client.applied_doc_hash(),
        client.revision(),
    );
    let token = contract_at(&w.env, "token");
    for (i, origin) in [
        "https://a.example",
        "https://b.example",
        "https://c.example",
        "https://d.example",
    ]
    .iter()
    .enumerate()
    {
        let key = Passkey::labelled(&format!("apps/small/{i}"));
        let stake = Grant {
            name: "stake",
            contract: &token,
            functions: Some(&["transfer"]),
            cap: Some((100, 17_280)),
            keys: &[0],
        };
        let doc = app_doc(&w, origin, &[&key], &[guess(&w, &[0]), stake]);
        w.apply_scope_as(account, "owner", app_scope_candidates(origin)[0], &doc)
            .unwrap();
    }
    assert_eq!(client.scope_count(), 4);
    assert_eq!(
        (
            client.installed_rules(),
            client.applied_doc_hash(),
            client.revision()
        ),
        before
    );
    // admin, the `app` rule of the world's document, and the recovery
    // rule: what it had.
    assert_eq!(before.0.len(), 3);
}

/// No app scope reaches the account or its recovery: a rule on the account,
/// the recovery controller, or the ZK adapter or pool is refused.
#[test]
fn an_app_scope_cannot_reach_the_account_or_recovery() {
    let w = world();
    let enrolled = w.enrolled("apps/reach", Profile::Loss, Mode::Zk);
    let account = &enrolled.account;
    let app = Passkey::labelled("apps/reach/game");
    let scope = app_scope_candidates(GAME)[0];
    for target in [&account.address, &w.controller, &w.adapter, &w.pool] {
        let doc = app_doc(
            &w,
            GAME,
            &[&app],
            &[Grant {
                name: "reach",
                contract: target,
                functions: None,
                cap: None,
                keys: &[0],
            }],
        );
        assert_eq!(
            w.apply_scope_as(account, "owner", scope, &doc),
            refused(PerchAccountError::ScopeEscalation),
            "{}",
            strkey(target)
        );
    }
}

/// The admin document with an app rule from before apps had scopes: the
/// account's admin rule, and `guess` signed by the app's key alone.
fn admin_with_app_rule(w: &World, account: &Account, app: &Passkey) -> Bytes {
    let verifier = strkey(&w.verifier);
    let json = format!(
        r#"{{"version":1,"network":"{NETWORK}","signers":[{{"id":"admin","verifier":"{verifier}","key":"{}"}},{{"id":"session","verifier":"{verifier}","key":"{}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["admin"]}}}},{{"name":"guess","scope":{{"type":"contract","address":"{}"}},"principals":{{"type":"all","signers":["session"]}},"functions":["protected"]}}]}}"#,
        hex::encode(account.key("owner").pubkey()),
        hex::encode(app.pubkey()),
        strkey(&w.target)
    );
    Bytes::from_slice(&w.env, json.as_bytes())
}

/// Moving an app's rule out of the admin document has no outage: the scope
/// is applied first, then the admin document without the rule at the
/// revision read before (`apply_scope` does not advance it), and the app's
/// call passes after each step.
#[test]
fn moving_an_apps_rules_has_no_outage() {
    let w = world();
    let account = minted(&w, "apps/move");
    let app = Passkey::labelled("apps/move/game");
    w.apply_bytes_as(
        &account,
        "owner",
        &admin_with_app_rule(&w, &account, &app),
        0,
    )
    .unwrap();
    let client = w.account(&account);
    let revision = client.revision();
    let old = w.rule_id(&account.address, "guess");
    assert!(calls(&w, &account, &app, old));

    let scope = app_scope_candidates(GAME)[0];
    w.apply_scope_as(
        &account,
        "owner",
        scope,
        &app_doc(&w, GAME, &[&app], &[guess(&w, &[0])]),
    )
    .expect("step 1: the scope");
    let moved = w.scoped_rule_id(&account.address, scope, "guess");
    assert!(calls(&w, &account, &app, moved));
    assert!(
        calls(&w, &account, &app, old),
        "both copies allow the same call"
    );
    assert_eq!(client.revision(), revision);

    let without = w.doc(&account, None);
    let without = nido_integration_tests::world::Doc {
        rules: std::vec![],
        ..without
    };
    w.apply_at(&account, &without, 0, revision)
        .expect("step 2: the admin document without it, at the revision read before step 1");
    assert!(calls(&w, &account, &app, moved));
    assert!(!calls(&w, &account, &app, old));
}

/// A completed recovery ends every app scope: the app's rule is refused
/// (`StaleScope`), no document may name its key again (`WipedCredential`,
/// scoped or admin), a fresh key revives the same scope id, and anyone
/// collects a wiped scope.
#[test]
fn a_recovery_ends_every_app_scope() {
    let w = world();
    let enrolled = w.enrolled("apps/recovery", Profile::Loss, Mode::Guardian);
    let account = &enrolled.account;
    let app = Passkey::labelled("apps/recovery/game");
    let other = Passkey::labelled("apps/recovery/other");
    let (gs, os) = (
        app_scope_candidates(GAME)[0],
        app_scope_candidates(OTHER)[0],
    );
    let doc = app_doc(&w, GAME, &[&app], &[guess(&w, &[0])]);
    w.apply_scope_as(account, "owner", gs, &doc).unwrap();
    w.apply_scope_as(
        account,
        "owner",
        os,
        &app_doc(&w, OTHER, &[&other], &[guess(&w, &[0])]),
    )
    .unwrap();
    let rule = w.scoped_rule_id(&account.address, gs, "guess");
    assert!(calls(&w, account, &app, rule));

    let client = w.account(account);
    let new_owner = Passkey::labelled("apps/recovery/new-owner");
    let source = client.applied_doc().unwrap();
    let replacements = w.replacements(&new_owner, None);
    let attempt = w.begin_lost_key(account, &replacements).unwrap();
    for guardian in &enrolled.guardians[..2] {
        w.try_guardian(account, guardian, attempt, EvidenceDomain::Initiate)
            .unwrap();
    }
    let target = w.target_bytes(account, RecoveryAction::LostKey, &source, &replacements);
    w.advance(DELAY);
    w.complete(account, &target).expect("anyone completes");
    assert_eq!(client.scope_generation(), 1);

    let a = &account.address;
    assert_eq!(
        w.check_auth(a, &[&app], &[rule], &[protected(&w, a)]),
        auth(PerchAuthError::StaleScope)
    );
    let mut recovered = account.clone();
    recovered.keys[0].1 = new_owner;
    assert_eq!(
        w.apply_scope_as(&recovered, "owner", gs, &doc),
        refused(PerchAccountError::WipedCredential)
    );
    let naming = admin_with_app_rule(&w, &recovered, &app);
    assert_eq!(
        w.apply_bytes_as(&recovered, "owner", &naming, 0),
        refused(PerchAccountError::WipedCredential)
    );

    let fresh = Passkey::labelled("apps/recovery/game-2");
    w.apply_scope_as(
        &recovered,
        "owner",
        gs,
        &app_doc(&w, GAME, &[&fresh], &[guess(&w, &[0])]),
    )
    .expect("a fresh key revives the same scope id");
    let revived = w.scoped_rule_id(a, gs, "guess");
    assert!(calls(&w, &recovered, &fresh, revived));

    assert_eq!(
        client.try_gc_scope(&gs),
        Err(Ok(PerchAccountError::ScopeLive))
    );
    client.gc_scope(&os);
    assert!(client.scope(&os).is_none());
}

/// The rule shapes the placement test compares, as each rule's fields after
/// its name: `{ME}` is the account's address and `{UNTIL}` a bound 30
/// ledgers ahead, filled in per account.
fn placement_shapes(
    w: &World,
    token: &Address,
    someone: &Address,
) -> std::vec::Vec<(&'static str, String)> {
    let t = format!(
        r#""scope":{{"type":"contract","address":"{}"}}"#,
        strkey(&w.target)
    );
    let x = format!(
        r#""scope":{{"type":"contract","address":"{}"}}"#,
        strkey(token)
    );
    let protected_arg0 = |address: &str| {
        format!(
            r#"{t},"functions":["protected"],"args":[{{"index":0,"pred":{{"type":"address-eq","address":"{address}"}}}}]"#
        )
    };
    std::vec![
        ("any", t.clone()),
        ("only", format!(r#"{t},"functions":["protected"]"#)),
        ("other-fn", format!(r#"{t},"functions":["drain"]"#)),
        ("arg-me", protected_arg0("{ME}")),
        ("arg-other", protected_arg0(&strkey(someone))),
        ("until", format!(r#"{t},"not-after-ledger":{{UNTIL}}"#)),
        (
            "cap",
            format!(
                r#"{x},"functions":["transfer"],"cap":{{"limit":"100","period-ledgers":17280}}"#
            ),
        ),
    ]
}

/// Two fresh accounts holding the rule `name` (fields `body`) for `app`'s
/// key: one in its admin document, one in `GAME`'s scope. Returns each with
/// the rule's id there.
fn placed(
    w: &World,
    app: &Passkey,
    i: usize,
    name: &str,
    body: &str,
) -> ((Account, u32), (Account, u32)) {
    let verifier = strkey(&w.verifier);
    let key = hex::encode(app.pubkey());
    let id = app_signer_id(GAME, &app.pubkey());
    let scope = app_scope_candidates(GAME)[0];
    let admin_acc = minted(w, &format!("apps/placement/{i}/admin"));
    let scope_acc = minted(w, &format!("apps/placement/{i}/scope"));
    let rule = |acc: &Account, signer: &str| {
        format!(
            r#"{{"name":"{name}",{},"principals":{{"type":"all","signers":["{signer}"]}}}}"#,
            body.replace("{ME}", &strkey(&acc.address))
                .replace("{UNTIL}", &(w.ledger() + 30).to_string())
        )
    };
    let admin_json = format!(
        r#"{{"version":1,"network":"{NETWORK}","signers":[{{"id":"admin","verifier":"{verifier}","key":"{}"}},{{"id":"session","verifier":"{verifier}","key":"{key}"}}],"rules":[{{"name":"admin","scope":{{"type":"self-admin"}},"principals":{{"type":"all","signers":["admin"]}}}},{}]}}"#,
        hex::encode(admin_acc.key("owner").pubkey()),
        rule(&admin_acc, "session")
    );
    w.apply_bytes_as(
        &admin_acc,
        "owner",
        &Bytes::from_slice(&w.env, admin_json.as_bytes()),
        0,
    )
    .unwrap_or_else(|e| panic!("{name} in the admin document: {e:?}"));
    let scope_json = format!(
        r#"{{"version":1,"network":"{NETWORK}","signers":[{{"id":"{id}","verifier":"{verifier}","key":"{key}"}}],"rules":[{}]}}"#,
        rule(&scope_acc, &id)
    );
    w.apply_scope_as(
        &scope_acc,
        "owner",
        scope,
        &Bytes::from_slice(&w.env, scope_json.as_bytes()),
    )
    .unwrap_or_else(|e| panic!("{name} in a scope: {e:?}"));
    let ra = w.rule_id(&admin_acc.address, name);
    let rs = w.scoped_rule_id(&scope_acc.address, scope, name);
    ((admin_acc, ra), (scope_acc, rs))
}

/// Where a rule sits never changes a verdict: each rule shape, signed by the
/// app's key, decides every context alike in the admin document (selected
/// by its admin id) and in the app's scope (selected by its scoped id),
/// spending caps and expiry included, on accounts that see the same
/// contexts in the same order.
#[test]
fn placement_never_changes_a_verdict() {
    let w = world();
    let app = Passkey::labelled("apps/placement/game");
    let token = contract_at(&w.env, "token");
    let elsewhere = contract_at(&w.env, "elsewhere");
    let someone = contract_at(&w.env, "someone");
    let contexts = |a: &Address| {
        let on = |c: &Address, f: &str, arg: &Address| {
            w.context(c, f, soroban_sdk::vec![&w.env, arg.into_val(&w.env)])
        };
        std::vec![
            on(&w.target, "protected", a),
            on(&w.target, "protected", &someone),
            on(&w.target, "drain", a),
            on(&elsewhere, "protected", a),
            transfer(&w, &token, a, 60),
            transfer(&w, &token, a, 60),
            transfer(&w, &token, a, 40),
        ]
    };
    let mut seen = (0, 0);
    for (i, (name, body)) in placement_shapes(&w, &token, &someone).iter().enumerate() {
        let ((admin_acc, ra), (scope_acc, rs)) = placed(&w, &app, i, name, body);
        for (k, (ca, cs)) in contexts(&admin_acc.address)
            .into_iter()
            .zip(contexts(&scope_acc.address))
            .enumerate()
        {
            let admin = w.check_auth(&admin_acc.address, &[&app], &[ra], &[ca]);
            let scoped = w.check_auth(&scope_acc.address, &[&app], &[rs], &[cs]);
            assert_eq!(
                admin.is_ok(),
                scoped.is_ok(),
                "{name}, context {k}: {admin:?} vs {scoped:?}"
            );
            if admin.is_ok() {
                seen.0 += 1;
            } else {
                seen.1 += 1;
            }
        }
        // Past the `until` shape's bound.
        w.advance(40);
        let admin = w.check_auth(
            &admin_acc.address,
            &[&app],
            &[ra],
            &[protected(&w, &admin_acc.address)],
        );
        let scoped = w.check_auth(
            &scope_acc.address,
            &[&app],
            &[rs],
            &[protected(&w, &scope_acc.address)],
        );
        assert_eq!(
            admin.is_ok(),
            scoped.is_ok(),
            "{name}, after 40 ledgers: {admin:?} vs {scoped:?}"
        );
    }
    assert!(
        seen.0 > 0 && seen.1 > 0,
        "the matrix both allows and refuses: {seen:?}"
    );
}
