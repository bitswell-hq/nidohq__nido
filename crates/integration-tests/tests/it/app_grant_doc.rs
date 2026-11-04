//! The scoped document an app grant with a passkey key applies compiles on
//! Perch's doc compiler, deployed from wasm with the `WebAuthn` verifier it
//! canonicalizes keys through, and applies as its origin's scope.
//!
//! The fixture is what /security/delegate-doc/ builds for a two-grant
//! `pubkey=` request from `https://game.example` to a new scope (`guess`
//! uncapped, and the capped XLM `transfer` payable only to the game: its
//! `to=` lowers to an `address-eq` on transfer's argument 1, both signed by
//! the app's key under its origin's signer id); the frontend's
//! `appGrantDoc.test.ts` keeps it byte-identical to that output and names
//! this world's verifier. The app's key is the bare 65-byte public key: the
//! compiler refuses a `WebAuthn` key with a credential id appended
//! (`KeyNotCanonicalizable`), which is why the request carries no
//! `credential_id`.

use nido_integration_tests::world::{app_scope_candidates, strkey, world, Passkey};
use perch_doc_compiler::DocCompilerError;
use serde_json::Value;
use soroban_sdk::Bytes;

const DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../packages/frontend/src/lib/policy/testdata/app-grant-doc.json"
));

#[test]
fn a_passkey_app_grant_compiles() {
    let w = world();
    let doc: Value = serde_json::from_str(DOC).unwrap();
    let verifier = strkey(&w.verifier);
    for signer in doc["signers"].as_array().unwrap() {
        assert_eq!(
            signer["verifier"],
            verifier.as_str(),
            "the fixture names this world's verifier"
        );
    }
    let compiled = w
        .compiler()
        .try_compile_doc(&Bytes::from_slice(&w.env, DOC.trim_end().as_bytes()));
    assert!(compiled.is_ok(), "the app grant must compile: {compiled:?}");
}

#[test]
fn a_credential_id_after_the_app_key_is_refused() {
    let w = world();
    let mut doc: Value = serde_json::from_str(DOC).unwrap();
    // Every signer of an app's scope is the app's key.
    for signer in doc["signers"].as_array_mut().unwrap() {
        let key = format!("{}abcdef123456", signer["key"].as_str().unwrap());
        signer["key"] = Value::String(key);
    }
    let json = serde_json::to_string(&doc).unwrap();
    assert_eq!(
        w.compiler()
            .try_compile_doc(&Bytes::from_slice(&w.env, json.as_bytes())),
        Err(Ok(DocCompilerError::KeyNotCanonicalizable)),
    );
}

#[test]
fn the_wallets_app_grant_applies_as_its_origins_scope() {
    let w = world();
    let account = w.mint(
        "app-grant-doc",
        Passkey::labelled("app-grant-doc/owner"),
        std::vec![],
    );
    let client = w.account(&account);
    let revision = client.revision();
    let scope = app_scope_candidates("https://game.example")[0];
    let bytes = Bytes::from_slice(&w.env, DOC.trim_end().as_bytes());
    let hash = w
        .apply_scope_as(&account, "owner", scope, &bytes)
        .expect("the owner applies the app's scope");
    let record = client.scope(&scope).expect("the scope is recorded");
    assert_eq!(record.doc_hash, hash);
    assert_eq!(record.rules.len(), 2);
    assert_eq!(client.scope_doc(&scope), Some(bytes));
    // The admin document is untouched: still none applied, same revision.
    assert_eq!(client.applied_doc_hash(), None);
    assert_eq!(client.revision(), revision);
}
