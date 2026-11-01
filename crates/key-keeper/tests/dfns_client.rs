//! The Dfns client against the local mock, and the Stellar check: a
//! signature obtained through the mock over a Stellar transaction is a valid
//! decorated signature for that transaction.

mod common;

use common::{client, client_with, key, key_public, payment_envelope, start_mock, xdr};
use ed25519_dalek::{Signature as EdSignature, SigningKey, VerifyingKey};
use nido_key_keeper::dfns::api::{GenerateSignatureRequest, SignatureStatus};
use nido_key_keeper::dfns::request_for;
use nido_key_keeper::{
    stellar, KeyId, KeyKeeper, MemoryKeyKeeper, Payload, SignError, StellarNetwork,
};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, Limits, ReadXdr, TransactionEnvelope, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};

/// The transaction hash, built from the XDR definitions directly rather than
/// through `stellar-xdr`'s `hash` helper the keepers use:
/// `SHA-256(XDR(TransactionSignaturePayload { SHA-256(passphrase), Tx(tx) }))`.
fn independent_tx_hash(passphrase: &str, envelope: &TransactionEnvelope) -> [u8; 32] {
    let TransactionEnvelope::Tx(v1) = envelope else {
        panic!("fixture is a v1 envelope");
    };
    let payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(v1.tx.clone()),
    };
    Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into()
}

#[test]
fn mock_signatures_are_valid_decorated_signatures_for_the_transaction() {
    let mock = start_mock();
    let keeper = client(&mock);
    let address = stellar::account_strkey(&key_public());
    let envelope = payment_envelope(&address);
    let tx_hash = independent_tx_hash("Test SDF Network ; September 2015", &envelope);
    assert_eq!(
        stellar::transaction_hash(StellarNetwork::Testnet, &envelope).unwrap(),
        tx_hash
    );

    let payloads = [
        Payload::Hash(tx_hash),
        Payload::Message(tx_hash.to_vec()),
        Payload::StellarTransaction {
            network: StellarNetwork::Testnet,
            envelope_xdr: xdr(&envelope),
        },
    ];
    for payload in payloads {
        let signature = keeper.sign(&key(), &payload).expect("mock signs");
        let signature = signature.to_ed25519().expect("Ed25519 signature");

        // Attach it the way a submitter would, and read the envelope back.
        let mut signed = envelope.clone();
        let TransactionEnvelope::Tx(v1) = &mut signed else {
            unreachable!()
        };
        v1.signatures = vec![stellar::decorated_signature(&key_public(), &signature)]
            .try_into()
            .unwrap();
        let signed = TransactionEnvelope::from_xdr(xdr(&signed), Limits::none()).unwrap();
        let TransactionEnvelope::Tx(v1) = &signed else {
            unreachable!()
        };
        let decorated = &v1.signatures[0];

        // The signer is the transaction's source account, named by the hint.
        let source = stellar::account_public_key(&address).unwrap();
        assert_eq!(decorated.hint.0, source[28..], "{payload:?}");
        // And the signature verifies over the transaction hash.
        let verifying = VerifyingKey::from_bytes(&source).unwrap();
        let sig = EdSignature::from_slice(decorated.signature.as_slice()).unwrap();
        assert!(
            verifying.verify_strict(&tx_hash, &sig).is_ok(),
            "{payload:?}"
        );
        assert!(stellar::verify_decorated_signature(
            &source, &tx_hash, decorated
        ));
    }
}

#[test]
fn a_signature_does_not_verify_for_the_other_network() {
    let mock = start_mock();
    let keeper = client(&mock);
    let envelope = payment_envelope(&stellar::account_strkey(&key_public()));
    let signature = keeper
        .sign(
            &key(),
            &Payload::StellarTransaction {
                network: StellarNetwork::Testnet,
                envelope_xdr: xdr(&envelope),
            },
        )
        .unwrap()
        .to_ed25519()
        .unwrap();
    let decorated = stellar::decorated_signature(&key_public(), &signature);
    let mainnet_hash =
        independent_tx_hash("Public Global Stellar Network ; September 2015", &envelope);
    assert!(!stellar::verify_decorated_signature(
        &key_public(),
        &mainnet_hash,
        &decorated
    ));
}

#[test]
fn the_mock_and_the_memory_keeper_sign_identically() {
    let mock = start_mock();
    let dfns = client(&mock);
    let mut memory = MemoryKeyKeeper::new();
    memory.insert(key(), common::KEY_SEED);
    let envelope = payment_envelope(&stellar::account_strkey(&key_public()));
    for payload in [
        Payload::Hash([3; 32]),
        Payload::Message(b"arbitrary bytes".to_vec()),
        Payload::Message(Vec::new()),
        Payload::StellarTransaction {
            network: StellarNetwork::Mainnet,
            envelope_xdr: xdr(&envelope),
        },
    ] {
        assert_eq!(
            dfns.sign(&key(), &payload).unwrap(),
            memory.sign(&key(), &payload).unwrap(),
            "{payload:?}"
        );
    }
    assert_eq!(memory.requests().len(), 4);
}

#[test]
fn the_client_sends_the_documented_request_bodies() {
    let envelope = payment_envelope(&stellar::account_strkey(&key_public()));
    let cases = [
        (
            Payload::Hash([0xab; 32]),
            serde_json::json!({ "kind": "Hash", "hash": format!("0x{}", "ab".repeat(32)) }),
        ),
        (
            Payload::Message(vec![1, 2, 3]),
            serde_json::json!({ "kind": "Message", "message": "0x010203" }),
        ),
        (
            Payload::StellarTransaction {
                network: StellarNetwork::Testnet,
                envelope_xdr: xdr(&envelope),
            },
            serde_json::json!({
                "kind": "Transaction",
                "transaction": format!("0x{}", hex::encode(xdr(&envelope))),
                "network": "StellarTestnet",
            }),
        ),
    ];
    for (payload, expected) in cases {
        assert_eq!(
            serde_json::to_value(request_for(&payload)).unwrap(),
            expected
        );
    }
}

#[test]
fn signature_requests_read_back_with_the_documented_fields() {
    let mock = start_mock();
    let keeper = client(&mock);
    let created = keeper
        .generate_signature(&key(), &request_for(&Payload::Hash([5; 32])))
        .unwrap();
    assert_eq!(created.status, SignatureStatus::Signed);
    assert_eq!(created.key_id, common::KEY);
    assert_eq!(created.requester.user_id, common::USER_ID);
    assert_eq!(
        created.request_body,
        serde_json::json!({ "kind": "Hash", "hash": format!("0x{}", "05".repeat(32)) })
    );
    assert!(created.id.starts_with("sig-"));
    assert!(created.date_signed.is_some());
    let components = created.signature.as_ref().unwrap();
    assert_eq!(
        hex::decode(
            components
                .encoded
                .as_ref()
                .unwrap()
                .trim_start_matches("0x")
        )
        .unwrap(),
        [
            hex::decode(components.r.trim_start_matches("0x")).unwrap(),
            hex::decode(components.s.trim_start_matches("0x")).unwrap()
        ]
        .concat()
    );

    let read = keeper.get_signature(&key(), &created.id).unwrap();
    assert_eq!(read, created);
    assert_eq!(
        keeper.get_signature(&KeyId::new(common::OTHER_KEY), &created.id),
        Err(SignError::UnknownKey(KeyId::new(common::OTHER_KEY)))
    );
}

#[test]
fn external_id_is_idempotent_and_conflicts_on_a_different_request() {
    let mock = start_mock();
    let keeper = client(&mock);
    let with_id = |hash: [u8; 32]| GenerateSignatureRequest::Hash {
        hash: hex::encode(hash),
        taproot_merkle_root: None,
        network: None,
        blockchain_kind: None,
        external_id: Some("relay-0001".to_owned()),
    };
    let first = keeper
        .generate_signature(&key(), &with_id([1; 32]))
        .unwrap();
    let again = keeper
        .generate_signature(&key(), &with_id([1; 32]))
        .unwrap();
    assert_eq!(first.id, again.id);
    assert_eq!(first.external_id.as_deref(), Some("relay-0001"));
    match keeper.generate_signature(&key(), &with_id([2; 32])) {
        Err(SignError::Backend { status: 409, .. }) => {}
        other => panic!("expected 409, got {other:?}"),
    }
    match keeper.generate_signature(&KeyId::new(common::OTHER_KEY), &with_id([1; 32])) {
        Err(SignError::Backend { status: 409, .. }) => {}
        other => panic!("expected 409, got {other:?}"),
    }
}

#[test]
fn unknown_keys_and_unregistered_credentials_are_refused() {
    let mock = start_mock();
    assert_eq!(
        client(&mock).sign(
            &KeyId::new("key-nope0-nope0-nope0000000000"),
            &Payload::Hash([0; 32])
        ),
        Err(SignError::UnknownKey(KeyId::new(
            "key-nope0-nope0-nope0000000000"
        )))
    );

    // A credential id the token does not list: the client refuses before
    // signing the challenge.
    let stranger = client_with(&mock, common::TOKEN, "cr-other", common::credential_key());
    assert!(matches!(
        stranger.sign(&key(), &Payload::Hash([0; 32])),
        Err(SignError::Unauthorized(_))
    ));

    // The right credential id with the wrong private key: the mock cannot
    // verify the challenge signature.
    let impostor = client_with(
        &mock,
        common::TOKEN,
        common::CRED_ID,
        SigningKey::from_bytes(&[1; 32]),
    );
    assert!(matches!(
        impostor.sign(&key(), &Payload::Hash([0; 32])),
        Err(SignError::Unauthorized(_))
    ));

    let bad_token = client_with(
        &mock,
        "not-a-token",
        common::CRED_ID,
        common::credential_key(),
    );
    assert!(matches!(
        bad_token.sign(&key(), &Payload::Hash([0; 32])),
        Err(SignError::Unauthorized(_))
    ));
}

#[test]
fn payloads_the_mock_cannot_sign_are_invalid_requests() {
    let mock = start_mock();
    let keeper = client(&mock);
    assert!(matches!(
        keeper.sign(
            &key(),
            &Payload::StellarTransaction {
                network: StellarNetwork::Testnet,
                envelope_xdr: vec![1, 2, 3],
            }
        ),
        Err(SignError::InvalidRequest(_))
    ));
    let fee_bump = GenerateSignatureRequest::StellarFeeBumpTransaction {
        inner_transaction: "00".to_owned(),
        transaction_reference: "ref".to_owned(),
        network: Some("StellarTestnet".to_owned()),
        blockchain_kind: None,
        external_id: None,
    };
    assert!(matches!(
        keeper.generate_signature(&key(), &fee_bump),
        Err(SignError::InvalidRequest(_))
    ));
}

#[test]
fn the_memory_keeper_records_refused_requests_too() {
    let mut memory = MemoryKeyKeeper::new();
    let public = memory.insert(key(), common::KEY_SEED);
    assert_eq!(memory.public_key(&key()), Some(public));
    let unknown = KeyId::new("missing");
    assert_eq!(
        memory.sign(&unknown, &Payload::Hash([0; 32])),
        Err(SignError::UnknownKey(unknown.clone()))
    );
    assert!(matches!(
        memory.sign(
            &key(),
            &Payload::StellarTransaction {
                network: StellarNetwork::Testnet,
                envelope_xdr: vec![0xff],
            }
        ),
        Err(SignError::UnsupportedPayload(_))
    ));
    assert_eq!(
        memory
            .requests()
            .iter()
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>(),
        [unknown, key()]
    );
}
