//! Fixtures shared by the Dfns tests: a mock with one token and two keys, a
//! client for it, and an unsigned Stellar payment.

#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use nido_key_keeper::dfns::mock::{MockConfig, MockServer};
use nido_key_keeper::dfns::{DfnsConfig, DfnsKeyKeeper, KeyCredential};
use nido_key_keeper::{stellar, KeyId};
use stellar_xdr::{
    Asset, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions,
    SequenceNumber, Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope,
    Uint256, WriteXdr,
};

pub const TOKEN: &str = "test-service-account-token";
pub const USER_ID: &str = "us-3k8s2-q0pde-4hn2bq7k4u1c8a9f";
pub const CRED_ID: &str = "cr-6tq9a-1m2kd-8s7f0d3l5p2h4j6k";
pub const KEY: &str = "key-01snl-t56gb-j8tsok0vn802p80i";
pub const OTHER_KEY: &str = "key-7c2mr-90xqa-5f8ud3w1n6y4b2zs";

pub const KEY_SEED: [u8; 32] = [7; 32];
pub const OTHER_KEY_SEED: [u8; 32] = [9; 32];
pub const CREDENTIAL_SEED: [u8; 32] = [42; 32];

pub fn credential_key() -> SigningKey {
    SigningKey::from_bytes(&CREDENTIAL_SEED)
}

pub fn key_public() -> [u8; 32] {
    SigningKey::from_bytes(&KEY_SEED).verifying_key().to_bytes()
}

pub fn mock_config() -> MockConfig {
    MockConfig::default()
        .with_key(KEY, KEY_SEED)
        .with_key(OTHER_KEY, OTHER_KEY_SEED)
        .with_token(TOKEN, USER_ID, CRED_ID, &credential_key().verifying_key())
}

pub fn start_mock() -> MockServer {
    MockServer::start(&mock_config(), "127.0.0.1:0").expect("mock starts")
}

pub fn client(mock: &MockServer) -> DfnsKeyKeeper {
    client_with(mock, TOKEN, CRED_ID, credential_key())
}

pub fn client_with(
    mock: &MockServer,
    token: &str,
    cred_id: &str,
    signing_key: SigningKey,
) -> DfnsKeyKeeper {
    DfnsKeyKeeper::new(DfnsConfig::new(
        mock.url(),
        token,
        KeyCredential {
            cred_id: cred_id.to_owned(),
            signing_key,
        },
    ))
}

pub fn key() -> KeyId {
    KeyId::new(KEY)
}

/// An unsigned one-operation payment of 1 XLM from `source` (a `G…`
/// address) to a fixed destination.
pub fn payment_envelope(source: &str) -> TransactionEnvelope {
    let source = stellar::account_public_key(source).expect("source is a G address");
    let destination =
        stellar::account_public_key("GAZWLHTNAOJWW52GZCUJAS5MSXK7LAWCUC5TFOFFVDQ7CDTNFODJ37GB")
            .expect("destination is a G address");
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source)),
            fee: 100,
            seq_num: SequenceNumber(4_294_967_297),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: MuxedAccount::Ed25519(Uint256(destination)),
                    asset: Asset::Native,
                    amount: 10_000_000,
                }),
            }]
            .try_into()
            .expect("one operation"),
            ext: TransactionExt::V0,
        },
        signatures: Vec::new().try_into().expect("no signatures"),
    })
}

pub fn xdr(envelope: &TransactionEnvelope) -> Vec<u8> {
    envelope.to_xdr(Limits::none()).expect("envelope encodes")
}
