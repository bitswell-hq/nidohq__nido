//! Signing wiring through the host: the check runs before the keeper is
//! called, and each payload kind is signed bound to what the action says.

use agent_host::grant::{Grants, Payload, SigningCaveat};
use agent_host::sign::{Request, RequestPayload, MESSAGE_PREFIX};
use agent_host::{AgentId, CallError, Host, Output, ToolCall, Vocabulary};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nido_key_keeper::stellar::{transaction_hash, MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};
use nido_key_keeper::{KeyId, MemoryKeyKeeper, StellarNetwork};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, InvokeContractArgs, Limits, Memo, MuxedAccount,
    Preconditions, ScAddress, ScSymbol, SequenceNumber, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn envelope() -> TransactionEnvelope {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([7; 32])),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: VecM::default(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
}

fn auth_preimage(passphrase: &str) -> Vec<u8> {
    HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
        nonce: 42,
        signature_expiration_ledger: 1000,
        invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([1; 32]))),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        },
    })
    .to_xdr(Limits::none())
    .unwrap()
}

/// The preimage a delegated signer (a grant signer holder) signs: it names
/// the account it authorizes for.
fn delegated_auth_preimage(passphrase: &str) -> Vec<u8> {
    HashIdPreimage::SorobanAuthorizationWithAddress(HashIdPreimageSorobanAuthorizationWithAddress {
        network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
        address: ScAddress::Contract(ContractId(Hash([9; 32]))),
        nonce: 42,
        signature_expiration_ledger: 1000,
        invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(ContractId(Hash([1; 32]))),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: VecM::default(),
            }),
            sub_invocations: VecM::default(),
        },
    })
    .to_xdr(Limits::none())
    .unwrap()
}

fn sign(key: &str, network: &str, payload: RequestPayload) -> ToolCall {
    ToolCall::Sign(Request {
        key: key.into(),
        network: network.into(),
        payload,
    })
}

struct Fixture {
    host: Host<MemoryKeyKeeper>,
    agent: AgentId,
    public: VerifyingKey,
}

/// An agent allowed to have `key-a` sign transactions, auth entries and
/// messages on testnet. The keeper also holds `key-b`.
fn fixture() -> Fixture {
    let mut keeper = MemoryKeyKeeper::new();
    let public = keeper.insert(KeyId::new("key-a"), [1; 32]);
    keeper.insert(KeyId::new("key-b"), [2; 32]);
    let mut host = Host::new(keeper).unwrap();
    let agent = host
        .issue(&Grants {
            signing: vec![
                SigningCaveat::KeyIn(vec!["key-a".into()]),
                SigningCaveat::NetworkIn(vec![TESTNET_PASSPHRASE.into()]),
            ],
            ..Grants::default()
        })
        .unwrap();
    Fixture {
        host,
        agent,
        public: VerifyingKey::from_bytes(&public).unwrap(),
    }
}

fn signature(result: Result<Output, CallError>) -> Signature {
    match result {
        Ok(Output::Signature(s)) => Signature::from_slice(&s).unwrap(),
        other => panic!("expected a signature, got {other:?}"),
    }
}

fn assert_denied(result: Result<Output, CallError>) {
    match result {
        Err(CallError::Denied {
            vocabulary: Vocabulary::Signing,
            ..
        }) => {}
        other => panic!("expected a signing denial, got {other:?}"),
    }
}

#[test]
fn an_allowed_transaction_is_signed_for_its_network() {
    let mut f = fixture();
    let xdr = envelope().to_xdr(Limits::none()).unwrap();
    let sig = signature(f.host.call(
        f.agent,
        &sign(
            "key-a",
            TESTNET_PASSPHRASE,
            RequestPayload::Transaction(b64(&xdr)),
        ),
    ));
    let hash = transaction_hash(StellarNetwork::Testnet, &envelope()).unwrap();
    f.public.verify(&hash, &sig).unwrap();
    let mainnet = transaction_hash(StellarNetwork::Mainnet, &envelope()).unwrap();
    assert!(f.public.verify(&mainnet, &sig).is_err());
}

#[test]
fn an_allowed_auth_entry_is_signed_over_the_preimage_hash() {
    let mut f = fixture();
    let preimage = auth_preimage(TESTNET_PASSPHRASE);
    let sig = signature(f.host.call(
        f.agent,
        &sign(
            "key-a",
            TESTNET_PASSPHRASE,
            RequestPayload::AuthEntry(b64(&preimage)),
        ),
    ));
    f.public.verify(&Sha256::digest(&preimage), &sig).unwrap();
}

#[test]
fn a_delegated_signers_auth_entry_is_signed_over_the_preimage_hash() {
    let mut f = fixture();
    let preimage = delegated_auth_preimage(TESTNET_PASSPHRASE);
    let sig = signature(f.host.call(
        f.agent,
        &sign(
            "key-a",
            TESTNET_PASSPHRASE,
            RequestPayload::AuthEntry(b64(&preimage)),
        ),
    ));
    f.public.verify(&Sha256::digest(&preimage), &sig).unwrap();

    // Named for testnet, built for mainnet: refused before the keeper.
    let requests = f.host.keeper().requests().len();
    let result = f.host.call(
        f.agent,
        &sign(
            "key-a",
            TESTNET_PASSPHRASE,
            RequestPayload::AuthEntry(b64(&delegated_auth_preimage(MAINNET_PASSPHRASE))),
        ),
    );
    assert!(matches!(result, Err(CallError::Failed(_))), "{result:?}");
    assert_eq!(f.host.keeper().requests().len(), requests);
}

#[test]
fn an_allowed_message_is_signed_with_the_sep53_prefix() {
    let mut f = fixture();
    let sig = signature(f.host.call(
        f.agent,
        &sign(
            "key-a",
            TESTNET_PASSPHRASE,
            RequestPayload::Message("hello".into()),
        ),
    ));
    let mut hasher = Sha256::new();
    hasher.update(MESSAGE_PREFIX);
    hasher.update(b"hello");
    f.public.verify(&hasher.finalize(), &sig).unwrap();
    assert!(f.public.verify(b"hello", &sig).is_err());
}

#[test]
fn a_disallowed_key_is_denied_before_the_keeper_is_called() {
    let mut f = fixture();
    let xdr = envelope().to_xdr(Limits::none()).unwrap();
    assert_denied(f.host.call(
        f.agent,
        &sign(
            "key-b",
            TESTNET_PASSPHRASE,
            RequestPayload::Transaction(b64(&xdr)),
        ),
    ));
    assert_denied(f.host.call(
        f.agent,
        &sign(
            "key-b",
            TESTNET_PASSPHRASE,
            RequestPayload::Message("m".into()),
        ),
    ));
    assert!(f.host.keeper().requests().is_empty());
}

#[test]
fn a_disallowed_network_is_denied_before_the_keeper_is_called() {
    let mut f = fixture();
    let xdr = envelope().to_xdr(Limits::none()).unwrap();
    assert_denied(f.host.call(
        f.agent,
        &sign(
            "key-a",
            MAINNET_PASSPHRASE,
            RequestPayload::Transaction(b64(&xdr)),
        ),
    ));
    assert_denied(f.host.call(
        f.agent,
        &sign(
            "key-a",
            MAINNET_PASSPHRASE,
            RequestPayload::AuthEntry(b64(&auth_preimage(MAINNET_PASSPHRASE))),
        ),
    ));
    assert!(f.host.keeper().requests().is_empty());
}

#[test]
fn an_auth_entry_for_another_network_than_named_is_refused() {
    let mut f = fixture();
    // The agent names testnet (allowed) but the preimage is for mainnet.
    let result = f.host.call(
        f.agent,
        &sign(
            "key-a",
            TESTNET_PASSPHRASE,
            RequestPayload::AuthEntry(b64(&auth_preimage(MAINNET_PASSPHRASE))),
        ),
    );
    assert!(matches!(result, Err(CallError::Failed(_))), "{result:?}");
    assert!(f.host.keeper().requests().is_empty());
}

#[test]
fn a_disallowed_payload_kind_is_denied() {
    let mut keeper = MemoryKeyKeeper::new();
    keeper.insert(KeyId::new("key-a"), [1; 32]);
    let mut host = Host::new(keeper).unwrap();
    let agent = host
        .issue(&Grants {
            signing: vec![SigningCaveat::PayloadIn(vec![Payload::Transaction])],
            ..Grants::default()
        })
        .unwrap();
    assert_denied(host.call(
        agent,
        &sign(
            "key-a",
            TESTNET_PASSPHRASE,
            RequestPayload::Message("m".into()),
        ),
    ));
    assert!(host.keeper().requests().is_empty());
}
