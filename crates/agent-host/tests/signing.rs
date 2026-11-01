//! Signing wiring through the host: the checks run before the keeper is
//! called, each payload kind is signed bound to what the action says, and a
//! transaction or authorization entry is signed only when the chain grant
//! allows every context the signature would authorize.

use agent_host::grant::{ChainCaveat, Grants, I128Text, Payload, SigningCaveat};
use agent_host::sign::{Request, RequestPayload, MESSAGE_PREFIX};
use agent_host::{AgentId, CallError, Host, Output, ToolCall, Vocabulary};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nido_key_keeper::stellar::{transaction_hash, MAINNET_PASSPHRASE, TESTNET_PASSPHRASE};
use nido_key_keeper::{KeyId, MemoryKeyKeeper, Payload as KeeperPayload, StellarNetwork};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    AccountId, Asset, BytesM, ContractExecutable, ContractId, ContractIdPreimage,
    ContractIdPreimageFromAddress, CreateAccountOp, CreateContractArgs, FeeBumpTransaction,
    FeeBumpTransactionEnvelope, FeeBumpTransactionExt, FeeBumpTransactionInnerTx, Hash,
    HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, Memo, MuxedAccount, Operation, OperationBody, PaymentOp,
    Preconditions, PublicKey, ScAddress, ScSymbol, ScVal, SequenceNumber, SetOptionsOp, Signer,
    SignerKey, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

/// The contract the fixture's chain grant allows.
const TOKEN: [u8; 32] = [1; 32];
/// A contract it does not.
const OTHER: [u8; 32] = [9; 32];
/// The fixture's bound on `transfer`'s amount (argument 2).
const MAX_AMOUNT: i64 = 1000;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn contract(id: [u8; 32]) -> ScAddress {
    ScAddress::Contract(ContractId(Hash(id)))
}

fn account(id: u8) -> ScAddress {
    ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
        [id; 32],
    ))))
}

fn amount(n: i64) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: if n < 0 { -1 } else { 0 },
        lo: n.cast_unsigned(),
    })
}

/// `transfer(from, to, amount)` on `id`.
fn transfer(id: [u8; 32], n: i64) -> InvokeContractArgs {
    call(
        id,
        "transfer",
        vec![
            ScVal::Address(account(7)),
            ScVal::Address(account(8)),
            amount(n),
        ],
    )
}

fn call(id: [u8; 32], function: &str, args: Vec<ScVal>) -> InvokeContractArgs {
    InvokeContractArgs {
        contract_address: contract(id),
        function_name: ScSymbol(function.try_into().unwrap()),
        args: args.try_into().unwrap(),
    }
}

fn node(
    args: InvokeContractArgs,
    sub_invocations: Vec<SorobanAuthorizedInvocation>,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(args),
        sub_invocations: sub_invocations.try_into().unwrap(),
    }
}

/// An entry the transaction's signature authorizes.
fn source_entry(root: SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: root,
    }
}

/// An entry signed by `address` itself.
fn address_entry(
    address: ScAddress,
    root: SorobanAuthorizedInvocation,
) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address,
            nonce: 1,
            signature_expiration_ledger: 1000,
            signature: ScVal::Void,
        }),
        root_invocation: root,
    }
}

fn op(body: OperationBody) -> Operation {
    Operation {
        source_account: None,
        body,
    }
}

fn invoke_op(func: HostFunction, auth: Vec<SorobanAuthorizationEntry>) -> Operation {
    op(OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
        host_function: func,
        auth: auth.try_into().unwrap(),
    }))
}

fn tx(operations: Vec<Operation>) -> Transaction {
    Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([7; 32])),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: operations.try_into().unwrap(),
        ext: TransactionExt::V0,
    }
}

fn envelope_of(operations: Vec<Operation>) -> TransactionEnvelope {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx(operations),
        signatures: VecM::default(),
    })
}

/// A transaction calling `func` with the authorization entries `auth`.
fn invoke_tx(
    func: InvokeContractArgs,
    auth: Vec<SorobanAuthorizationEntry>,
) -> TransactionEnvelope {
    envelope_of(vec![invoke_op(HostFunction::InvokeContract(func), auth)])
}

/// An allowed transfer the source account authorizes.
fn envelope() -> TransactionEnvelope {
    invoke_tx(
        transfer(TOKEN, 5),
        vec![source_entry(node(transfer(TOKEN, 5), vec![]))],
    )
}

fn preimage_of(passphrase: &str, invocation: SorobanAuthorizedInvocation) -> Vec<u8> {
    HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
        nonce: 42,
        signature_expiration_ledger: 1000,
        invocation,
    })
    .to_xdr(Limits::none())
    .unwrap()
}

/// The preimage a delegated signer (a grant signer holder) signs: it names
/// the account it authorizes for.
fn delegated_preimage_of(passphrase: &str, invocation: SorobanAuthorizedInvocation) -> Vec<u8> {
    HashIdPreimage::SorobanAuthorizationWithAddress(HashIdPreimageSorobanAuthorizationWithAddress {
        network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
        address: contract(OTHER),
        nonce: 42,
        signature_expiration_ledger: 1000,
        invocation,
    })
    .to_xdr(Limits::none())
    .unwrap()
}

/// An allowed transfer's authorization preimage.
fn auth_preimage(passphrase: &str) -> Vec<u8> {
    preimage_of(passphrase, node(transfer(TOKEN, 5), vec![]))
}

fn sign(key: &str, network: &str, payload: RequestPayload) -> ToolCall {
    ToolCall::Sign(Request {
        key: key.into(),
        network: network.into(),
        payload,
    })
}

fn sign_tx(envelope: &TransactionEnvelope) -> ToolCall {
    sign(
        "key-a",
        TESTNET_PASSPHRASE,
        RequestPayload::Transaction(b64(&envelope.to_xdr(Limits::none()).unwrap())),
    )
}

fn sign_auth(preimage: &[u8]) -> ToolCall {
    sign(
        "key-a",
        TESTNET_PASSPHRASE,
        RequestPayload::AuthEntry(b64(preimage)),
    )
}

struct Fixture {
    host: Host<MemoryKeyKeeper>,
    agent: AgentId,
    public: VerifyingKey,
}

/// The fixture's chain grant: `transfer` on `TOKEN`, amount at most
/// `MAX_AMOUNT`.
fn token_transfers() -> Vec<ChainCaveat> {
    vec![
        ChainCaveat::ContractIn(vec![contract(TOKEN).to_string()]),
        ChainCaveat::FunctionIn(vec!["transfer".into()]),
        ChainCaveat::ArgI128AtMost(2, I128Text::Number(MAX_AMOUNT)),
    ]
}

/// An agent allowed to have `key-a` sign transactions, auth entries and
/// messages on testnet, for transfers of at most `MAX_AMOUNT` on `TOKEN`.
/// The keeper also holds `key-b`.
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
            chain: token_transfers(),
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

/// The chain grant denied the call, and nothing reached the keeper.
fn assert_chain_denied(f: &Fixture, result: Result<Output, CallError>) {
    match result {
        Err(CallError::Denied {
            vocabulary: Vocabulary::Chain,
            ..
        }) => {}
        other => panic!("expected a chain denial, got {other:?}"),
    }
    assert!(f.host.keeper().requests().is_empty());
}

/// The host refused to sign the payload, and nothing reached the keeper.
fn assert_refused(f: &Fixture, result: Result<Output, CallError>) {
    match result {
        Err(CallError::Failed(_)) => {}
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(f.host.keeper().requests().is_empty());
}

#[test]
fn an_allowed_transaction_is_signed_for_its_network() {
    let mut f = fixture();
    let sig = signature(f.host.call(f.agent, &sign_tx(&envelope())));
    let hash = transaction_hash(StellarNetwork::Testnet, &envelope()).unwrap();
    f.public.verify(&hash, &sig).unwrap();
    let mainnet = transaction_hash(StellarNetwork::Mainnet, &envelope()).unwrap();
    assert!(f.public.verify(&mainnet, &sig).is_err());
}

#[test]
fn the_keeper_signs_the_transaction_that_was_checked() {
    let mut f = fixture();
    signature(f.host.call(f.agent, &sign_tx(&envelope())));
    let requests = f.host.keeper().requests();
    let [(
        key,
        KeeperPayload::StellarTransaction {
            network,
            envelope_xdr,
        },
    )] = &requests[..]
    else {
        panic!("expected one transaction request, got {requests:?}");
    };
    assert_eq!(key.as_str(), "key-a");
    assert_eq!(*network, StellarNetwork::Testnet);
    assert_eq!(*envelope_xdr, envelope().to_xdr(Limits::none()).unwrap());
}

#[test]
fn an_allowed_auth_entry_is_signed_over_the_preimage_hash() {
    let mut f = fixture();
    let preimage = auth_preimage(TESTNET_PASSPHRASE);
    let sig = signature(f.host.call(f.agent, &sign_auth(&preimage)));
    f.public.verify(&Sha256::digest(&preimage), &sig).unwrap();
}

#[test]
fn a_delegated_signers_auth_entry_is_signed_over_the_preimage_hash() {
    let mut f = fixture();
    let preimage = delegated_preimage_of(TESTNET_PASSPHRASE, node(transfer(TOKEN, 5), vec![]));
    let sig = signature(f.host.call(f.agent, &sign_auth(&preimage)));
    f.public.verify(&Sha256::digest(&preimage), &sig).unwrap();

    // Named for testnet, built for mainnet: refused before the keeper.
    let requests = f.host.keeper().requests().len();
    let result = f.host.call(
        f.agent,
        &sign_auth(&delegated_preimage_of(
            MAINNET_PASSPHRASE,
            node(transfer(TOKEN, 5), vec![]),
        )),
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
    let result = f
        .host
        .call(f.agent, &sign_auth(&auth_preimage(MAINNET_PASSPHRASE)));
    assert_refused(&f, result);
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

// An agent allowed to have its key sign transactions and authorization
// entries tries to have it sign calls its chain grant does not allow.

#[test]
fn a_transaction_calling_a_contract_outside_the_chain_grant_is_denied() {
    let mut f = fixture();
    let result = f.host.call(
        f.agent,
        &sign_tx(&invoke_tx(
            transfer(OTHER, 5),
            vec![source_entry(node(transfer(OTHER, 5), vec![]))],
        )),
    );
    assert_chain_denied(&f, result);
}

#[test]
fn a_transaction_over_the_amount_bound_is_denied() {
    let mut f = fixture();
    let over = MAX_AMOUNT + 1;
    let result = f.host.call(
        f.agent,
        &sign_tx(&invoke_tx(
            transfer(TOKEN, over),
            vec![source_entry(node(transfer(TOKEN, over), vec![]))],
        )),
    );
    assert_chain_denied(&f, result);
}

#[test]
fn a_disallowed_call_inside_a_transactions_authorization_tree_is_denied() {
    let mut f = fixture();
    // The host function is an allowed transfer; the tree the transaction's
    // signature authorizes also reaches another contract.
    let hidden = node(
        transfer(TOKEN, 5),
        vec![node(call(OTHER, "drain", vec![]), vec![])],
    );
    let result = f.host.call(
        f.agent,
        &sign_tx(&invoke_tx(transfer(TOKEN, 5), vec![source_entry(hidden)])),
    );
    assert_chain_denied(&f, result);
}

#[test]
fn a_disallowed_call_in_any_authorization_entry_of_the_transaction_is_denied() {
    let mut f = fixture();
    let result = f.host.call(
        f.agent,
        &sign_tx(&invoke_tx(
            transfer(TOKEN, 5),
            vec![
                source_entry(node(transfer(TOKEN, 5), vec![])),
                address_entry(account(8), node(transfer(OTHER, 5), vec![])),
            ],
        )),
    );
    assert_chain_denied(&f, result);
}

#[test]
fn a_transaction_deploying_a_contract_is_denied_by_a_chain_grant() {
    let mut f = fixture();
    let deploy = HostFunction::CreateContract(CreateContractArgs {
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: account(7),
            salt: Uint256([0; 32]),
        }),
        executable: ContractExecutable::Wasm(Hash([3; 32])),
    });
    let result = f.host.call(
        f.agent,
        &sign_tx(&envelope_of(vec![invoke_op(deploy, vec![])])),
    );
    assert_chain_denied(&f, result);
}

#[test]
fn a_transaction_uploading_contract_code_is_refused() {
    let mut f = fixture();
    let upload =
        HostFunction::UploadContractWasm(BytesM::try_from(vec![0, 0x61, 0x73, 0x6d]).unwrap());
    let result = f.host.call(
        f.agent,
        &sign_tx(&envelope_of(vec![invoke_op(upload, vec![])])),
    );
    assert_refused(&f, result);
}

#[test]
fn a_transaction_with_an_operation_the_chain_vocabulary_cannot_express_is_refused() {
    let add_signer = OperationBody::SetOptions(SetOptionsOp {
        inflation_dest: None,
        clear_flags: None,
        set_flags: None,
        master_weight: None,
        low_threshold: None,
        med_threshold: None,
        high_threshold: None,
        home_domain: None,
        signer: Some(Signer {
            key: SignerKey::Ed25519(Uint256([6; 32])),
            weight: 255,
        }),
    });
    let new_account = OperationBody::CreateAccount(CreateAccountOp {
        destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([6; 32]))),
        starting_balance: 10_000_000,
    });
    let payment = OperationBody::Payment(PaymentOp {
        destination: MuxedAccount::Ed25519(Uint256([6; 32])),
        asset: Asset::Native,
        amount: 10_000_000,
    });
    for body in [add_signer, new_account, payment] {
        let mut f = fixture();
        let result = f.host.call(f.agent, &sign_tx(&envelope_of(vec![op(body)])));
        assert_refused(&f, result);
    }
}

#[test]
fn a_transaction_with_a_second_operation_is_refused() {
    let mut f = fixture();
    let result = f.host.call(
        f.agent,
        &sign_tx(&envelope_of(vec![
            invoke_op(
                HostFunction::InvokeContract(transfer(TOKEN, 5)),
                vec![source_entry(node(transfer(TOKEN, 5), vec![]))],
            ),
            op(OperationBody::Payment(PaymentOp {
                destination: MuxedAccount::Ed25519(Uint256([6; 32])),
                asset: Asset::Native,
                amount: 10_000_000,
            })),
        ])),
    );
    assert_refused(&f, result);
}

#[test]
fn a_fee_bump_envelope_is_refused() {
    let mut f = fixture();
    let TransactionEnvelope::Tx(inner) = envelope() else {
        unreachable!()
    };
    let bump = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256([7; 32])),
            fee: 1_000_000,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
            ext: FeeBumpTransactionExt::V0,
        },
        signatures: VecM::default(),
    });
    let result = f.host.call(f.agent, &sign_tx(&bump));
    assert_refused(&f, result);
}

#[test]
fn an_auth_entry_for_a_contract_outside_the_chain_grant_is_denied() {
    let mut f = fixture();
    let preimage = preimage_of(TESTNET_PASSPHRASE, node(transfer(OTHER, 5), vec![]));
    let result = f.host.call(f.agent, &sign_auth(&preimage));
    assert_chain_denied(&f, result);
}

#[test]
fn a_disallowed_call_inside_an_auth_entrys_tree_is_denied() {
    let mut f = fixture();
    let preimage = preimage_of(
        TESTNET_PASSPHRASE,
        node(
            transfer(TOKEN, 5),
            vec![node(transfer(TOKEN, MAX_AMOUNT + 1), vec![])],
        ),
    );
    let result = f.host.call(f.agent, &sign_auth(&preimage));
    assert_chain_denied(&f, result);
}

#[test]
fn a_disallowed_call_inside_a_delegated_signers_auth_entry_is_denied() {
    let mut f = fixture();
    let preimage = delegated_preimage_of(
        TESTNET_PASSPHRASE,
        node(
            transfer(TOKEN, 5),
            vec![node(call(OTHER, "drain", vec![]), vec![])],
        ),
    );
    let result = f.host.call(f.agent, &sign_auth(&preimage));
    assert_chain_denied(&f, result);
}

#[test]
fn an_auth_entry_whose_whole_tree_is_allowed_is_signed() {
    let mut f = fixture();
    let preimage = preimage_of(
        TESTNET_PASSPHRASE,
        node(
            transfer(TOKEN, 5),
            vec![node(transfer(TOKEN, MAX_AMOUNT), vec![])],
        ),
    );
    let sig = signature(f.host.call(f.agent, &sign_auth(&preimage)));
    f.public.verify(&Sha256::digest(&preimage), &sig).unwrap();
}

#[test]
fn a_sub_agent_cannot_sign_calls_its_parent_may_not_make() {
    let mut f = fixture();
    // The sub-agent asks for another contract; its grant still carries the
    // parent's chain caveats.
    let Ok(Output::Agent(kid)) = f.host.call(
        f.agent,
        &ToolCall::Delegate {
            add: Grants {
                chain: vec![ChainCaveat::ContractIn(vec![contract(OTHER).to_string()])],
                ..Grants::default()
            },
        },
    ) else {
        panic!("delegation failed");
    };
    let result = f.host.call(
        kid,
        &sign_tx(&invoke_tx(
            transfer(OTHER, 5),
            vec![source_entry(node(transfer(OTHER, 5), vec![]))],
        )),
    );
    assert_chain_denied(&f, result);
    // Nor what its own caveats exclude, though the parent may.
    let result = f.host.call(kid, &sign_tx(&envelope()));
    assert_chain_denied(&f, result);
}
