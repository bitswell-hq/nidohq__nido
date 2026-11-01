//! A contract call measured as one Soroban transaction.
//!
//! [`measure`] re-executes the call in a fresh host over a snapshot of the
//! world's ledger, with the signed authorization entries enforced: the
//! host's `invoke_host_function_in_recording_mode`, which simulation
//! services run, here in enforcing-auth mode, so every custom account's
//! `__check_auth` runs (in recording-auth mode, which a simulation without
//! auth entries uses, it does not). From the recorded footprint and
//! resources it builds the transaction envelope a wallet would sign (one
//! `InvokeHostFunction` operation, one source signature) and prices it with
//! the host's `compute_transaction_resource_fee` under the SDK's snapshot of
//! mainnet fee settings. Rent is not included: it depends on how long ago
//! each entry was last extended.

extern crate std;

use crate::world::World;
use soroban_env_host::budget::Budget;
use soroban_env_host::e2e_invoke::{
    invoke_host_function_in_recording_mode, RecordingInvocationAuthMode,
};
use soroban_env_host::fees::{
    compute_transaction_resource_fee, FeeConfiguration, TransactionResources,
};
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{
    AccountId, DecoratedSignature, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits,
    Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey, ScAddress, ScSymbol,
    ScVal, SequenceNumber, Signature, SignatureHint, SorobanAuthorizationEntry, SorobanResources,
    SorobanTransactionData, SorobanTransactionDataExt, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};
use soroban_sdk::Address;
use std::rc::Rc;
use std::vec::Vec;

/// The SDK's snapshot of mainnet fee settings (`soroban-sdk`
/// `testutils::cost_estimate::CostEstimate::fee`, 2026-07-10).
fn mainnet_fees() -> FeeConfiguration {
    FeeConfiguration {
        fee_per_instruction_increment: 7,
        fee_per_disk_read_entry: 1563,
        fee_per_write_entry: 2500,
        fee_per_disk_read_1kb: 447,
        fee_per_write_1kb: 875,
        fee_per_historical_1kb: 4059,
        fee_per_contract_event_1kb: 5000,
        fee_per_transaction_size_1kb: 406,
    }
}

/// One call as a transaction.
#[derive(Clone, Debug)]
pub struct Measured {
    /// The recorded resources, footprint included.
    pub resources: SorobanResources,
    /// Size of the signed transaction envelope's XDR.
    pub envelope_bytes: u32,
    /// Size of the contract events and return value.
    pub events_and_return_bytes: u32,
    /// Resource fee without rent: the non-refundable part (instructions,
    /// reads, writes, bandwidth, history) and the refundable part (events).
    pub non_refundable_fee: i64,
    pub refundable_fee: i64,
}

/// `contract.function(args)` authorized by `auth`, re-executed over the
/// world's current ledger (see the module docs). The world itself is not
/// changed.
///
/// # Panics
/// If the call fails.
#[must_use]
pub fn measure(
    w: &World,
    contract: &Address,
    function: &str,
    args: Vec<ScVal>,
    auth: Vec<SorobanAuthorizationEntry>,
) -> Measured {
    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: ScAddress::from(contract.clone()),
        function_name: ScSymbol(function.try_into().unwrap()),
        args: args.try_into().unwrap(),
    });
    let source = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32])));
    let budget = Budget::default();
    budget.reset_unlimited().unwrap();
    let snapshot = w.env.to_ledger_snapshot();
    let ledger = w.env.ledger().get();
    let mut diagnostics = Vec::new();
    let result = invoke_host_function_in_recording_mode(
        &budget,
        false,
        &host_function,
        &source,
        RecordingInvocationAuthMode::Enforcing(auth),
        ledger,
        Rc::new(snapshot),
        [0; 32],
        &mut diagnostics,
    )
    .expect("the recording run completes");
    result
        .invoke_result
        .as_ref()
        .unwrap_or_else(|e| panic!("{function} fails as a transaction: {e:?}"));

    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256([7; 32])),
            fee: u32::MAX,
            seq_num: SequenceNumber(i64::MAX),
            cond: Preconditions::None,
            memo: Memo::None,
            operations: std::vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function,
                    auth: result.auth.clone().try_into().unwrap(),
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V1(SorobanTransactionData {
                ext: SorobanTransactionDataExt::V0,
                resources: result.resources.clone(),
                resource_fee: i64::MAX,
            }),
        },
        signatures: std::vec![DecoratedSignature {
            hint: SignatureHint([0; 4]),
            signature: Signature(std::vec![0u8; 64].try_into().unwrap()),
        }]
        .try_into()
        .unwrap(),
    });
    let envelope_bytes = u32::try_from(envelope.to_xdr(Limits::none()).unwrap().len()).unwrap();
    let r = &result.resources;
    let (non_refundable_fee, refundable_fee) = compute_transaction_resource_fee(
        &TransactionResources {
            instructions: r.instructions,
            disk_read_entries: 0,
            write_entries: u32::try_from(r.footprint.read_write.len()).unwrap(),
            disk_read_bytes: r.disk_read_bytes,
            write_bytes: r.write_bytes,
            contract_events_size_bytes: result.contract_events_and_return_value_size,
            transaction_size_bytes: envelope_bytes,
        },
        &mainnet_fees(),
    );
    Measured {
        resources: result.resources,
        envelope_bytes,
        events_and_return_bytes: result.contract_events_and_return_value_size,
        non_refundable_fee,
        refundable_fee,
    }
}
