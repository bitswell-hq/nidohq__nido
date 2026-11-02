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
//! the host's `compute_transaction_resource_fee` under the SDK's 2026-07-10
//! snapshot of mainnet fee settings. Rent is not included: it depends on how
//! long ago each entry was last extended.
//!
//! [`measure_archived`] re-executes the call the same way over a copy of the
//! snapshot in which chosen entries are archived (persistent entries live
//! until the ledger before this one, temporary entries gone), under a
//! network's settings ([`NetworkSettings`]: its cost model, entry lifetimes
//! and limits): the host restores the archived entries the call reads as it
//! runs, and records which, with their sizes and every rent change.

extern crate std;

use crate::world::World;
use soroban_env_host::budget::Budget;
use soroban_env_host::e2e_invoke::{
    extract_rent_changes, invoke_host_function_in_recording_mode,
    InvokeHostFunctionRecordingModeResult, RecordingInvocationAuthMode,
};
use soroban_env_host::fees::{
    compute_transaction_resource_fee, FeeConfiguration, TransactionResources,
};
use soroban_env_host::storage::SnapshotSource;
use soroban_env_host::LedgerInfo;
use soroban_sdk::testutils::Ledger as _;
use soroban_sdk::xdr::{
    AccountId, ContractCostParamEntry, ContractCostParams, ContractDataDurability,
    DecoratedSignature, ExtensionPoint, HostFunction, InvokeContractArgs, InvokeHostFunctionOp,
    LedgerKey, Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
    ReadXdr, ScAddress, ScSymbol, ScVal, SequenceNumber, Signature, SignatureHint,
    SorobanAuthorizationEntry, SorobanResources, SorobanResourcesExtV0, SorobanTransactionData,
    SorobanTransactionDataExt, Transaction, TransactionEnvelope, TransactionExt,
    TransactionV1Envelope, Uint256, WriteXdr,
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
    let budget = Budget::default();
    budget.reset_unlimited().unwrap();
    let (result, measured) = run(
        &budget,
        contract,
        function,
        args,
        auth,
        w.env.ledger().get(),
        Rc::new(w.env.to_ledger_snapshot()),
    );
    drop(result);
    measured
}

/// `contract.function(args)` authorized by `auth`, run in recording mode
/// over `snapshot` at `ledger`, and its envelope and fee (see the module
/// docs).
fn run(
    budget: &Budget,
    contract: &Address,
    function: &str,
    args: Vec<ScVal>,
    auth: Vec<SorobanAuthorizationEntry>,
    ledger: LedgerInfo,
    snapshot: Rc<dyn SnapshotSource>,
) -> (InvokeHostFunctionRecordingModeResult, Measured) {
    let host_function = HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: ScAddress::from(contract.clone()),
        function_name: ScSymbol(function.try_into().unwrap()),
        args: args.try_into().unwrap(),
    });
    let source = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([7; 32])));
    let mut diagnostics = Vec::new();
    let result = invoke_host_function_in_recording_mode(
        budget,
        false,
        &host_function,
        &source,
        RecordingInvocationAuthMode::Enforcing(auth),
        ledger,
        snapshot,
        [0; 32],
        &mut diagnostics,
    )
    .expect("the recording run completes");
    result
        .invoke_result
        .as_ref()
        .unwrap_or_else(|e| panic!("{function} fails as a transaction: {e:?}"));

    let ext = if result.restored_rw_entry_indices.is_empty() {
        SorobanTransactionDataExt::V0
    } else {
        SorobanTransactionDataExt::V1(SorobanResourcesExtV0 {
            archived_soroban_entries: result.restored_rw_entry_indices.clone().try_into().unwrap(),
        })
    };
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
                ext,
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
    let measured = Measured {
        resources: result.resources.clone(),
        envelope_bytes,
        events_and_return_bytes: result.contract_events_and_return_value_size,
        non_refundable_fee,
        refundable_fee,
    };
    (result, measured)
}

/// The settings of a network [`measure_archived`] runs under, read from
/// the archive `research/email-recovery/eval/fees/settings.mjs` writes
/// (`results/settings/<network>.json`).
pub struct NetworkSettings {
    pub min_persistent_ttl: u32,
    pub min_temporary_ttl: u32,
    pub max_entry_ttl: u32,
    /// The network's cost model, cut to the cost types this host meters.
    pub cpu_cost_params: ContractCostParams,
    pub mem_cost_params: ContractCostParams,
    /// The number of cost types the network's model has.
    pub network_cost_types: usize,
}

impl NetworkSettings {
    /// # Panics
    /// If the archive cannot be read or lacks a field.
    #[must_use]
    pub fn read(path: &std::path::Path) -> Self {
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let s = &v["settings"];
        let ttl = |k: &str| u32::try_from(s["state_archival"][k].as_u64().unwrap()).unwrap();
        let known = soroban_sdk::xdr::ContractCostType::variants().len();
        let params = |k: &str| {
            let all = s[k].as_array().unwrap();
            let entries: Vec<ContractCostParamEntry> = all
                .iter()
                .take(known)
                .map(|p| ContractCostParamEntry {
                    ext: ExtensionPoint::V0,
                    const_term: p["const_term"].as_str().unwrap().parse().unwrap(),
                    linear_term: p["linear_term"].as_str().unwrap().parse().unwrap(),
                })
                .collect();
            (ContractCostParams(entries.try_into().unwrap()), all.len())
        };
        let (cpu_cost_params, network_cost_types) = params("contract_cost_params_cpu_instructions");
        let (mem_cost_params, _) = params("contract_cost_params_memory_bytes");
        Self {
            min_persistent_ttl: ttl("min_persistent_ttl"),
            min_temporary_ttl: ttl("min_temporary_ttl"),
            max_entry_ttl: ttl("max_entry_ttl"),
            cpu_cost_params,
            mem_cost_params,
            network_cost_types,
        }
    }
}

/// An entry [`measure_archived`]'s call restored.
#[derive(Clone, Debug)]
pub struct Restored {
    pub key: LedgerKey,
    /// Its XDR size, which the restoration reads from disk and writes.
    pub xdr_bytes: u32,
    /// Its size for rent (the XDR size, plus the in-memory module for code).
    pub rent_bytes: u32,
    /// Whether the call removes it after restoring it.
    pub removed: bool,
}

/// A change in an entry's size or lifetime that the call pays rent for.
#[derive(Clone, Debug)]
pub struct RentChange {
    pub key: LedgerKey,
    pub persistent: bool,
    pub code: bool,
    pub old_size: u32,
    pub new_size: u32,
    pub old_live_until: u32,
    pub new_live_until: u32,
}

/// [`measure_archived`]'s reading of one call.
pub struct Archived {
    pub measured: Measured,
    /// The ledger it ran in.
    pub ledger: u32,
    pub restored: Vec<Restored>,
    pub rent_changes: Vec<RentChange>,
}

/// [`measure`] over the world's ledger with every entry `archived` selects
/// archived, under `settings` (see the module docs). The world itself is not
/// changed.
///
/// # Panics
/// If the call fails, or the settings' cost model does not load.
#[must_use]
pub fn measure_archived(
    w: &World,
    contract: &Address,
    function: &str,
    args: Vec<ScVal>,
    auth: Vec<SorobanAuthorizationEntry>,
    archived: &dyn Fn(&LedgerKey) -> bool,
    settings: &NetworkSettings,
) -> Archived {
    let mut ledger = w.env.ledger().get();
    ledger.min_persistent_entry_ttl = settings.min_persistent_ttl;
    ledger.min_temp_entry_ttl = settings.min_temporary_ttl;
    ledger.max_entry_ttl = settings.max_entry_ttl;
    let sequence = ledger.sequence_number;
    let mut snapshot = w.env.to_ledger_snapshot();
    snapshot.ledger_entries = snapshot
        .ledger_entries
        .into_iter()
        .filter_map(|(key, (entry, live_until))| {
            if live_until.is_none() || !archived(&key) {
                return Some((key, (entry, live_until)));
            }
            let temporary = matches!(&*key, LedgerKey::ContractData(d) if d.durability == ContractDataDurability::Temporary);
            (!temporary).then(|| (key, (entry, Some(sequence - 1))))
        })
        .collect();
    // Each entry's XDR size, which restoring it reads (and writes, unless the
    // call removes it).
    let xdr_sizes: std::collections::BTreeMap<Vec<u8>, u32> = snapshot
        .ledger_entries
        .iter()
        .map(|(k, (e, _))| {
            (
                k.to_xdr(Limits::none()).unwrap(),
                u32::try_from(e.to_xdr(Limits::none()).unwrap().len()).unwrap(),
            )
        })
        .collect();
    let budget = Budget::try_from_configs(
        u64::MAX,
        u64::MAX,
        settings.cpu_cost_params.clone(),
        settings.mem_cost_params.clone(),
    )
    .expect("the network's cost model");
    let (result, measured) = run(
        &budget,
        contract,
        function,
        args,
        auth,
        ledger,
        Rc::new(snapshot),
    );
    let rw = &result.resources.footprint.read_write;
    let restored_keys: Vec<LedgerKey> = result
        .restored_rw_entry_indices
        .iter()
        .map(|&i| rw[i as usize].clone())
        .collect();
    let mut restored = Vec::new();
    let mut rent_changes = Vec::new();
    for change in &result.ledger_changes {
        let key = LedgerKey::from_xdr(&change.encoded_key, Limits::none()).unwrap();
        if restored_keys.contains(&key) {
            restored.push(Restored {
                key: key.clone(),
                xdr_bytes: xdr_sizes[&change.encoded_key],
                rent_bytes: change
                    .new_entry_size_bytes_for_rent
                    .max(change.old_entry_size_bytes_for_rent),
                removed: change.encoded_new_value.is_none(),
            });
        }
        if let Some(r) = extract_rent_changes(core::slice::from_ref(change)).pop() {
            rent_changes.push(RentChange {
                key,
                persistent: r.is_persistent,
                code: r.is_code_entry,
                old_size: r.old_size_bytes,
                new_size: r.new_size_bytes,
                old_live_until: r.old_live_until_ledger,
                new_live_until: r.new_live_until_ledger,
            });
        }
    }
    Archived {
        measured,
        ledger: sequence,
        restored,
        rent_changes,
    }
}
