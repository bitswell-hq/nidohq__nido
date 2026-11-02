// Soroban's resource fee, computed from a network's archived settings
// (results/settings/*.json), as the host computes it: a port of
// soroban-env-host's `fees.rs` (`compute_transaction_resource_fee`,
// `compute_rent_write_fee_per_1kb`, `compute_rent_fee`; the same in
// soroban-env-host 27.0.1 and 29.0.2, the host protocol 29 runs). Integers
// throughout; every division rounds up, as the host's does.
//
// A transaction is charged its inclusion fee plus its resource fee: the
// non-refundable part (compute, ledger reads and writes, history, size) and
// the refundable part (events and rent). `breakdown` attributes a recorded
// transaction's charged fee to these components from its declared
// resources and the network's settings.

export const TX_BASE_RESULT_SIZE = 300;
export const TTL_ENTRY_SIZE = 48;
const INSTRUCTIONS_INCREMENT = 10_000n;
const KB = 1024n;
const MINIMUM_RENT_WRITE_FEE_PER_1KB = 1000n;
const CODE_ENTRY_RENT_DISCOUNT_FACTOR = 3n;

const ceilDiv = (a, b) => (a + b - 1n) / b;
const perIncrement = (value, rate, increment) => ceilDiv(BigInt(value) * BigInt(rate), increment);

/** The fee schedule of an archive's `settings`. */
export function schedule(settings) {
  const s = settings;
  return {
    instructionIncrement: BigInt(s.contract_compute_v0.fee_rate_per_instructions_increment),
    diskReadEntry: BigInt(s.contract_ledger_cost_v0.fee_disk_read_ledger_entry),
    writeEntry: BigInt(s.contract_ledger_cost_v0.fee_write_ledger_entry),
    diskRead1kb: BigInt(s.contract_ledger_cost_v0.fee_disk_read1_kb),
    write1kb: BigInt(s.contract_ledger_cost_ext_v0.fee_write1_kb),
    historical1kb: BigInt(s.contract_historical_data_v0.fee_historical1_kb),
    events1kb: BigInt(s.contract_events_v0.fee_contract_events1_kb),
    txSize1kb: BigInt(s.contract_bandwidth_v0.fee_tx_size1_kb),
    rent1kb: rentWriteFeePer1kb(s),
    persistentRentDenominator: BigInt(s.state_archival.persistent_rent_rate_denominator),
    temporaryRentDenominator: BigInt(s.state_archival.temp_rent_rate_denominator),
  };
}

/**
 * The average Soroban state size over the network's sample window (the
 * average core keeps, an integer), and the effective rent fee per 1 KB
 * `compute_rent_write_fee_per_1kb` derives from it.
 */
export function averageStateSize(settings) {
  const w = settings.live_soroban_state_size_window.map(BigInt);
  return w.reduce((a, b) => a + b, 0n) / BigInt(w.length);
}

export function rentWriteFeePer1kb(settings) {
  const c = settings.contract_ledger_cost_v0;
  const size = averageStateSize(settings);
  const target = BigInt(c.soroban_state_target_size_bytes);
  const low = BigInt(c.rent_fee1_kb_soroban_state_size_low);
  const high = BigInt(c.rent_fee1_kb_soroban_state_size_high);
  const multiplier = high - low < 0n ? (1n << 63n) - 1n : high - low;
  let fee;
  if (size < target) {
    fee = ceilDiv(multiplier * size, target > 0n ? target : 1n) + low;
  } else {
    fee = high + ceilDiv(multiplier * (size - target) * BigInt(c.soroban_state_rent_fee_growth_factor), target > 0n ? target : 1n);
  }
  return fee > MINIMUM_RENT_WRITE_FEE_PER_1KB ? fee : MINIMUM_RENT_WRITE_FEE_PER_1KB;
}

/**
 * `compute_transaction_resource_fee`, by component. `r`: instructions,
 * diskReadEntries, writeEntries, diskReadBytes, writeBytes, eventsBytes,
 * txBytes. Returns stroops as Numbers.
 */
export function resourceFee(r, sch) {
  const c = {
    compute: perIncrement(r.instructions, sch.instructionIncrement, INSTRUCTIONS_INCREMENT),
    diskReadEntries: sch.diskReadEntry * BigInt(r.diskReadEntries),
    writeEntries: sch.writeEntry * BigInt(r.writeEntries),
    diskReadBytes: perIncrement(r.diskReadBytes, sch.diskRead1kb, KB),
    writeBytes: perIncrement(r.writeBytes, sch.write1kb, KB),
    historical: perIncrement(r.txBytes + TX_BASE_RESULT_SIZE, sch.historical1kb, KB),
    size: perIncrement(r.txBytes, sch.txSize1kb, KB),
    events: perIncrement(r.eventsBytes, sch.events1kb, KB),
  };
  const nonRefundable = c.compute + c.diskReadEntries + c.writeEntries + c.diskReadBytes + c.writeBytes + c.historical + c.size;
  return { ...Object.fromEntries(Object.entries(c).map(([k, v]) => [k, Number(v)])), nonRefundable: Number(nonRefundable) };
}

/**
 * `compute_rent_fee` for entry changes `{ persistent, code, oldSize,
 * newSize, oldLiveUntil, newLiveUntil }` (in-memory sizes; 0 for a new
 * entry) at ledger `ledger`.
 */
export function rentFee(changes, sch, ledger) {
  let fee = 0n;
  let extended = 0n;
  for (const e of changes) {
    const isNew = e.oldSize === 0 && e.oldLiveUntil === 0;
    const before = isNew ? ledger - 1 : e.oldLiveUntil;
    let f = 0n;
    if (e.newLiveUntil >= before) f += rentFor(e.persistent, e.newSize, e.newLiveUntil - before, sch);
    if (!isNew && e.oldLiveUntil >= ledger && e.newSize >= e.oldSize) f += rentFor(e.persistent, e.newSize - e.oldSize, e.oldLiveUntil - ledger + 1, sch);
    if (e.code) f = ceilDiv(f, CODE_ENTRY_RENT_DISCOUNT_FACTOR);
    fee += f;
    if (e.oldLiveUntil < e.newLiveUntil) extended += 1n;
  }
  fee += sch.writeEntry * extended + perIncrement(Number(extended) * TTL_ENTRY_SIZE, sch.write1kb, KB);
  return Number(fee);
}

function rentFor(persistent, size, ledgers, sch) {
  const denom = KB * (persistent ? sch.persistentRentDenominator : sch.temporaryRentDenominator);
  return ceilDiv(BigInt(size) * sch.rent1kb * BigInt(ledgers), denom);
}

/**
 * A recorded transaction's resources as the fee counts them: the declared
 * instructions and bytes, its footprint's write entries, the entries read
 * from disk (classic entries in the footprint and restored archived
 * entries), its envelope's size, and the event bytes the host metered.
 */
export function resourcesOf(t) {
  const fp = t.footprint ?? { readOnly: [], readWrite: [] };
  const classic = [...fp.readOnly, ...fp.readWrite].filter((k) => !/^(data|code) /.test(k)).length;
  const restoring = /^restore /.test(t.label) ? t.declared.readWrite : (t.declared.archivedEntries ?? 0);
  return {
    instructions: t.declared.instructions,
    diskReadEntries: classic + restoring,
    writeEntries: t.declared.readWrite,
    diskReadBytes: t.declared.diskReadBytes,
    writeBytes: t.declared.writeBytes,
    eventsBytes: t.metered?.emit_event_byte ?? t.eventsBytes ?? 0,
    txBytes: t.envelopeBytes,
  };
}

/**
 * A recorded transaction's charged fee by component under `settings`, and
 * whether the components add up to what the network charged
 * (`feeSplit` and `feeCharged`): the inclusion fee is what remains.
 */
export function breakdown(t, settings) {
  const sch = schedule(settings);
  const f = resourceFee(resourcesOf(t), sch);
  const rent = t.feeSplit?.rent ?? 0;
  const resource = f.nonRefundable + f.events + rent;
  const out = { ...f, rent, resource, inclusion: t.feeCharged - resource, charged: t.feeCharged };
  if (t.feeSplit) {
    out.matches = f.nonRefundable === t.feeSplit.nonRefundableResource && f.events + rent === t.feeSplit.refundableResource;
  }
  return out;
}

/** The ContractCostType of each wasm parsing input, in `ContractCodeCostInputs` order. */
const PARSE_COSTS = [
  ['nInstructions', 23],
  ['nFunctions', 24],
  ['nGlobals', 25],
  ['nTableEntries', 26],
  ['nTypes', 27],
  ['nDataSegments', 28],
  ['nElemSegments', 29],
  ['nImports', 30],
  ['nExports', 31],
  ['nDataSegmentBytes', 32],
];

/**
 * A contract code entry's size for rent, as the host sizes it
 * (`entry_size_for_rent`, `wasm_module_memory_cost`): the entry's XDR size
 * (its `LedgerEntryData` and 8 bytes of envelope) plus the memory cost the
 * network's model gives the module's parsing inputs (`costInputs`, the
 * `ContractCodeCostInputs` the entry records), each `const + (linear ×
 * input) >> 7`.
 */
export function codeRentBytes(dataBytes, costInputs, settings) {
  const mem = settings.contract_cost_params_memory_bytes;
  let size = BigInt(dataBytes + 8);
  for (const [field, type] of PARSE_COSTS) size += BigInt(mem[type].const_term) + ((BigInt(mem[type].linear_term) * BigInt(costInputs[field])) >> 7n);
  return Number(size);
}

/**
 * The schedule soroban-sdk 27.0.6's `cost_estimate().fee()` prices with
 * (`testutils/cost_estimate.rs`): its snapshot of mainnet's fee settings of
 * 2026-07-10, and a rent rate set above the network's on purpose. The test
 * host's transaction reading (`transaction::measure`) uses the same
 * snapshot.
 */
export const SDK_SNAPSHOT = {
  instructionIncrement: 7n,
  diskReadEntry: 1563n,
  writeEntry: 2500n,
  diskRead1kb: 447n,
  write1kb: 875n,
  historical1kb: 4059n,
  events1kb: 5000n,
  txSize1kb: 406n,
  rent1kb: 12000n,
  persistentRentDenominator: 1215n,
  temporaryRentDenominator: 2430n,
};
