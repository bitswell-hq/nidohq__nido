// The email-factor recovery after archival, as transactions under a
// network's limits and fees (research/email-recovery/eval/README.md,
// "Archival and the keeper"). Input: the test host's reading of each step
// with every entry it reads archived (results/archival-test-host.json): the
// step's resources with the host restoring its archived entries as it runs,
// each restored entry's size, and every rent change.
//
// A step whose inline restoration fits the network's per-transaction
// limits runs as one transaction. One that does not first restores its
// largest archived entries in separate RestoreFootprint transactions
// (packed largest first under the same limits), until the rest fits. Each
// transaction is priced with fees/model.mjs. Rent sizes are the test host's
// unless `rentSizes` gives the network's own for that key.
import { Keypair, Networks, Operation, SorobanDataBuilder, Account, TransactionBuilder, xdr } from '@stellar/stellar-sdk';
import { resourceFee, rentFee, schedule } from './model.mjs';

/** The per-transaction limits of `settings`. */
export function limits(settings) {
  const c = settings.contract_ledger_cost_v0;
  return {
    instructions: Number(settings.contract_compute_v0.tx_max_instructions),
    diskReadBytes: c.tx_max_disk_read_bytes,
    diskReadEntries: c.tx_max_disk_read_entries,
    writeBytes: c.tx_max_write_bytes,
    writeEntries: c.tx_max_write_ledger_entries,
    footprintEntries: settings.contract_ledger_cost_ext_v0.tx_max_footprint_entries,
    txBytes: settings.contract_bandwidth_v0.tx_max_size_bytes,
  };
}

/** Which of `limits` resources `r` exceeds. */
export function exceeded(r, lim) {
  return Object.keys(lim).filter((k) => r[k] !== undefined && r[k] > lim[k]);
}

/** The signed envelope size of one RestoreFootprint transaction over `keys` (base64 LedgerKey XDR). */
export function restoreEnvelopeBytes(keys) {
  const source = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 7));
  const tx = new TransactionBuilder(new Account(source.publicKey(), '0'), { fee: '100', networkPassphrase: Networks.PUBLIC })
    .addOperation(Operation.restoreFootprint({}))
    .setSorobanData(new SorobanDataBuilder().setReadWrite(keys.map((k) => xdr.LedgerKey.fromXDR(k, 'base64'))).setResourceFee(1_000_000_000n).setResources(0, 200_000, 132_096).build())
    .setTimeout(180)
    .build();
  tx.sign(source);
  return tx.toEnvelope().toXDR().length;
}

/**
 * The transactions of `steps` under `settings`: each step's restorations
 * that fit inline, the RestoreFootprint transactions it needs before it,
 * and every transaction's fee by component.
 */
export function plan(steps, settings, { rentSizes = {} } = {}) {
  const sch = schedule(settings);
  const lim = limits(settings);
  const minPersistent = settings.state_archival.min_persistent_ttl;
  const size = (e) => rentSizes[e.keyXdr] ?? e.rentBytes;
  const out = [];
  for (const s of steps) {
    const restored = s.restored.map((e) => ({ ...e, rentBytes: size(e), source: rentSizes[e.keyXdr] ? 'network' : 'test host' }));
    // Move the largest restored entries out until the step fits.
    const moved = [];
    const inline = [...restored].sort((a, b) => b.xdrBytes - a.xdrBytes);
    const resources = (keep) => {
      const out_ = moved.reduce((n, e) => n + e.xdrBytes, 0);
      return {
        instructions: s.instructions,
        diskReadBytes: s.diskReadBytes - out_,
        diskReadEntries: keep.length,
        writeBytes: s.writeBytes - moved.filter((e) => !e.removed).reduce((n, e) => n + e.xdrBytes, 0),
        writeEntries: s.readWrite - moved.length,
        footprintEntries: s.readOnly + s.readWrite,
        txBytes: s.envelopeBytes - 4 * moved.length,
      };
    };
    while (inline.length && exceeded(resources(inline), lim).length) moved.push(inline.shift());
    const r = resources(inline);
    const over = exceeded(r, lim);
    if (over.length) throw new Error(`${s.step} exceeds ${over.join(', ')} even with nothing restored inline`);
    // Rent: the step's own changes, with each inline restoration at its rent size; moved entries pay theirs in their restore transactions.
    const movedKeys = new Set(moved.map((e) => e.keyXdr));
    const changes = s.rentChanges
      .filter((c) => !movedKeys.has(c.keyXdr))
      .map((c) => (rentSizes[c.keyXdr] !== undefined && c.oldSize === 0 ? { ...c, newSize: rentSizes[c.keyXdr] } : c));
    const restoreTxs = pack(moved, lim).map((group) => {
      const keys = group.map((e) => e.keyXdr);
      const txBytes = restoreEnvelopeBytes(keys);
      const bytes = group.reduce((n, e) => n + e.xdrBytes, 0);
      const f = resourceFee({ instructions: 0, diskReadEntries: group.length, writeEntries: group.length, diskReadBytes: bytes, writeBytes: bytes, eventsBytes: 0, txBytes }, sch);
      const rent = rentFee(group.map((e) => ({ persistent: true, code: e.code, oldSize: 0, newSize: e.rentBytes, oldLiveUntil: 0, newLiveUntil: s.ledger + minPersistent - 1 })), sch, s.ledger);
      return { kind: 'restore', step: s.step, entries: group.map((e) => ({ key: e.key, xdrBytes: e.xdrBytes, rentBytes: e.rentBytes, source: e.source })), txBytes, ...f, rent, fee: f.nonRefundable + rent + 100 };
    });
    const f = resourceFee({ ...r, eventsBytes: s.eventsBytes }, sch);
    const rent = rentFee(changes, sch, s.ledger);
    out.push(...restoreTxs, {
      kind: 'step',
      step: s.step,
      restoredInline: inline.map((e) => ({ key: e.key, xdrBytes: e.xdrBytes, rentBytes: e.rentBytes, source: e.source })),
      resources: r,
      ...f,
      rent,
      fee: f.nonRefundable + f.events + rent + 100,
    });
  }
  return out;
}

/** First-fit decreasing: `entries` into groups each within one restore transaction's limits. */
function pack(entries, lim) {
  const groups = [];
  for (const e of [...entries].sort((a, b) => b.xdrBytes - a.xdrBytes)) {
    const g = groups.find((x) => {
      const bytes = x.reduce((n, y) => n + y.xdrBytes, 0) + e.xdrBytes;
      return bytes <= lim.writeBytes && bytes <= lim.diskReadBytes && x.length + 1 <= lim.writeEntries;
    });
    if (g) g.push(e);
    else groups.push([e]);
  }
  return groups;
}
