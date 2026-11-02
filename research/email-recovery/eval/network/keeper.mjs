#!/usr/bin/env node
// The operator's keeper (docs/email-recovery/spec.md §12, "Keeping the
// contracts live"): keeps the ledger entries an email recovery reads from
// being archived. For each contract named, its instance and its code (the
// wasm the instance runs); for each extra key, that entry. An entry whose
// remaining lifetime is below the threshold is extended to the network's
// maximum (one ExtendFootprintTTL transaction per contract, or per entry
// with --per-entry); an archived entry is restored first (RestoreFootprint).
// Anyone may extend or restore any entry, so the keeper needs no contract
// call and no authority: only a funded account to pay.
//
// The account's secret comes from NIDO_KEEPER_SECRET (never the command
// line). Prints one JSON line per transaction (what it extended or
// restored, from and to which ledger, and its measured fee) and a summary.
//
//   NIDO_KEEPER_SECRET=S… node research/email-recovery/eval/network/keeper.mjs \
//     --rpc URL --passphrase P [--threshold LEDGERS] [--force] [--per-entry] C… [--key BASE64]…
import { Address, Keypair, xdr } from '@stellar/stellar-sdk';
import { Chain } from './lib/chain.mjs';

/** The instance key and the code key of `contract`, read from its instance. */
export async function contractKeys(chain, contract) {
  const instance = xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({ contract: Address.fromString(contract).toScAddress(), key: xdr.ScVal.scvLedgerKeyContractInstance(), durability: xdr.ContractDataDurability.persistent() }),
  );
  const [e] = await chain.entries([instance]);
  if (!e) throw new Error(`${contract} has no instance entry`);
  const exec = e.value.contractData().val().instance().executable();
  if (exec.switch().name !== 'contractExecutableWasm') return [instance];
  return [instance, xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash: exec.wasmHash() }))];
}

/** The network's maximum entry lifetime, from its state-archival setting. */
export async function maxEntryTtl(chain) {
  const key = xdr.LedgerKey.configSetting(new xdr.LedgerKeyConfigSetting({ configSettingId: xdr.ConfigSettingId.configSettingStateArchival() }));
  const [e] = await chain.entries([key]);
  return e.value.configSetting().stateArchivalSettings().maxEntryTtl();
}

/**
 * Keep `groups` (each a list of LedgerKey XDR, one transaction each) live:
 * restore what is archived, then extend what has fewer than `threshold`
 * ledgers left (everything with `force`) to the network's maximum.
 */
export async function keep(chain, source, groups, { threshold = 518_400, force = false } = {}) {
  const extendTo = (await maxEntryTtl(chain)) - 1;
  const done = [];
  for (const { label, keys } of groups) {
    const latest = await chain.ledger();
    const before = await chain.entries(keys);
    const archived = keys.filter((_, i) => !before[i] || before[i].liveUntil < latest);
    if (archived.length) {
      const m = await chain.restore(source, archived, { label: `keeper restore ${label}` });
      done.push({ label, action: 'restore', keys: archived.map((k) => k.toXDR('base64')), ...m });
    }
    const now = await chain.entries(keys);
    const due = keys.filter((_, i) => force || now[i].liveUntil - latest < threshold);
    if (!due.length) continue;
    const from = due.map((k) => now[keys.indexOf(k)].liveUntil);
    const m = await chain.extend(source, due, extendTo, { label: `keeper extend ${label}` });
    const after = await chain.entries(due);
    done.push({ label, action: 'extend', keys: due.map((k) => k.toXDR('base64')), entryBytes: due.map((k) => now[keys.indexOf(k)].bytes), from, to: after.map((a) => a.liveUntil), ...m });
  }
  return done;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const argv = process.argv.slice(2);
  const opt = (name) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv.splice(i, 2)[1] : undefined;
  };
  const flag = (name) => {
    const i = argv.indexOf(name);
    return i >= 0 ? (argv.splice(i, 1), true) : false;
  };
  const rpcUrl = opt('--rpc');
  const passphrase = opt('--passphrase');
  const threshold = Number(opt('--threshold') ?? 518_400);
  const force = flag('--force');
  const perEntry = flag('--per-entry');
  const extra = [];
  for (let k; (k = opt('--key')); ) extra.push(xdr.LedgerKey.fromXDR(k, 'base64'));
  if (!rpcUrl || !passphrase || !process.env.NIDO_KEEPER_SECRET) throw new Error('needs --rpc, --passphrase and NIDO_KEEPER_SECRET');
  const chain = new Chain({ rpcUrl, passphrase });
  const source = Keypair.fromSecret(process.env.NIDO_KEEPER_SECRET);
  const groups = [];
  for (const c of argv) {
    const keys = await contractKeys(chain, c);
    if (perEntry) keys.forEach((k, i) => groups.push({ label: `${c} ${i ? 'code' : 'instance'}`, keys: [k] }));
    else groups.push({ label: c, keys });
  }
  extra.forEach((k, i) => groups.push({ label: `key ${i}`, keys: [k] }));
  const done = await keep(chain, source, groups, { threshold, force });
  for (const d of done) console.log(JSON.stringify(d));
  console.error(`keeper: ${done.length} transactions, ${done.reduce((n, d) => n + (d.feeCharged ?? 0), 0)} stroops`);
}
