/**
 * The transaction scan (spec §10.2, `src/votes.ts`) on real mainnet
 * transactions: 17 recorded from `getTransactions` pages in stellar-xdr JSON
 * (`fixtures/mainnet-transactions.json.gz`, from the sample of spec §12 and
 * `research/email-recovery/eval/mainnet/scan.mjs`): classic, Soroban and
 * fee-bumped, successful and failed. The walk reads each without error and
 * finds no vote at a controller that is not on mainnet; the same real
 * envelope, with one authorization entry turned into a contract guardian's
 * nested `submit_guardian`, yields exactly that vote.
 */
import { readFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { StrKey } from '@stellar/stellar-sdk';
import { describe, expect, it } from 'vitest';
import { type JsonTransaction, guardianVotes, writtenAttempts } from '../src/votes.js';

const { transactions } = JSON.parse(gunzipSync(readFileSync(new URL('./fixtures/mainnet-transactions.json.gz', import.meta.url))).toString('utf8')) as {
  transactions: JsonTransaction[];
};
const CONTROLLER = StrKey.encodeContract(Buffer.alloc(32, 0xc1));
const GUARDIAN = StrKey.encodeContract(Buffer.alloc(32, 0xe1));

/** Every authorization entry of an envelope, wherever it sits. */
function entries(v: unknown, out: Record<string, unknown>[] = []): Record<string, unknown>[] {
  if (Array.isArray(v)) for (const x of v) entries(x, out);
  else if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    if ('credentials' in o && 'root_invocation' in o) out.push(o);
    for (const x of Object.values(o)) entries(x, out);
  }
  return out;
}

describe('the transaction scan on recorded mainnet transactions', () => {
  it('reads classic, Soroban and fee-bumped transactions, successful or failed, and finds no vote at another controller', () => {
    expect(transactions).toHaveLength(17);
    const kinds = new Set(transactions.map((t) => `${JSON.stringify(t.envelopeJson).includes('tx_fee_bump') ? 'fee-bump ' : ''}${t.status}`));
    expect(kinds).toEqual(new Set(['SUCCESS', 'FAILED', 'fee-bump SUCCESS']));
    expect(transactions.filter((t) => entries(t.envelopeJson).length).length).toBeGreaterThanOrEqual(6);
    for (const t of transactions) {
      expect(guardianVotes(t, CONTROLLER)).toEqual([]);
      expect(writtenAttempts(t.resultMetaJson, CONTROLLER)).toEqual([]);
    }
  });

  it('a real fee-bumped envelope whose entry becomes a contract guardian’s nested submit_guardian yields that one vote', () => {
    const real = transactions.find((t) => JSON.stringify(t.envelopeJson).includes('tx_fee_bump') && entries(t.envelopeJson).length)!;
    const tx = structuredClone(real);
    const [entry] = entries(tx.envelopeJson);
    entry!.credentials = { address: { address: GUARDIAN, nonce: '7', signature_expiration_ledger: tx.ledger + 100, signature: 'void' } };
    const root = entry!.root_invocation as { sub_invocations: unknown[] };
    const digest = 'ab'.repeat(32);
    root.sub_invocations = [
      ...root.sub_invocations,
      { function: { contract_fn: { contract_address: CONTROLLER, function_name: 'submit_guardian', args: [{ bytes: digest }] } }, sub_invocations: [] },
    ];
    expect(guardianVotes(tx, CONTROLLER)).toEqual([{ guardian: GUARDIAN, fn: 'submit_guardian', digest, txHash: real.txHash, ledger: real.ledger }]);
    expect(guardianVotes({ ...tx, status: 'FAILED' }, CONTROLLER)).toEqual([]);
  });
});
