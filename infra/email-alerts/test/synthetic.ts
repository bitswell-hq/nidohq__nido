/**
 * Controller events built with the Stellar SDK in the exact encoding the
 * recorded ones have (`#[contractevent]`: topic 0 the snake-case name,
 * topic 1 the account, data a map of the remaining fields), for cases the
 * recorded recovery does not contain.
 */
import { type RpcEvent, eventId, ledgerCloseTime } from '@nidohq/email-mocks';
import { Address, nativeToScVal, xdr } from '@stellar/stellar-sdk';

let tx = 900;

export function controllerEvent(
  controller: string,
  account: string,
  name: string,
  ledger: number,
  fields: [string, xdr.ScVal][],
): RpcEvent {
  tx++;
  const data = xdr.ScVal.scvMap(
    [...fields]
      .sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: v })),
  );
  return {
    type: 'contract',
    ledger,
    ledgerClosedAt: ledgerCloseTime(ledger).toISOString(),
    contractId: controller,
    id: eventId(ledger, tx, 0, 0),
    operationIndex: 0,
    transactionIndex: tx - 1,
    topic: [xdr.ScVal.scvSymbol(name).toXDR('base64'), new Address(account).toScVal().toXDR('base64')],
    value: data.toXDR('base64'),
    txHash: '00'.repeat(32),
  };
}

const u64 = (n: bigint | number) => nativeToScVal(BigInt(n), { type: 'u64' });
const u32 = (n: number) => nativeToScVal(n, { type: 'u32' });

export const attemptBegun = (c: string, a: string, ledger: number, attemptId: number) =>
  controllerEvent(c, a, 'attempt_begun', ledger, [
    ['action', u32(1)],
    ['attempt_id', u64(attemptId)],
    ['target_doc_hash', xdr.ScVal.scvBytes(Buffer.alloc(32, 1))],
  ]);

export const attemptAuthorized = (c: string, a: string, ledger: number, attemptId: number, expiresAt: number) =>
  controllerEvent(c, a, 'attempt_authorized', ledger, [
    ['attempt_id', u64(attemptId)],
    ['executable_after', u32(ledger + 10)],
    ['expires_at', u32(expiresAt)],
  ]);

export const attemptCancelled = (c: string, a: string, ledger: number, attemptId: number) =>
  controllerEvent(c, a, 'attempt_cancelled', ledger, [
    ['attempt_id', u64(attemptId)],
    ['counted', xdr.ScVal.scvBool(true)],
  ]);
