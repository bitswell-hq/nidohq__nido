/**
 * Controller events built with the Stellar SDK in the exact encoding the
 * recorded ones have (`#[contractevent]`: topic 0 the snake-case name,
 * topic 1 the account, data a map of the remaining fields), for cases the
 * recorded recovery does not contain; and transactions carrying a contract
 * guardian's vote, as `getTransactions` serves them.
 */
import { type RpcEvent, type RpcTransaction, eventId, ledgerCloseTime } from '@nidohq/email-mocks';
import { Account, Address, Keypair, Networks, Operation, TransactionBuilder, nativeToScVal, xdr } from '@stellar/stellar-sdk';

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

/** An `Attempt` as Perch stores it (`perch-recovery/src/types.rs`), the fields the host reads among others. */
export interface SyntheticAttempt {
  id: number;
  state?: 'Collecting' | 'Authorized' | 'Cancelled';
  guardians?: string[];
  cancelGuardians?: string[];
  evidenceDeadline?: number;
  epoch?: number;
}

function attemptScVal(a: SyntheticAttempt): xdr.ScVal {
  const vec = (xs: string[]) => xdr.ScVal.scvVec(xs.map((g) => new Address(g).toScVal()));
  const fields: [string, xdr.ScVal][] = [
    ['action', xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('LostKey')])],
    ['cancel_guardians', vec(a.cancelGuardians ?? [])],
    ['epoch', u64(a.epoch ?? 1)],
    ['evidence_deadline', u32(a.evidenceDeadline ?? 10_000_000)],
    ['guardians', vec(a.guardians ?? [])],
    ['id', u64(a.id)],
    ['state', xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(a.state ?? 'Collecting')])],
  ];
  return xdr.ScVal.scvMap(fields.map(([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: v })));
}

function attemptEntry(controller: string, ledger: number, a: SyntheticAttempt): xdr.LedgerEntry {
  return new xdr.LedgerEntry({
    lastModifiedLedgerSeq: ledger,
    data: xdr.LedgerEntryData.contractData(
      new xdr.ContractDataEntry({
        ext: new xdr.ExtensionPoint(0),
        contract: new Address(controller).toScAddress(),
        // Perch's key encoding is its own; the host reads only the value.
        key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol('collecting'), u64(a.id)]),
        durability: xdr.ContractDataDurability.temporary(),
        val: attemptScVal(a),
      }),
    ),
    ext: new xdr.LedgerEntryExt(0),
  });
}

let order = 0;

/**
 * A transaction carrying `guardian`'s authorization for the controller's
 * `fn` (`submit_guardian` with the attempt's id and domain, or
 * `approve_change`), as a wallet submits it, with the attempt it wrote in
 * its meta (a `state` then an `updated` change, in meta v3; the live
 * network's v4 meta holds the same changes, which the attack suite reads). `wrappedBy` puts the vote under another contract's call, the
 * guardian's authorization naming the controller's function as a
 * sub-invocation of that contract's.
 */
export function voteTransaction(o: {
  controller: string;
  account: string;
  guardian: string;
  ledger: number;
  fn?: 'submit_guardian' | 'approve_change';
  domain?: 0 | 1;
  digest?: Uint8Array;
  before?: SyntheticAttempt;
  after?: SyntheticAttempt;
  status?: 'SUCCESS' | 'FAILED';
  wrappedBy?: string;
}): RpcTransaction {
  const fn = o.fn ?? 'submit_guardian';
  const digest = o.digest ?? Buffer.alloc(32, 0xd1);
  const call = new xdr.InvokeContractArgs({
    contractAddress: new Address(o.controller).toScAddress(),
    functionName: fn,
    args: [xdr.ScVal.scvBytes(Buffer.from(digest))],
  });
  const voteFn = xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(call);
  const outer = o.wrappedBy
    ? xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({ contractAddress: new Address(o.wrappedBy).toScAddress(), functionName: 'relay', args: [] }),
      )
    : undefined;
  const invocation = outer
    ? new xdr.SorobanAuthorizedInvocation({ function: outer, subInvocations: [new xdr.SorobanAuthorizedInvocation({ function: voteFn, subInvocations: [] })] })
    : new xdr.SorobanAuthorizedInvocation({ function: voteFn, subInvocations: [] });
  const entry = new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: new Address(o.guardian).toScAddress(),
        nonce: xdr.Int64.fromString('7'),
        signatureExpirationLedger: o.ledger + 100,
        signature: xdr.ScVal.scvBytes(Buffer.alloc(64, 0x5a)),
      }),
    ),
    rootInvocation: invocation,
  });
  const attemptId = o.after?.id ?? o.before?.id ?? 0;
  const args =
    fn === 'submit_guardian'
      ? [new Address(o.account).toScVal(), u64(attemptId), u32(o.domain ?? 0), new Address(o.guardian).toScVal()]
      : [new Address(o.account).toScVal(), xdr.ScVal.scvVoid(), u32(o.ledger + 100), new Address(o.guardian).toScVal()];
  const target = o.wrappedBy
    ? new xdr.InvokeContractArgs({ contractAddress: new Address(o.wrappedBy).toScAddress(), functionName: 'relay', args: [] })
    : new xdr.InvokeContractArgs({ contractAddress: new Address(o.controller).toScAddress(), functionName: fn, args });
  const tx = new TransactionBuilder(new Account(Keypair.random().publicKey(), '1'), { fee: '100', networkPassphrase: Networks.STANDALONE })
    .addOperation(Operation.invokeHostFunction({ func: xdr.HostFunction.hostFunctionTypeInvokeContract(target), auth: [entry] }))
    .setTimeout(0)
    .build();
  const changes: xdr.LedgerEntryChange[] = [];
  if (o.before) changes.push(xdr.LedgerEntryChange.ledgerEntryState(attemptEntry(o.controller, o.ledger - 1, o.before)));
  if (o.after) changes.push((o.before ? xdr.LedgerEntryChange.ledgerEntryUpdated : xdr.LedgerEntryChange.ledgerEntryCreated)(attemptEntry(o.controller, o.ledger, o.after)));
  // The SDK's union for TransactionMeta has numeric arms and no named constructor.
  const Meta = xdr.TransactionMeta as unknown as new (arm: number, value: xdr.TransactionMetaV3) => xdr.TransactionMeta;
  const meta = new Meta(
    3,
    new xdr.TransactionMetaV3({
      ext: new xdr.ExtensionPoint(0),
      txChangesBefore: [],
      operations: [new xdr.OperationMeta({ changes })],
      txChangesAfter: [],
      sorobanMeta: null,
    }),
  );
  const result = new xdr.TransactionResult({
    feeCharged: xdr.Int64.fromString('100'),
    result: o.status === 'FAILED' ? xdr.TransactionResultResult.txFailed([]) : xdr.TransactionResultResult.txSuccess([]),
    ext: new xdr.TransactionResultExt(0),
  });
  return {
    status: o.status ?? 'SUCCESS',
    txHash: Buffer.from(tx.hash()).toString('hex'),
    applicationOrder: ++order,
    feeBump: false,
    envelopeXdr: tx.toEnvelope().toXDR('base64'),
    resultXdr: result.toXDR('base64'),
    resultMetaXdr: meta.toXDR('base64'),
    ledger: o.ledger,
  };
}
