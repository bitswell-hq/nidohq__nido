/**
 * The email guardian on chain (`docs/email-recovery/spec.md` §8): its
 * configuration and approval as Soroban values, its deployment, and the
 * `submit_guardian` invocation whose guardian authorization entry carries
 * the email approval.
 *
 * The encodings are the contract's own `#[contracttype]` structs
 * (`contracts/email-guardian/src/lib.rs`): a struct is a map from field
 * symbols, in sorted order, to values; `BytesN<32>` and `Bytes` are bytes;
 * `Vec<KeyPin>` a vector. `emailGuardian.test.ts` pins them to bytes the
 * contract crate's own tests write.
 */

import { Address, Contract, Operation, StrKey, hash, rpc, scValToNative, xdr } from '@stellar/stellar-sdk';
import { Buffer } from 'buffer';
import { NETWORK_PASSPHRASE, RPC_URL } from '../network.js';
import { simulateRead } from '../simulateRead.js';

export const ALLOW_ALL = 31;

export interface KeyPin {
  root: Uint8Array;
  /** The last ledger close time (Unix seconds) the pin is accepted at. */
  validUntil: number;
}

export interface GuardianConfig {
  account: string;
  controller: string;
  /** `C`, 32 octets. */
  commitment: Uint8Array;
  registry: string;
  keyPin: KeyPin[];
  allowedActions: number;
  verifier: string;
  /** `sha256` of the verifier's key, 32 octets. */
  circuitId: Uint8Array;
}

export interface EmailApproval {
  /** The Perch statement encoding. */
  statement: Uint8Array;
  keyRoot: Uint8Array;
  proof: Uint8Array;
}

const sym = (s: string) => xdr.ScVal.scvSymbol(s);
const bytes = (b: Uint8Array) => xdr.ScVal.scvBytes(Buffer.from(b));
const addr = (a: string) => Address.fromString(a).toScVal();

/** A `#[contracttype]` struct: fields sorted by name. */
function struct(fields: Record<string, xdr.ScVal>): xdr.ScVal {
  return xdr.ScVal.scvMap(
    Object.keys(fields)
      .sort()
      .map((k) => new xdr.ScMapEntry({ key: sym(k), val: fields[k]! })),
  );
}

function check32(name: string, b: Uint8Array) {
  if (b.length !== 32) throw new Error(`${name} is 32 octets`);
}

export function keyPinScVal(p: KeyPin): xdr.ScVal {
  check32('a pin root', p.root);
  if (!Number.isSafeInteger(p.validUntil) || p.validUntil < 0) throw new Error('a pin expiry is a close time in seconds');
  return struct({ root: bytes(p.root), valid_until: xdr.ScVal.scvU64(new xdr.Uint64(BigInt(p.validUntil))) });
}

export function guardianConfigScVal(c: GuardianConfig): xdr.ScVal {
  check32('the commitment', c.commitment);
  check32('the circuit id', c.circuitId);
  return struct({
    account: addr(c.account),
    controller: addr(c.controller),
    commitment: bytes(c.commitment),
    registry: addr(c.registry),
    key_pin: xdr.ScVal.scvVec(c.keyPin.map(keyPinScVal)),
    allowed_actions: xdr.ScVal.scvU32(c.allowedActions),
    verifier: addr(c.verifier),
    circuit_id: bytes(c.circuitId),
  });
}

/** `GuardianConfig` from `config()`'s native value. */
export function guardianConfigFromNative(v: unknown): GuardianConfig {
  const m = v as Record<string, unknown>;
  const b = (x: unknown) => new Uint8Array(x as Uint8Array);
  return {
    account: String(m.account),
    controller: String(m.controller),
    commitment: b(m.commitment),
    registry: String(m.registry),
    keyPin: ((m.key_pin as Record<string, unknown>[]) ?? []).map((p) => ({ root: b(p.root), validUntil: Number(p.valid_until) })),
    allowedActions: Number(m.allowed_actions),
    verifier: String(m.verifier),
    circuitId: b(m.circuit_id),
  };
}

export function emailApprovalScVal(a: EmailApproval): xdr.ScVal {
  check32('the key root', a.keyRoot);
  return struct({ statement: bytes(a.statement), key_root: bytes(a.keyRoot), proof: bytes(a.proof) });
}

/**
 * The guardian's authorization entry for `fnName` on `controller`: the host
 * asks the guardian to authorize exactly `(digest,)`
 * (`require_auth_for_args`), and the entry's signature is the approval. The
 * guardian does not read the nonce or expiration (spec §8.3); the host only
 * needs the nonce unused for this guardian.
 */
export function emailApprovalEntry(e: {
  guardian: string;
  controller: string;
  fnName: 'submit_guardian' | 'approve_change';
  digest: Uint8Array;
  approval: EmailApproval;
  nonce: bigint;
  expirationLedger: number;
}): xdr.SorobanAuthorizationEntry {
  check32('the digest', e.digest);
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
      new xdr.SorobanAddressCredentials({
        address: Address.fromString(e.guardian).toScAddress(),
        nonce: xdr.Int64.fromString(e.nonce.toString()),
        signatureExpirationLedger: e.expirationLedger,
        signature: emailApprovalScVal(e.approval),
      }),
    ),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: Address.fromString(e.controller).toScAddress(),
          functionName: e.fnName,
          args: [bytes(e.digest)],
        }),
      ),
      subInvocations: [],
    }),
  });
}

/** `controller.submit_guardian(account, attempt_id, domain, guardian)` with the guardian's entry attached. */
export function submitGuardianOperation(p: {
  controller: string;
  account: string;
  attemptId: bigint;
  domain: number;
  guardian: string;
  entry: xdr.SorobanAuthorizationEntry;
}): xdr.Operation {
  const func = xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: Address.fromString(p.controller).toScAddress(),
      functionName: 'submit_guardian',
      args: [addr(p.account), xdr.ScVal.scvU64(xdr.Uint64.fromString(p.attemptId.toString())), xdr.ScVal.scvU32(p.domain), addr(p.guardian)],
    }),
  );
  return Operation.invokeHostFunction({ func, auth: [p.entry] });
}

/** A random authorization nonce (a non-negative i64). */
export function randomNonce(): bigint {
  const b = crypto.getRandomValues(new Uint8Array(8));
  b[0] = b[0]! & 0x7f;
  return b.reduce((acc, x) => (acc << 8n) | BigInt(x), 0n);
}

/** The address `deployer` gets for `salt` on `networkPassphrase` (CAP-46 contract id preimage). */
export function deployedAddress(deployer: string, salt: Uint8Array, networkPassphrase = NETWORK_PASSPHRASE): string {
  const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
    new xdr.HashIdPreimageContractId({
      networkId: hash(Buffer.from(networkPassphrase)),
      contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
        new xdr.ContractIdPreimageFromAddress({ address: Address.fromString(deployer).toScAddress(), salt: Buffer.from(salt) }),
      ),
    }),
  );
  return StrKey.encodeContract(hash(preimage.toXDR()));
}

/** Deploy a guardian with `config` from `deployer`'s account (it pays and authorizes). */
export function deployGuardianOperation(p: { deployer: string; wasmHash: Uint8Array; salt: Uint8Array; config: GuardianConfig }): xdr.Operation {
  return Operation.createCustomContract({
    address: Address.fromString(p.deployer),
    wasmHash: Buffer.from(p.wasmHash),
    salt: Buffer.from(p.salt),
    constructorArgs: [guardianConfigScVal(p.config)],
  });
}

/** The guardian's `config()`, or `undefined` when `address` is not a guardian. */
export async function readGuardianConfig(address: string, server = new rpc.Server(RPC_URL)): Promise<GuardianConfig | undefined> {
  const v = await simulateRead(server, address, 'config', []);
  return v ? guardianConfigFromNative(v) : undefined;
}

/** The wasm hash a contract runs, or `undefined` when it has no wasm instance. */
export async function contractWasmHash(address: string, server = new rpc.Server(RPC_URL)): Promise<string | undefined> {
  try {
    const entry = await server.getContractData(address, xdr.ScVal.scvLedgerKeyContractInstance(), rpc.Durability.Persistent);
    const exe = entry.val.contractData().val().instance().executable();
    return exe.switch().name === 'contractExecutableWasm' ? Buffer.from(exe.wasmHash()).toString('hex') : undefined;
  } catch {
    return undefined;
  }
}

export { scValToNative };
