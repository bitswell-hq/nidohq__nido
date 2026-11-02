/**
 * Guardian votes, read from the network's transactions
 * (`docs/email-recovery/spec.md` §10.2). Perch emits no event when a
 * guardian's vote is recorded below quorum, or for a cancellation's or a
 * change's approval; but every such vote by a contract guardian is a
 * successful transaction carrying that guardian's Soroban authorization
 * entry for the controller's `submit_guardian` or `approve_change`, and the
 * attempt it changed is in the transaction's meta. So a vote is found per
 * vote, whatever the number of attempts open.
 *
 * Transactions come from Stellar RPC `getTransactions` with `xdrFormat:
 * "json"`: the RPC decodes them with stellar-xdr's own JSON encoding, so a
 * transaction using XDR newer than this host's SDK still reads. The walk is
 * structural: an authorization entry is any object with `credentials` and
 * `root_invocation`, wherever the envelope (plain or fee-bumped) holds it;
 * its signer is the contract address its credentials name (the `address`
 * of `credentials.address`, or of a newer credentials variant); the
 * controller's function may be the root of its invocation tree or any
 * sub-invocation; an attempt is any created, updated or restored contract
 * data entry of the controller whose value is an `Attempt` (Perch's
 * `perch-recovery/src/types.rs`: `id`, `state`, `guardians`,
 * `cancel_guardians`, `evidence_deadline`).
 */

/** One transaction as `getTransactions` answers with `xdrFormat: "json"`. */
export interface JsonTransaction {
  status: string;
  txHash: string;
  applicationOrder: number;
  ledger: number;
  envelopeJson: unknown;
  resultMetaJson?: unknown;
}

/** An attempt a transaction wrote, as its meta holds it. */
export interface WrittenAttempt {
  id: bigint;
  state: string;
  guardians: string[];
  cancelGuardians: string[];
  evidenceDeadline: number;
}

/** A contract guardian's authorized vote at the controller. */
export interface GuardianVote {
  guardian: string;
  fn: 'submit_guardian' | 'approve_change';
  /** The statement digest the guardian authorized (`require_auth_for_args((digest,))`), hex. */
  digest: string;
  txHash: string;
  ledger: number;
}

const VOTE_FNS = new Set(['submit_guardian', 'approve_change']);
const CONTRACT = /^C[A-Z2-7]{55}$/;

type Json = unknown;
const isObject = (v: Json): v is Record<string, Json> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Every object below `v` (and `v` itself) for which `pick` holds, depth first. */
function* objects(v: Json, pick: (o: Record<string, Json>) => boolean): Generator<Record<string, Json>> {
  if (Array.isArray(v)) {
    for (const x of v) yield* objects(x, pick);
  } else if (isObject(v)) {
    if (pick(v)) yield v;
    for (const x of Object.values(v)) yield* objects(x, pick);
  }
}

/** The contract an authorization entry's credentials name: `{<variant>: {address, …}}`. */
function signer(credentials: Json): string | undefined {
  if (!isObject(credentials)) return undefined;
  for (const variant of Object.values(credentials)) {
    if (isObject(variant) && typeof variant.address === 'string' && CONTRACT.test(variant.address)) return variant.address;
  }
  return undefined;
}

/** The controller calls in an authorized invocation tree that are votes, with their first argument's bytes. */
function voteCalls(invocation: Json, controller: string): { fn: GuardianVote['fn']; digest: string }[] {
  const out: { fn: GuardianVote['fn']; digest: string }[] = [];
  for (const node of objects(invocation, (o) => isObject(o.contract_fn))) {
    const call = node.contract_fn as Record<string, Json>;
    if (call.contract_address !== controller || !VOTE_FNS.has(String(call.function_name))) continue;
    const first = Array.isArray(call.args) ? call.args[0] : undefined;
    const digest = isObject(first) && typeof first.bytes === 'string' ? first.bytes : '';
    out.push({ fn: call.function_name as GuardianVote['fn'], digest });
  }
  return out;
}

/**
 * The votes at `controller` that a successful transaction authorizes for
 * contract guardians, one per (guardian, call).
 */
export function guardianVotes(tx: JsonTransaction, controller: string): GuardianVote[] {
  if (tx.status !== 'SUCCESS') return [];
  const out: GuardianVote[] = [];
  const seen = new Set<string>();
  for (const entry of objects(tx.envelopeJson, (o) => 'credentials' in o && 'root_invocation' in o)) {
    const guardian = signer(entry.credentials);
    if (!guardian) continue;
    for (const c of voteCalls(entry.root_invocation, controller)) {
      const key = `${guardian}|${c.fn}|${c.digest}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ guardian, ...c, txHash: tx.txHash, ledger: tx.ledger });
    }
  }
  return out;
}

/** A stellar-xdr JSON `ScVal` as a plain value: maps by symbol key, vecs as arrays, numbers as bigint. */
export function scValFromJson(v: Json): unknown {
  if (!isObject(v)) return v === 'void' ? undefined : v;
  const [kind, x] = Object.entries(v)[0] ?? [];
  switch (kind) {
    case 'u32':
    case 'i32':
      return Number(x);
    case 'u64':
    case 'i64':
    case 'u128':
    case 'i128':
      return BigInt(String(x));
    case 'vec':
      return Array.isArray(x) ? x.map(scValFromJson) : [];
    case 'map': {
      const o: Record<string, unknown> = {};
      for (const e of Array.isArray(x) ? x : []) {
        if (!isObject(e)) continue;
        const k = scValFromJson(e.key);
        if (typeof k === 'string') o[k] = scValFromJson(e.val);
      }
      return o;
    }
    case 'symbol':
    case 'string':
    case 'address':
    case 'bytes':
    case 'bool':
      return x;
    default:
      return x;
  }
}

/** The `Attempt` values of `controller` a transaction created, updated or restored. */
export function writtenAttempts(meta: Json, controller: string): WrittenAttempt[] {
  const out: WrittenAttempt[] = [];
  for (const change of objects(meta, (o) => ['created', 'updated', 'restored'].some((k) => isObject(o[k])))) {
    const entry = (change.created ?? change.updated ?? change.restored) as Record<string, Json>;
    for (const cd of objects(entry, (o) => isObject(o.contract_data))) {
      const data = cd.contract_data as Record<string, Json>;
      if (data.contract !== controller) continue;
      const a = scValFromJson(data.val) as Record<string, unknown> | undefined;
      if (!isObject(a) || typeof a.id !== 'bigint' || !Array.isArray(a.guardians) || !Array.isArray(a.cancel_guardians)) continue;
      const state = Array.isArray(a.state) ? a.state[0] : a.state;
      out.push({
        id: a.id,
        state: String(state),
        guardians: a.guardians.map(String),
        cancelGuardians: a.cancel_guardians.map(String),
        evidenceDeadline: Number(a.evidence_deadline ?? 0),
      });
    }
  }
  return out;
}
