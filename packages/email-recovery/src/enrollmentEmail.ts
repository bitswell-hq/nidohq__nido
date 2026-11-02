/**
 * Enrollment (`docs/email-recovery/spec.md` §5): the enrollment email's
 * Subject, the wallet's local check of the email the user sent (§5.4), and
 * the guardian's salted key pin (§7.4).
 *
 * Nothing on chain verifies the enrollment email. The wallet checks it
 * because the commitment `C` is computed from its `From` address, and an
 * address the recovery circuit would refuse, or a provider whose format it
 * cannot prove, would leave the user with an email factor that can never
 * approve anything. So the check runs the recovery circuit itself on the
 * enrollment email's signed header block (`circuitAcceptsHeader`), after the
 * checks of the address's domain and the Subject that the circuit's
 * placeholder inputs leave out.
 */

import {
  ADDR_MAX,
  HEADER_MAX,
  type KeyPath,
  LAUNCH_DOMAINS,
  REGISTRY_DEPTH,
  addressCommitment,
  alignedSignedBlock,
  bigIntToBytes,
  fieldHex,
  initHashes,
  keyHash,
  merkleRoot,
  noirInputs,
  p2,
  pinSalt,
  registryLeaf,
  splitDigest,
  treePath,
} from './recoveryInputs.js';
import { DkimHeaderError, blockFieldValue, domainOf, fromAddress } from './dkimHeader.js';
import { type CompiledCircuit, solveWitness } from './prover/prove.js';

/** `BE(sha256("nido/email-recovery/v1/enroll")) mod r` (spec §2). */
export const DOM_ENROLL = 0x2bfe80f315441c3aadf9e7de0ab78fae545af772c0671cf5a512eb1ae713c9e7n;
/** The enrollment Subject phrase, trailing space included (spec §5.4). */
export const ENROLL_PHRASE = 'ENROLL NIDO ACCOUNT RECOVERY ';

/** Octets a recovery email's signed block has beyond the enrollment email's: its phrase is one octet longer (spec §4.2, §5.4). */
export const RECOVERY_SUBJECT_EXTRA = 1;

/** The recovery circuit's refusal of a header it accepts whose Subject is not a recovery Subject (`lib/src/subject.nr`). */
export const RECOVERY_PHRASE_REFUSAL = 'Subject: must start with the recovery phrase';

/** `E = P2(DOM_ENROLL, account_hi, account_lo, rho_e)` for a 32-octet account contract id. */
export function enrollmentValue(accountId: Uint8Array, rhoE: bigint): bigint {
  const [hi, lo] = splitDigest(accountId);
  return p2([DOM_ENROLL, hi, lo, rhoE]);
}

/** The enrollment email's Subject (spec §5.4), without the `Subject:` name. */
export function enrollmentSubject(accountId: Uint8Array, rhoE: bigint): string {
  return ENROLL_PHRASE + fieldHex(enrollmentValue(accountId, rhoE));
}

const ATEXT = "[A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~]+";
const LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
const ADDR_SPEC = new RegExp(`^${ATEXT}(?:\\.${ATEXT})*@${LABEL}(?:\\.${LABEL})+$`);
// The display name (spec §4.5): outside quoted strings `atext`, `.` and SP;
// inside one, printable ASCII except `"`, `\`, `<` and `>`, or a quoted-pair
// (`\` and printable ASCII except `<` and `>`).
const DISPLAY_NAME = /^(?:[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~. ]|"(?:[\x20\x21\x23-\x3b\x3d\x3f-\x5b\x5d-\x7e]|\\[\x20-\x3b\x3d\x3f-\x7e])*")*$/;

/** Whether `value` (a relaxed `From` value) has one of the two forms the circuit's parser accepts (spec §4.5). */
export function fromGrammarOk(value: string): boolean {
  const lt = value.indexOf('<');
  const address = lt < 0 ? value : value.slice(lt + 1, -1);
  if (lt >= 0 && (!value.endsWith('>') || !DISPLAY_NAME.test(value.slice(0, lt)))) return false;
  return address.length >= 1 && address.length <= ADDR_MAX && ADDR_SPEC.test(address);
}

export interface EnrollmentEmailInput {
  /** The raw enrollment email, CRLF line endings. */
  eml: Uint8Array;
  /** The recovery circuit's compiled artifact (`circuits/email-recovery/artifacts/recovery.json`), the one the prover proves with. */
  circuit: CompiledCircuit;
  /** The 32-octet contract id of the account being enrolled. */
  accountId: Uint8Array;
  /** The `rho_e` the Subject was built with. */
  rhoE: bigint;
  accountCode: bigint;
  /** The RSA-2048 modulus of the key that signed it (the registry's, or the one DNS publishes). */
  modulus: bigint;
  /** The From domains an enrollment may use; the registry's launch allowlist by default. */
  allowedDomains?: readonly string[];
}

export interface CheckedEnrollment {
  /** The From address exactly as signed: what `C` commits to. */
  address: string;
  /** The lowercase `d=`, which is the address's domain. */
  domain: string;
  selector: string;
  /** `C = P2(DOM_COMMIT, len, pack(address), account_code)`. */
  commitment: bigint;
  /** The registry-format leaf of the signing key (§7.2). */
  keyLeaf: bigint;
}

/**
 * Runs the recovery circuit itself on a signed header block: `circuit`
 * executed with noir_js, without a proof, under placeholder public inputs
 * and openings. The relation checks the header (C1, C2, the `From` grammar,
 * the DKIM-Signature tags and `d=`) and the Subject's position before it
 * compares the Subject with the recovery phrase
 * (`verify_dkim_header_with_hints` in `lib/src/dkim.nr`, then
 * `parse_subject`), so a header it accepts whose Subject is the enrollment
 * phrase is refused first by `RECOVERY_PHRASE_REFUSAL`. Any other refusal is
 * the circuit's verdict on how the provider signed, thrown as a
 * `DkimHeaderError`. The parser check pins the same order on real and fuzzed
 * headers (`research/email-recovery/eval/parser`, its cross-check).
 */
export async function circuitAcceptsHeader(
  circuit: CompiledCircuit,
  block: Uint8Array,
  modulus: bigint,
  signature: bigint,
  solve: typeof solveWitness = solveWitness,
): Promise<void> {
  let inputs: Record<string, unknown>;
  try {
    const placeholders = { commitment: 1n, digestHi: 2n, digestLo: 3n, keyRoot: 4n, rho: 5n, accountCode: 6n, keyIndex: 0 };
    inputs = noirInputs({ ...placeholders, header: block, modulus, signature, keySiblings: new Array<bigint>(REGISTRY_DEPTH).fill(0n) });
  } catch (e) {
    // The block is over the bound, or the key or the signature does not fit 2048 bits.
    throw new DkimHeaderError(`the recovery circuit cannot take this email: ${e instanceof Error ? e.message : String(e)}`);
  }
  let refusal: string;
  try {
    await solve(circuit, inputs);
    refusal = 'it accepted placeholder public inputs';
  } catch (e) {
    refusal = (e instanceof Error ? e.message : String(e)).replace(/^Circuit execution failed: /, '');
  }
  if (refusal !== RECOVERY_PHRASE_REFUSAL) throw new DkimHeaderError(`the recovery circuit refuses how this email is signed: ${refusal}`);
}

/**
 * The checks of spec §5.4 on the email the user sent: its aligned
 * DKIM-Signature verifies under `modulus`, its `From` address is at an
 * allowlisted domain, its Subject is the enrollment phrase for this account
 * and `rho_e`, and the recovery circuit accepts its signed header block
 * (`circuitAcceptsHeader`) with room for the recovery Subject's extra octet.
 * Throws a `DkimHeaderError` naming the first rule broken.
 */
export async function checkEnrollmentEmail(input: EnrollmentEmailInput): Promise<CheckedEnrollment> {
  await initHashes();
  const { signature, block, value } = await alignedSignedBlock(input.eml, input.modulus);
  const tags = signature.tags;
  if (tags.get('v') !== '1') throw new DkimHeaderError('the DKIM-Signature is not v=1');
  if (tags.get('a')?.toLowerCase() !== 'rsa-sha256') throw new DkimHeaderError('the DKIM-Signature is not rsa-sha256');
  if ((tags.get('c') ?? 'simple/simple').split('/')[0]!.toLowerCase() !== 'relaxed') {
    throw new DkimHeaderError('the provider signs headers with simple canonicalization, which the circuit refuses');
  }
  const signed = (tags.get('h') ?? '').split(':').map((h) => h.trim().toLowerCase());
  if (!signed.includes('from') || !signed.includes('subject')) throw new DkimHeaderError('the signature does not cover From and Subject');
  if (block.length > HEADER_MAX) throw new DkimHeaderError(`the signed header block is ${block.length} octets; the circuit takes at most ${HEADER_MAX}`);

  const fromValue = blockFieldValue(block, 'from');
  if (!fromGrammarOk(fromValue)) throw new DkimHeaderError('the From field is not in a form the recovery circuit accepts');
  const address = fromAddress(fromValue);
  const domain = tags.get('d')!.toLowerCase();
  if (domainOf(address).toLowerCase() !== domain) throw new DkimHeaderError('d= is not the From domain');
  if (!(input.allowedDomains ?? LAUNCH_DOMAINS).includes(domain)) {
    throw new DkimHeaderError(`${domain} is not one of the providers email recovery supports`);
  }
  if (blockFieldValue(block, 'subject') !== enrollmentSubject(input.accountId, input.rhoE)) {
    throw new DkimHeaderError('the signed Subject is not this enrollment’s Subject');
  }
  if (block.length + RECOVERY_SUBJECT_EXTRA > HEADER_MAX) {
    throw new DkimHeaderError(`the signed header block is ${block.length} octets; a recovery email from this inbox would exceed the circuit's ${HEADER_MAX}`);
  }
  await circuitAcceptsHeader(input.circuit, block, input.modulus, value);
  return {
    address,
    domain,
    selector: tags.get('s') ?? '',
    commitment: addressCommitment(address, input.accountCode),
    keyLeaf: registryLeaf(domain, keyHash(input.modulus)),
  };
}

/**
 * How long the guardian's key pin lasts (spec §7.4), in seconds of ledger
 * close time: 30 days, within the guardian's 365-day cap. The wallet, the
 * evaluation's harness and the integration tests read this one definition.
 */
export const PIN_LIFETIME_SECONDS = 2_592_000;

/** A key the pin holds: its domain (the `d=` it signs for) and modulus. */
export interface PinnedKey {
  domain: string;
  modulus: bigint;
}

/** The salted pin tree (spec §7.4): leaf 0 `P2(DOM_PIN_SALT, account_code)`, leaves 1 to k the keys' registry leaves. */
export interface PinTree {
  root: bigint;
  leaves: bigint[];
  /** The key path of the pinned key at `keys[i]` (tree index `i + 1`). */
  path(i: number): KeyPath;
}

export function pinTree(accountCode: bigint, keys: PinnedKey[]): PinTree {
  if (keys.length < 1) throw new RangeError('a pin holds at least one key');
  const leaves = [pinSalt(accountCode), ...keys.map((k) => registryLeaf(k.domain.toLowerCase(), keyHash(k.modulus)))];
  const siblings0 = treePath(leaves, 0);
  const root = merkleRoot(leaves[0]!, 0, siblings0);
  return {
    root,
    leaves,
    path: (i) => {
      const index = i + 1;
      if (index < 1 || index >= leaves.length) throw new RangeError('no pinned key there');
      return { root, index, siblings: treePath(leaves, index) };
    },
  };
}

/** A field element as the 32 octets a contract stores. */
export const fieldBytes = (x: bigint): Uint8Array => bigIntToBytes(x, 32);
