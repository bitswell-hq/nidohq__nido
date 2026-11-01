/**
 * The recovery circuit's inputs (`docs/email-recovery/spec.md` §6) from a
 * raw recovery email: `circuits/email-recovery/recovery`'s public inputs
 * `C`, `digest_hi`, `digest_lo`, `key_root` and its private witness, as a
 * noir_js input map or a nargo `Prover.toml`.
 *
 * `P2` is Barretenberg's Poseidon2 through bb.js, which Noir's
 * `Poseidon2::hash` (noir-lang/poseidon v0.2.0) and the Soroban host's
 * `poseidon2_permutation` both match; `test/recoveryInputs.test.ts` pins its
 * outputs to the values the circuit's own tests and the DKIM key registry
 * assert.
 *
 * `encodeRecoveryEmail` checks everything the circuit checks that it can
 * check cheaply (the aligned signature verifies under the key, the Subject
 * carries this statement's blinded digest, the key's leaf reaches the given
 * root), so a wallet learns of a bad input before it starts proving.
 */
import { BarretenbergSync, Fr } from '@aztec/bb.js';
import {
  DkimHeaderError,
  type DkimSignatureField,
  alignedSignatures,
  blockFieldValue,
  domainOf,
  fromAddress,
  parseMessage,
  signatureValue,
  signedHeaderBlock,
} from './dkimHeader.js';

/** The BN254 scalar field modulus `r`. */
export const FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;

/** Domain tags, `BE(sha256("nido/email-recovery/v1/<name>")) mod r` (spec §2). */
export const DOM_COMMIT = 0x28c44578265e026b7cecaa4b01b79fef9a1d1e4340e270596de3a724f044ee56n;
export const DOM_BLIND = 0x2e13b680b3b2cbdab71f094fdf34f9ccd940c01ac6158ebc826ee5bdb05d0726n;
export const DOM_KEY = 0x1f6d4c7ed15d3b9480457cf9ff55d0ffff201158605d66399703659bf4d765f5n;
export const DOM_LEAF = 0x1ddd7b4c7e2eba95d7da44139642c575589aa685188088b0555d3d4fbb5b1f7en;
export const DOM_PIN_SALT = 0x03d73ecb3a706d8271405c0c77fb8020c22717b7db10c5eb91f480ea1456bff6n;

/**
 * The DKIM key registry's launch allowlist (`nido_dkim_registry::LAUNCH_DOMAINS`,
 * spec §7.6): the From domains an enrollment may use.
 */
export const LAUNCH_DOMAINS = [
  'gmail.com',
  'outlook.com',
  'hotmail.com',
  'icloud.com',
  'yahoo.com',
  'proton.me',
  'protonmail.com',
  'fastmail.com',
  'gmx.net',
  'gmx.de',
  'web.de',
] as const;

/** The recovery Subject phrase, trailing space included (spec §4.2). */
export const RECOVERY_PHRASE = 'APPROVE NIDO ACCOUNT RECOVERY ';
/** The circuit's bound on the signed header block, in octets. */
export const HEADER_MAX = 1536;
export const ADDR_MAX = 124;
export const DOMAIN_MAX = 62;
export const REGISTRY_DEPTH = 16;
export const RSA_LIMBS = 18;
const LIMB_BITS = 120n;

let api: BarretenbergSync | undefined;

/** Loads Barretenberg's WASM once; every hash below needs it. */
export async function initHashes(): Promise<void> {
  api ??= await BarretenbergSync.initSingleton();
}

/** `P2(x_1, .., x_n)`: Noir's `Poseidon2::hash([x_1, .., x_n], n)`. */
export function p2(inputs: bigint[]): bigint {
  if (!api) throw new Error('email-recovery: call initHashes() first');
  const out = api.poseidon2Hash(inputs.map((x) => new Fr(x))).toBuffer();
  return bytesToBigInt(out);
}

export function bytesToBigInt(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const x of bytes) v = (v << 8n) | BigInt(x);
  return v;
}

export function bigIntToBytes(v: bigint, length: number): Uint8Array {
  if (v < 0n || v >= 1n << BigInt(8 * length)) throw new RangeError(`value does not fit in ${length} bytes`);
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** `hex(x)`: 64 lowercase hex characters of the 32-byte big-endian encoding (spec §2). */
export function fieldHex(x: bigint): string {
  return x.toString(16).padStart(64, '0');
}

const hex0x = (x: bigint) => `0x${x.toString(16)}`;

/** `split(x)` of a 32-byte value: the big-endian halves (spec §2, §3.2). */
export function splitDigest(digest: Uint8Array): [bigint, bigint] {
  if (digest.length !== 32) throw new RangeError('a digest is 32 bytes');
  return [bytesToBigInt(digest.subarray(0, 16)), bytesToBigInt(digest.subarray(16))];
}

/** `pack(bytes, max)`: right-padded with zeros to `max`, read as 31-byte big-endian chunks (spec §2). */
export function pack(bytes: Uint8Array, max: number): bigint[] {
  if (bytes.length < 1 || bytes.length > max) throw new RangeError(`pack: ${bytes.length} bytes, bound ${max}`);
  const padded = new Uint8Array(max);
  padded.set(bytes);
  const out: bigint[] = [];
  for (let at = 0; at < max; at += 31) out.push(bytesToBigInt(padded.subarray(at, Math.min(at + 31, max))));
  return out;
}

const ascii = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0));

/** `C = P2(DOM_COMMIT, len, pack(address, 124), account_code)` (spec §5.3). */
export function addressCommitment(address: string, accountCode: bigint): bigint {
  const bytes = ascii(address);
  return p2([DOM_COMMIT, BigInt(bytes.length), ...pack(bytes, ADDR_MAX), accountCode]);
}

/** `T = P2(DOM_BLIND, digest_hi, digest_lo, rho)` (spec §4.2). */
export function blindedDigest(digest: Uint8Array, rho: bigint): bigint {
  const [hi, lo] = splitDigest(digest);
  return p2([DOM_BLIND, hi, lo, rho]);
}

/** The recovery email's Subject for `digest` (spec §4.2), without the `Subject:` name. */
export function recoverySubject(digest: Uint8Array, rho: bigint): string {
  return RECOVERY_PHRASE + fieldHex(blindedDigest(digest, rho));
}

/** 18 little-endian limbs of 120 bits (spec §7.1). */
export function limbs(x: bigint): bigint[] {
  const out: bigint[] = [];
  const mask = (1n << LIMB_BITS) - 1n;
  for (let i = 0; i < RSA_LIMBS; i++) {
    out.push(x & mask);
    x >>= LIMB_BITS;
  }
  if (x !== 0n) throw new RangeError('value does not fit in 18 limbs of 120 bits');
  return out;
}

/** `key_hash = P2(DOM_KEY, limbs(n))` (spec §7.1). */
export function keyHash(modulus: bigint): bigint {
  return p2([DOM_KEY, ...limbs(modulus)]);
}

/** `leaf = P2(DOM_LEAF, len(domain), pack(domain, 62), key_hash)` (spec §7.2). */
export function registryLeaf(domain: string, keyHashValue: bigint): bigint {
  const bytes = ascii(domain);
  return p2([DOM_LEAF, BigInt(bytes.length), ...pack(bytes, DOMAIN_MAX), keyHashValue]);
}

/** Leaf 0 of a key pin tree: `P2(DOM_PIN_SALT, account_code)` (spec §7.4). */
export function pinSalt(accountCode: bigint): bigint {
  return p2([DOM_PIN_SALT, accountCode]);
}

/** `Z_0 = 0`, `Z_{i+1} = P2(Z_i, Z_i)`: the roots of empty subtrees (spec §7.2). */
export function emptySubtrees(): bigint[] {
  const z = [0n];
  for (let i = 0; i < REGISTRY_DEPTH; i++) z.push(p2([z[i]!, z[i]!]));
  return z;
}

/** The root reached from `leaf` at `index` through `siblings`, lowest level first. */
export function merkleRoot(leaf: bigint, index: number, siblings: bigint[]): bigint {
  if (siblings.length !== REGISTRY_DEPTH) throw new RangeError(`a key path has ${REGISTRY_DEPTH} siblings`);
  if (!Number.isInteger(index) || index < 0 || index >= 1 << REGISTRY_DEPTH) throw new RangeError('leaf index out of range');
  let node = leaf;
  siblings.forEach((s, level) => {
    node = (index >> level) & 1 ? p2([s, node]) : p2([node, s]);
  });
  return node;
}

/** The depth-16 path of `leaves[index]` in the tree whose first leaves are `leaves` (the rest empty). */
export function treePath(leaves: bigint[], index: number): bigint[] {
  if (index < 0 || index >= leaves.length) throw new RangeError('no leaf at that index');
  const zeros = emptySubtrees();
  const siblings: bigint[] = [];
  let level = [...leaves];
  let at = index;
  for (let depth = 0; depth < REGISTRY_DEPTH; depth++) {
    const sibling = at ^ 1;
    siblings.push(sibling < level.length ? level[sibling]! : zeros[depth]!);
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) next.push(p2([level[i]!, i + 1 < level.length ? level[i + 1]! : zeros[depth]!]));
    level = next;
    at >>= 1;
  }
  return siblings;
}

/** A key-tree path: the root the proof is made against, the leaf index, and its siblings. */
export interface KeyPath {
  root: bigint;
  index: number;
  siblings: bigint[];
}

/** Everything the circuit takes, as bigints and octets. */
export interface RecoveryWitness {
  commitment: bigint;
  digestHi: bigint;
  digestLo: bigint;
  keyRoot: bigint;
  header: Uint8Array;
  modulus: bigint;
  signature: bigint;
  rho: bigint;
  accountCode: bigint;
  keyIndex: number;
  keySiblings: bigint[];
  /** noir-bignum's Barrett hint; `barrettHint(modulus)` unless given. */
  redc?: bigint;
}

/** noir-bignum's Barrett hint for an RSA-2048 modulus: `floor(2^4100 / n)`. */
export function barrettHint(modulus: bigint): bigint {
  return (1n << 4100n) / modulus;
}

/**
 * The witness as noir_js's input map for `circuits/email-recovery/recovery`,
 * or for a build of the same relation with another header bound.
 */
export function noirInputs(w: RecoveryWitness, headerMax: number = HEADER_MAX): Record<string, unknown> {
  if (w.header.length > headerMax) throw new RangeError(`the signed header block is ${w.header.length} octets; the circuit takes at most ${headerMax}`);
  const storage = new Array<number>(headerMax).fill(0);
  w.header.forEach((b, i) => (storage[i] = b));
  return {
    commitment: hex0x(w.commitment),
    digest_hi: hex0x(w.digestHi),
    digest_lo: hex0x(w.digestLo),
    key_root: hex0x(w.keyRoot),
    header: { storage, len: w.header.length },
    modulus: limbs(w.modulus).map(hex0x),
    redc: limbs(w.redc ?? barrettHint(w.modulus)).map(hex0x),
    signature: limbs(w.signature).map(hex0x),
    rho: hex0x(w.rho),
    account_code: hex0x(w.accountCode),
    key_index: hex0x(BigInt(w.keyIndex)),
    key_siblings: w.keySiblings.map(hex0x),
  };
}

/** The same input map as nargo's `Prover.toml`. */
export function proverToml(w: RecoveryWitness, headerMax: number = HEADER_MAX): string {
  const m = noirInputs(w, headerMax);
  const header = m.header as { storage: number[]; len: number };
  const quote = (v: unknown) => (Array.isArray(v) ? `[${v.map((x) => `"${x}"`).join(', ')}]` : `"${v}"`);
  const lines = Object.entries(m)
    .filter(([k]) => k !== 'header')
    .map(([k, v]) => `${k} = ${quote(v)}`);
  return `${lines.join('\n')}\n\n[header]\nstorage = [${header.storage.join(', ')}]\nlen = ${header.len}\n`;
}

/** The public inputs in circuit order, each 32 bytes big-endian: what the guardian hands the verifier. */
export function publicInputBytes(w: RecoveryWitness): Uint8Array {
  const out = new Uint8Array(128);
  [w.commitment, w.digestHi, w.digestLo, w.keyRoot].forEach((x, i) => out.set(bigIntToBytes(x, 32), 32 * i));
  return out;
}

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

/** DigestInfo for SHA-256 (RFC 8017 section 9.2, note 1). */
const SHA256_DIGEST_INFO = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data as Uint8Array<ArrayBuffer>));
}

/** Whether `signature` is a PKCS#1 v1.5 SHA-256 signature of `block` under an RSA-2048 `modulus`, `e = 65537`, `s < n`. */
export async function verifiesUnder(block: Uint8Array, signature: bigint, modulus: bigint): Promise<boolean> {
  if (modulus >> 2047n !== 1n || signature >= modulus) return false;
  const em = new Uint8Array(256);
  em[1] = 0x01;
  em.fill(0xff, 2, 256 - 52);
  em.set(SHA256_DIGEST_INFO, 256 - 51);
  em.set(await sha256(block), 256 - 32);
  return modpow(signature, 65537n, modulus) === bytesToBigInt(em);
}

export interface RecoveryEmailInput {
  /** The raw message as received, CRLF line endings. */
  eml: Uint8Array;
  /** The 16-byte `account_code` (spec §5.1). */
  accountCode: bigint;
  /** The `rho` the Subject was built with (spec §4.2). */
  rho: bigint;
  /** The Perch statement encoding whose digest the email approves. */
  statement: Uint8Array;
  /** The RSA-2048 modulus of the key that signed the email. */
  modulus: bigint;
  /** The key's path in the registry tree or the pin tree. */
  keyPath: KeyPath;
}

export interface EncodedRecoveryEmail {
  witness: RecoveryWitness;
  /** The From address exactly as signed. */
  address: string;
  /** The lowercase `d=`: the registry leaf's domain. */
  domain: string;
  selector: string;
  /** `sha256(statement)`. */
  digest: Uint8Array;
}

/** The aligned DKIM-Signature of `eml` that verifies under `modulus`, and the block it signs. */
export async function alignedSignedBlock(
  eml: Uint8Array,
  modulus: bigint,
): Promise<{ signature: DkimSignatureField; block: Uint8Array; value: bigint }> {
  const message = parseMessage(eml);
  const aligned = alignedSignatures(message);
  if (aligned.length === 0) throw new DkimHeaderError('no DKIM-Signature has a d= equal to the From domain');
  for (const signature of aligned) {
    const block = signedHeaderBlock(message, signature);
    const value = signatureValue(signature);
    if (await verifiesUnder(block, value, modulus)) return { signature, block, value };
  }
  throw new DkimHeaderError('no aligned DKIM-Signature verifies under this key');
}

/**
 * The circuit inputs for a recovery email, after checking that the proof
 * would succeed: the aligned signature verifies under `modulus`, the signed
 * Subject is the recovery Subject for this statement and `rho`, the key's
 * leaf reaches `keyPath.root`, and the block fits the circuit.
 */
export async function encodeRecoveryEmail(input: RecoveryEmailInput): Promise<EncodedRecoveryEmail> {
  await initHashes();
  const { signature, block, value } = await alignedSignedBlock(input.eml, input.modulus);
  if (block.length > HEADER_MAX) throw new DkimHeaderError(`the signed header block is ${block.length} octets; the circuit takes at most ${HEADER_MAX}`);
  const address = fromAddress(blockFieldValue(block, 'from'));
  const domain = signature.tags.get('d')!.toLowerCase();
  if (domainOf(address).toLowerCase() !== domain) throw new DkimHeaderError('d= is not the From domain');

  const digest = await sha256(input.statement);
  const subject = blockFieldValue(block, 'subject');
  if (subject !== recoverySubject(digest, input.rho)) {
    throw new DkimHeaderError("the signed Subject is not this statement's recovery Subject for this rho");
  }

  const leaf = registryLeaf(domain, keyHash(input.modulus));
  if (merkleRoot(leaf, input.keyPath.index, input.keyPath.siblings) !== input.keyPath.root) {
    throw new DkimHeaderError("the key's leaf does not reach the given root");
  }

  const [digestHi, digestLo] = splitDigest(digest);
  return {
    witness: {
      commitment: addressCommitment(address, input.accountCode),
      digestHi,
      digestLo,
      keyRoot: input.keyPath.root,
      header: block,
      modulus: input.modulus,
      signature: value,
      rho: input.rho,
      accountCode: input.accountCode,
      keyIndex: input.keyPath.index,
      keySiblings: input.keyPath.siblings,
    },
    address,
    domain,
    selector: signature.tags.get('s') ?? '',
    digest,
  };
}

/** A fresh `rho`: 31 random bytes, big-endian (spec §4.2). */
export function randomRho(): bigint {
  return bytesToBigInt(crypto.getRandomValues(new Uint8Array(31)));
}

/** A fresh `account_code`: 16 random bytes, big-endian (spec §5.1). */
export function randomAccountCode(): bigint {
  return bytesToBigInt(crypto.getRandomValues(new Uint8Array(16)));
}
