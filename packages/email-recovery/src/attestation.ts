/**
 * Verifying an AWS Nitro Enclaves attestation document, as AWS's
 * attestation process document specifies it
 * (https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md):
 * a COSE_Sign1 (RFC 9052; tagged 18 or untagged) with protected header
 * `{1: -35}` (ES384), an empty unprotected header, and a CBOR payload
 * carrying the module id, digest, timestamp, PCRs, the signing certificate,
 * its CA bundle, and optional `public_key`, `user_data`, and `nonce`.
 *
 * On top of AWS's checks, Nido's protocol (`docs/email-recovery/spec.md`
 * §10.3) requires a fresh nonce, a recent timestamp, a non-debug enclave,
 * an image measurement on the caller's allowlist, and a public key.
 */

import { decode, encode } from 'cborg';
import { buf, equal, sha256, toHex, utf8 } from './bytes.js';
import { importEcdsaKey, validateChain } from './x509.js';

export const MEASUREMENT_LABEL = 'nido/email-recovery/v1/enclave-image';

export interface AttestationDocument {
  moduleId: string;
  timestamp: number;
  digest: 'SHA384';
  pcrs: Map<number, Uint8Array>;
  certificate: Uint8Array;
  cabundle: Uint8Array[];
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  nonce?: Uint8Array;
}

const OPTIONAL_FIELDS = new Set(['public_key', 'user_data', 'nonce']);

const ALLOWED_FIELDS = new Set([
  'module_id',
  'digest',
  'timestamp',
  'pcrs',
  'certificate',
  'cabundle',
  'public_key',
  'user_data',
  'nonce',
]);

function bytesIn(v: unknown, min: number, max: number, what: string): Uint8Array {
  if (!(v instanceof Uint8Array) || v.length < min || v.length > max) {
    throw new Error(`attestation: bad ${what}`);
  }
  return v;
}

/** COSE_Sign1 → `[protected, payload, signature]`, structure checked. */
function coseSign1(bytes: Uint8Array): { protectedHeader: Uint8Array; payload: Uint8Array; signature: Uint8Array } {
  const tags: { [n: number]: (d: () => unknown) => unknown } = [];
  tags[18] = (d) => d();
  const arr = decode(bytes, { useMaps: true, strict: true, rejectDuplicateMapKeys: true, tags });
  if (!Array.isArray(arr) || arr.length !== 4) throw new Error('attestation: not a COSE_Sign1');
  const [prot, unprot, payload, signature] = arr as unknown[];
  const protectedHeader = bytesIn(prot, 1, 64, 'protected header');
  const header = decode(protectedHeader, { useMaps: true, strict: true, rejectDuplicateMapKeys: true });
  if (!(header instanceof Map) || header.size !== 1 || header.get(1) !== -35) {
    throw new Error('attestation: protected header is not {1: -35} (ES384)');
  }
  if (!(unprot instanceof Map) || unprot.size !== 0) throw new Error('attestation: unprotected header not empty');
  return {
    protectedHeader,
    payload: bytesIn(payload, 1, 16384, 'payload'),
    signature: bytesIn(signature, 96, 96, 'ES384 signature'),
  };
}

/** The payload, syntactically validated per AWS §3.2.2. */
export function parseAttestationPayload(payload: Uint8Array): AttestationDocument {
  const m = decode(payload, { useMaps: true, strict: true, rejectDuplicateMapKeys: true });
  if (!(m instanceof Map)) throw new Error('attestation: payload is not a map');
  for (const k of m.keys()) {
    if (typeof k !== 'string' || !ALLOWED_FIELDS.has(k)) throw new Error('attestation: unexpected field');
  }
  // AWS's rules allow no null field; the NSM itself writes an absent optional
  // field as null (its `AttestationDoc` serializes `Option::None`), so a null
  // optional field reads as absent.
  for (const [k, v] of m) {
    if ((v === null || v === undefined) && !OPTIONAL_FIELDS.has(k as string)) throw new Error(`attestation: null ${String(k)}`);
  }
  const moduleId = m.get('module_id');
  if (typeof moduleId !== 'string' || moduleId.length === 0) throw new Error('attestation: bad module_id');
  if (m.get('digest') !== 'SHA384') throw new Error('attestation: digest is not SHA384');
  const timestamp = m.get('timestamp');
  if (typeof timestamp !== 'number' || !Number.isSafeInteger(timestamp) || timestamp <= 0) {
    throw new Error('attestation: bad timestamp');
  }
  const pcrsIn = m.get('pcrs');
  if (!(pcrsIn instanceof Map) || pcrsIn.size < 1 || pcrsIn.size > 32) throw new Error('attestation: bad pcrs');
  const pcrs = new Map<number, Uint8Array>();
  for (const [i, v] of pcrsIn) {
    if (typeof i !== 'number' || !Number.isInteger(i) || i < 0 || i >= 32) throw new Error('attestation: bad PCR index');
    if (!(v instanceof Uint8Array) || ![32, 48, 64].includes(v.length)) throw new Error('attestation: bad PCR value');
    pcrs.set(i, v);
  }
  const cabundle = m.get('cabundle');
  if (!Array.isArray(cabundle) || cabundle.length === 0) throw new Error('attestation: bad cabundle');
  const doc: AttestationDocument = {
    moduleId,
    timestamp,
    digest: 'SHA384',
    pcrs,
    certificate: bytesIn(m.get('certificate'), 1, 1024, 'certificate'),
    cabundle: cabundle.map((c) => bytesIn(c, 1, 1024, 'cabundle entry')),
  };
  if (m.get('public_key') != null) doc.publicKey = bytesIn(m.get('public_key'), 1, 1024, 'public_key');
  if (m.get('user_data') != null) doc.userData = bytesIn(m.get('user_data'), 0, 512, 'user_data');
  if (m.get('nonce') != null) doc.nonce = bytesIn(m.get('nonce'), 0, 512, 'nonce');
  return doc;
}

/**
 * The image identity custodians and wallets allow:
 * `sha256(label || PCR0 || PCR1 || PCR2)`, each PCR the 48-byte SHA-384
 * register value `nitro-cli build-enclave` prints.
 */
export async function enclaveMeasurement(pcrs: Map<number, Uint8Array>): Promise<Uint8Array> {
  const regs = [0, 1, 2].map((i) => {
    const v = pcrs.get(i);
    if (!v || v.length !== 48) throw new Error(`attestation: PCR${i} missing`);
    return v;
  });
  return sha256(utf8(MEASUREMENT_LABEL), ...regs);
}

export interface VerifyOptions {
  /** DER root certificates; `cabundle[0]` must equal one of them. */
  roots: Uint8Array[];
  /** Hex measurements ([`enclaveMeasurement`]) the caller accepts. */
  allowedMeasurements: Iterable<string>;
  /** The nonce the caller sent; the document must carry exactly it. */
  nonce: Uint8Array;
  now?: Date;
  /** Oldest acceptable document, in milliseconds before `now`. */
  maxAgeMs?: number;
}

export interface VerifiedAttestation {
  document: AttestationDocument;
  /** Hex image measurement. */
  measurement: string;
  /** The `public_key` field. */
  publicKey: Uint8Array;
  userData: Uint8Array;
}

const CLOCK_SKEW_MS = 60_000;

/**
 * Verifies `bytes` as a Nitro attestation document under `opts`; throws on
 * any failure.
 */
export async function verifyAttestation(bytes: Uint8Array, opts: VerifyOptions): Promise<VerifiedAttestation> {
  const now = opts.now ?? new Date();
  const cose = coseSign1(bytes);
  const document = parseAttestationPayload(cose.payload);
  const target = await validateChain(document.certificate, document.cabundle, opts.roots, now);
  if (target.curve !== 'P-384') throw new Error('attestation: signing key is not P-384');
  const sigStructure = encode(['Signature1', cose.protectedHeader, new Uint8Array(0), cose.payload]);
  const key = await importEcdsaKey(target.spki, 'P-384');
  if (!(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, buf(cose.signature), buf(sigStructure)))) {
    throw new Error('attestation: COSE signature invalid');
  }

  if (!document.nonce || !equal(document.nonce, opts.nonce)) throw new Error('attestation: nonce mismatch');
  const age = now.getTime() - document.timestamp;
  if (age > (opts.maxAgeMs ?? 5 * 60_000) || age < -CLOCK_SKEW_MS) throw new Error('attestation: stale timestamp');
  const pcr0 = document.pcrs.get(0);
  if (pcr0 && pcr0.every((b) => b === 0)) throw new Error('attestation: debug-mode enclave');
  const measurement = toHex(await enclaveMeasurement(document.pcrs));
  if (!new Set(opts.allowedMeasurements).has(measurement)) throw new Error('attestation: measurement not allowed');
  if (!document.publicKey) throw new Error('attestation: no public key');
  return { document, measurement, publicKey: document.publicKey, userData: document.userData ?? new Uint8Array(0) };
}

/** `user_data` of a vault attestation: what the enclave binds to its key. */
export interface VaultUserData {
  purpose: 'nido-alert-vault/v1';
  /** The vault's VAPID public key (uncompressed P-256, 65 bytes). */
  vapid: Uint8Array;
}

export function encodeVaultUserData(u: VaultUserData): Uint8Array {
  return encode(new Map<string, unknown>([['purpose', u.purpose], ['vapid', u.vapid]]));
}

export function decodeVaultUserData(b: Uint8Array): VaultUserData {
  const m = decode(b, { useMaps: true, strict: true, rejectDuplicateMapKeys: true });
  if (!(m instanceof Map) || m.size !== 2 || m.get('purpose') !== 'nido-alert-vault/v1') {
    throw new Error('attestation: not a vault attestation');
  }
  const vapid = m.get('vapid');
  if (!(vapid instanceof Uint8Array) || vapid.length !== 65 || vapid[0] !== 4) throw new Error('attestation: bad VAPID key');
  return { purpose: 'nido-alert-vault/v1', vapid };
}

