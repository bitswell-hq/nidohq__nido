/**
 * TEST-ONLY mock of AWS Nitro Enclaves attestation: the Nitro Secure Module
 * an enclave asks for attestation documents, and the PKI that signs them.
 *
 * Documents follow AWS's published format
 * (https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md,
 * §2.2 and §3.1): a COSE_Sign1 tagged 18, protected header `{1: -35}`
 * (ES384), empty unprotected header, and a CBOR payload with `module_id`,
 * `digest` ("SHA384"), `timestamp` (ms), `pcrs` (16 SHA-384 registers),
 * `certificate`, `cabundle` (root first), and the optional `public_key`,
 * `user_data`, and `nonce`, in the field order the NSM writes them (an absent
 * optional field is `null`, as the NSM API's `AttestationDoc` serializes
 * `Option::None`). PCRs
 * follow AWS's "Where to get an enclave's measurements": PCR0 to PCR2 from
 * the image, PCR3 and PCR4 as `SHA384(0^48 || role ARN / instance id)`,
 * and all zero in debug mode.
 *
 * The chain is `keys/nitro/` (scripts/generate-nitro-test-ca.sh): P-384,
 * SHA-384, root → zonal → instance → enclave, under a TEST-ONLY name. It is
 * not, and does not chain to, AWS's root.
 *
 * `verifyAttestationNode` is an independent verifier built on
 * `node:crypto`'s X.509 support, used by the custodian mocks.
 */
import { createHash, createPrivateKey, sign, verify, X509Certificate, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { decode, encode } from 'cborg';

const NITRO_DIR = fileURLToPath(new URL('../keys/nitro/', import.meta.url));

function pem(name: string): string {
  return readFileSync(`${NITRO_DIR}TEST-ONLY-${name}.pem`, 'utf8');
}

function der(name: string): Uint8Array {
  return new Uint8Array(new X509Certificate(pem(name)).raw);
}

/** Which TEST-ONLY chain signs: the trusted one, or a variant a verifier must refuse. */
export type NitroChain = 'nitro' | 'rogue' | 'expired-enclave' | 'enclave-without-digital-signature';

const CHAINS: Record<NitroChain, { leaf: string; bundle: string[] }> = {
  nitro: { leaf: 'nitro-enclave', bundle: ['nitro-root', 'nitro-zonal', 'nitro-instance'] },
  rogue: { leaf: 'rogue-enclave', bundle: ['rogue-root'] },
  'expired-enclave': { leaf: 'nitro-enclave-expired', bundle: ['nitro-root', 'nitro-zonal', 'nitro-instance'] },
  'enclave-without-digital-signature': {
    leaf: 'nitro-enclave-nosig',
    bundle: ['nitro-root', 'nitro-zonal', 'nitro-instance'],
  },
};

/** DER of the TEST-ONLY Nitro root a verifier pins. */
export const nitroTestRoot = (): Uint8Array => der('nitro-root');
/** DER of an unrelated TEST-ONLY root, for refusal tests. */
export const rogueTestRoot = (): Uint8Array => der('rogue-root');

/** PCR0 to PCR2 of an enclave image (`nitro-cli build-enclave` output). */
export interface EnclaveImage {
  pcr0: Uint8Array;
  pcr1: Uint8Array;
  pcr2: Uint8Array;
}

const sha384 = (...parts: (Uint8Array | string)[]): Uint8Array => {
  const h = createHash('sha384');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};

/** A deterministic test image: each PCR is `SHA384(label/pcrN)`. */
export function testImage(label: string): EnclaveImage {
  return { pcr0: sha384(`${label}/pcr0`), pcr1: sha384(`${label}/pcr1`), pcr2: sha384(`${label}/pcr2`) };
}

/** AWS's PCR3/PCR4 rule: `SHA384(0^48 || value)`. */
const extendedPcr = (value: string): Uint8Array => sha384(new Uint8Array(48), value);

/** The measurement custodians and wallets allow (spec §10.4). */
export function imageMeasurement(image: EnclaveImage): Uint8Array {
  return new Uint8Array(
    createHash('sha256')
      .update('nido/email-recovery/v1/enclave-image')
      .update(image.pcr0)
      .update(image.pcr1)
      .update(image.pcr2)
      .digest(),
  );
}

export interface LaunchOptions {
  /** `--debug-mode`: every PCR reads as zero. */
  debug?: boolean;
  instanceId?: string;
  iamRoleArn?: string;
}

export interface AttestationRequest {
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  nonce?: Uint8Array;
}

/** The NSM of one running enclave. */
export class NsmMock {
  readonly pcrs: Map<number, Uint8Array>;
  readonly moduleId: string;
  private readonly leafKey: KeyObject;
  private readonly certificate: Uint8Array;
  private readonly cabundle: Uint8Array[];

  constructor(
    image: EnclaveImage,
    private readonly chain: NitroChain,
    private readonly clock: () => number,
    opts: LaunchOptions,
  ) {
    const instanceId = opts.instanceId ?? 'i-0000000000000test';
    this.moduleId = `${instanceId}-enc0000000000000test`;
    this.pcrs = new Map<number, Uint8Array>();
    for (let i = 0; i < 16; i++) this.pcrs.set(i, new Uint8Array(48));
    if (!opts.debug) {
      this.pcrs.set(0, image.pcr0);
      this.pcrs.set(1, image.pcr1);
      this.pcrs.set(2, image.pcr2);
      this.pcrs.set(3, extendedPcr(opts.iamRoleArn ?? 'arn:aws:iam::000000000000:role/test-only-vault'));
      this.pcrs.set(4, extendedPcr(instanceId));
    }
    const c = CHAINS[chain];
    this.leafKey = createPrivateKey(readFileSync(`${NITRO_DIR}TEST-ONLY-${c.leaf}.key.pem`, 'utf8'));
    this.certificate = der(c.leaf);
    this.cabundle = c.bundle.map(der);
  }

  /** The NSM `Attestation` request: a signed document over the given fields. */
  attest(req: AttestationRequest = {}): Uint8Array {
    for (const [name, v, max] of [
      ['public_key', req.publicKey, 1024],
      ['user_data', req.userData, 512],
      ['nonce', req.nonce, 512],
    ] as const) {
      if (v && v.length > max) throw new Error(`NSM: ${name} longer than ${max} bytes`);
    }
    const doc = new Map<string, unknown>([
      ['module_id', this.moduleId],
      ['digest', 'SHA384'],
      ['timestamp', this.clock()],
      ['pcrs', this.pcrs],
      ['certificate', this.certificate],
      ['cabundle', this.cabundle],
      ['public_key', req.publicKey ?? null],
      ['user_data', req.userData ?? null],
      ['nonce', req.nonce ?? null],
    ]);
    const keepOrder = { mapSorter: () => 0 };
    const payload = encode(doc, keepOrder);
    const protectedHeader = encode(new Map([[1, -35]]));
    const sigStructure = encode(['Signature1', protectedHeader, new Uint8Array(0), payload]);
    const signature = sign('sha384', sigStructure, { key: this.leafKey, dsaEncoding: 'ieee-p1363' });
    const cose = encode([protectedHeader, new Map(), payload, new Uint8Array(signature)]);
    const tagged = new Uint8Array(cose.length + 1);
    tagged[0] = 0xd2; // CBOR tag 18 (COSE_Sign1)
    tagged.set(cose, 1);
    return tagged;
  }
}

/** The hypervisor: launches enclaves whose NSM signs with the chosen chain. */
export class NitroHypervisorMock {
  constructor(
    private readonly opts: { chain?: NitroChain; clock?: () => number } = {},
  ) {}

  launch(image: EnclaveImage, opts: LaunchOptions = {}): NsmMock {
    return new NsmMock(image, this.opts.chain ?? 'nitro', this.opts.clock ?? Date.now, opts);
  }
}

export interface NodeVerified {
  measurement: Uint8Array;
  publicKey?: Uint8Array;
  userData?: Uint8Array;
  timestamp: number;
}

/**
 * An attestation verifier on `node:crypto` (independent of the browser
 * one): COSE structure, the chain to a pinned root with validity and CA
 * flags, the ES384 signature, a fresh nonce, a recent timestamp, and no
 * debug PCRs. Returns the image measurement.
 */
export function verifyAttestationNode(
  bytes: Uint8Array,
  opts: { roots: Uint8Array[]; nonce: Uint8Array; now: number; maxAgeMs?: number },
): NodeVerified {
  const tags: { [n: number]: (d: () => unknown) => unknown } = [];
  tags[18] = (d) => d();
  const cose = decode(bytes, { useMaps: true, tags }) as unknown[];
  if (!Array.isArray(cose) || cose.length !== 4) throw new Error('not COSE_Sign1');
  const [prot, , payload, signature] = cose as [Uint8Array, unknown, Uint8Array, Uint8Array];
  const header = decode(prot, { useMaps: true }) as Map<number, number>;
  if (header.get(1) !== -35) throw new Error('not ES384');
  const doc = decode(payload, { useMaps: true }) as Map<string, unknown>;
  if (doc.get('digest') !== 'SHA384') throw new Error('digest');
  const cabundle = doc.get('cabundle') as Uint8Array[];
  if (!opts.roots.some((r) => Buffer.from(r).equals(Buffer.from(cabundle[0]!)))) throw new Error('untrusted root');
  const chain = [doc.get('certificate') as Uint8Array, ...[...cabundle].reverse()].map(
    (d) => new X509Certificate(Buffer.from(d)),
  );
  const now = new Date(opts.now);
  chain.forEach((c, i) => {
    if (now < new Date(c.validFrom) || now > new Date(c.validTo)) throw new Error(`certificate ${i} expired`);
    const issuer = chain[Math.min(i + 1, chain.length - 1)]!;
    if (!c.checkIssued(issuer) || !c.verify(issuer.publicKey)) throw new Error(`certificate ${i} not issued by the next`);
    if ((i > 0) !== c.ca) throw new Error(`certificate ${i} CA flag`);
  });
  const sigStructure = encode(['Signature1', prot, new Uint8Array(0), payload]);
  if (!verify('sha384', sigStructure, { key: chain[0]!.publicKey, dsaEncoding: 'ieee-p1363' }, signature)) {
    throw new Error('COSE signature');
  }
  const nonce = doc.get('nonce') as Uint8Array | undefined;
  if (!nonce || !Buffer.from(nonce).equals(Buffer.from(opts.nonce))) throw new Error('nonce');
  const timestamp = doc.get('timestamp') as number;
  if (opts.now - timestamp > (opts.maxAgeMs ?? 5 * 60_000)) throw new Error('stale');
  const pcrs = doc.get('pcrs') as Map<number, Uint8Array>;
  if (pcrs.get(0)!.every((b) => b === 0)) throw new Error('debug-mode enclave');
  const measurement = imageMeasurement({ pcr0: pcrs.get(0)!, pcr1: pcrs.get(1)!, pcr2: pcrs.get(2)! });
  const out: NodeVerified = { measurement, timestamp };
  const pk = doc.get('public_key');
  if (pk instanceof Uint8Array) out.publicKey = pk;
  const ud = doc.get('user_data');
  if (ud instanceof Uint8Array) out.userData = ud;
  return out;
}
