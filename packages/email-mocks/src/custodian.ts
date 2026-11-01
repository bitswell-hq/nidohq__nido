/**
 * TEST-ONLY mock of one key custodian of the alert vault
 * (`docs/email-recovery/spec.md` §10.5).
 *
 * A custodian holds one Shamir share of the vault key and hands it only to
 * an enclave that proves, with a fresh Nitro attestation, that it runs an
 * image whose measurement is active in the enclave-image registry (approved
 * by the registry's multisig and past its 14-day public timelock). The share
 * travels HPKE-sealed to the `public_key` in that attestation, the shape AWS
 * KMS uses for enclave recipients (the response is encrypted to the
 * attested public key; https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html).
 *
 * Attestations are checked with [`verifyAttestationNode`], independently of
 * the browser verifier.
 */
import { randomBytes, type webcrypto } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { decode } from 'cborg';
import { verifyAttestationNode } from './nitro.js';

export const SHARE_DEPOSIT_INFO = 'nido/email-recovery/v1/share-deposit';
export const SHARE_RELEASE_INFO = 'nido/email-recovery/v1/share-release';
export const DEPOSIT_PURPOSE = 'nido-share-deposit/v1';
export const RELEASE_PURPOSE = 'nido-share-request/v1';

/** Whether the registry holds a measurement as active, read from public chain state. */
export interface MeasurementRegistryView {
  isActive(measurementHex: string): boolean | Promise<boolean>;
}

export interface Sealed {
  enc: Uint8Array;
  ct: Uint8Array;
}

export interface CustodianDecision {
  op: 'deposit' | 'release';
  vault: string;
  measurement?: string;
  outcome: 'granted' | 'refused';
  reason?: string;
}

export class CustodianRefusal extends Error {}

const suite = () =>
  new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const enc = new TextEncoder();
const concat = (a: Uint8Array, b: Uint8Array) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
};

const CHALLENGE_TTL_MS = 5 * 60_000;

export class CustodianMock {
  readonly decisions: CustodianDecision[] = [];
  private readonly shares = new Map<string, Uint8Array>();
  private readonly challenges = new Map<string, number>();
  private server?: Server;

  private constructor(
    readonly name: string,
    private readonly keyPair: webcrypto.CryptoKeyPair,
    /** HPKE public key (uncompressed P-256) a depositing enclave seals to. */
    readonly publicKey: Uint8Array,
    private readonly roots: Uint8Array[],
    private readonly registry: MeasurementRegistryView,
    private readonly clock: () => number,
  ) {}

  static async create(opts: {
    name: string;
    roots: Uint8Array[];
    registry: MeasurementRegistryView;
    clock?: () => number;
  }): Promise<CustodianMock> {
    const s = suite();
    const kp = await s.kem.generateKeyPair();
    const pk = new Uint8Array(await s.kem.serializePublicKey(kp.publicKey));
    return new CustodianMock(opts.name, kp, pk, opts.roots, opts.registry, opts.clock ?? Date.now);
  }

  /** A single-use nonce the enclave must place in its next attestation. */
  challenge(): Uint8Array {
    const n = new Uint8Array(randomBytes(32));
    this.challenges.set(hex(n), this.clock() + CHALLENGE_TTL_MS);
    return n;
  }

  /** Whether this custodian holds a share for `vault`. */
  holds(vault: Uint8Array): boolean {
    return this.shares.has(hex(vault));
  }

  /**
   * Check `attestation` for `purpose` and `vault`: a nonce this custodian
   * issued and has not seen used, an active measurement, and `user_data`
   * naming the purpose and the vault. Returns the attested public key.
   */
  private async admit(
    op: CustodianDecision['op'],
    vault: Uint8Array,
    attestation: Uint8Array,
    purpose: string,
  ): Promise<{ publicKey?: Uint8Array; nonce: Uint8Array }> {
    const refuse = (reason: string, measurement?: string): never => {
      this.decisions.push({ op, vault: hex(vault), ...(measurement ? { measurement } : {}), outcome: 'refused', reason });
      throw new CustodianRefusal(`${this.name}: ${reason}`);
    };
    let nonce: Uint8Array | undefined;
    try {
      const tags: { [n: number]: (d: () => unknown) => unknown } = [];
      tags[18] = (d) => d();
      const cose = decode(attestation, { useMaps: true, tags }) as unknown[];
      nonce = (decode(cose[2] as Uint8Array, { useMaps: true }) as Map<string, unknown>).get('nonce') as Uint8Array;
    } catch {
      refuse('malformed attestation');
    }
    const expiry = nonce ? this.challenges.get(hex(nonce)) : undefined;
    if (!nonce || expiry === undefined || expiry < this.clock()) refuse('unknown or expired challenge');
    this.challenges.delete(hex(nonce!));
    let v;
    try {
      v = verifyAttestationNode(attestation, { roots: this.roots, nonce: nonce!, now: this.clock() });
    } catch (e) {
      return refuse(`attestation: ${(e as Error).message}`);
    }
    const measurement = hex(v.measurement);
    if (!(await this.registry.isActive(measurement))) refuse('measurement not active in the registry', measurement);
    let ud: Map<string, unknown> | undefined;
    try {
      ud = decode(v.userData ?? new Uint8Array(), { useMaps: true }) as Map<string, unknown>;
    } catch {
      refuse('malformed user_data', measurement);
    }
    const named = ud?.get('vault');
    if (ud?.get('purpose') !== purpose || !(named instanceof Uint8Array) || hex(named) !== hex(vault)) {
      refuse('user_data does not name this purpose and vault', measurement);
    }
    this.decisions.push({ op, vault: hex(vault), measurement, outcome: 'granted' });
    return { ...(v.publicKey ? { publicKey: v.publicKey } : {}), nonce: nonce! };
  }

  /**
   * First deposit of `vault`'s share, sealed to this custodian's key. A
   * custodian never replaces a share it holds.
   */
  async deposit(req: { vault: Uint8Array; attestation: Uint8Array; share: Sealed }): Promise<void> {
    if (this.holds(req.vault)) {
      this.decisions.push({ op: 'deposit', vault: hex(req.vault), outcome: 'refused', reason: 'share already held' });
      throw new CustodianRefusal(`${this.name}: share already held`);
    }
    await this.admit('deposit', req.vault, req.attestation, DEPOSIT_PURPOSE);
    const pt = await suite().open(
      { recipientKey: this.keyPair, enc: req.share.enc, info: enc.encode(SHARE_DEPOSIT_INFO) },
      req.share.ct,
      req.vault,
    );
    this.shares.set(hex(req.vault), new Uint8Array(pt));
  }

  /** The share, sealed to the attested enclave's `public_key`. */
  async release(req: { vault: Uint8Array; attestation: Uint8Array }): Promise<Sealed> {
    const share = this.shares.get(hex(req.vault));
    const { publicKey: recipient, nonce } = await this.admit('release', req.vault, req.attestation, RELEASE_PURPOSE);
    if (!share) throw new CustodianRefusal(`${this.name}: no share for this vault`);
    if (!recipient) throw new CustodianRefusal(`${this.name}: attestation carries no public key`);
    const s = suite();
    const spki = await crypto.subtle.importKey('spki', new Uint8Array(recipient), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', spki));
    const pk = await s.kem.deserializePublicKey(raw);
    const sealed = await s.seal(
      { recipientPublicKey: pk, info: enc.encode(SHARE_RELEASE_INFO) },
      share,
      concat(nonce, req.vault),
    );
    return { enc: new Uint8Array(sealed.enc), ct: new Uint8Array(sealed.ct) };
  }

  /** Serve `POST /v1/{challenge,deposit,release}` (JSON, base64url fields). */
  async listen(): Promise<string> {
    const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64url');
    const unb64 = (s: unknown) => new Uint8Array(Buffer.from(String(s), 'base64url'));
    this.server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const reply = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      try {
        const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
        if (req.method !== 'POST') return reply(405, { error: 'method' });
        if (req.url === '/v1/challenge') return reply(200, { nonce: b64(this.challenge()) });
        if (req.url === '/v1/deposit') {
          await this.deposit({
            vault: unb64(body.vault),
            attestation: unb64(body.attestation),
            share: { enc: unb64(body.share.enc), ct: unb64(body.share.ct) },
          });
          return reply(200, { ok: true });
        }
        if (req.url === '/v1/release') {
          const s = await this.release({ vault: unb64(body.vault), attestation: unb64(body.attestation) });
          return reply(200, { enc: b64(s.enc), ct: b64(s.ct) });
        }
        return reply(404, { error: 'not found' });
      } catch (e) {
        return reply(e instanceof CustodianRefusal ? 403 : 400, { error: (e as Error).message });
      }
    });
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', r));
    return `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  async close(): Promise<void> {
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()));
  }
}
