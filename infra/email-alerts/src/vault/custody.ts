/**
 * Getting the vault's master secret `K` in and out of custody
 * (`docs/email-recovery/spec.md` §10.5).
 *
 * - **Genesis**: draw `K`, split it 2-of-3, and deposit share `i` with
 *   custodian `i`, sealed to that custodian's HPKE key, under a fresh
 *   attestation (custodian nonce; `user_data` = `{purpose: deposit, vault}`).
 *   Every custodian must accept.
 * - **Restore**: for each custodian, attest with the custodian's nonce and
 *   an ephemeral HPKE key as `public_key` (`user_data` = `{purpose:
 *   request, vault}`); the custodian checks the attestation and the
 *   registry, and seals its share to that key. Two shares reconstruct `K`,
 *   which is accepted only if it re-derives the vault id.
 */
import { randomBytes } from 'node:crypto';
import { bytes, hpkeSuite, open, seal, spkiFromRawPublicKey } from '@nidohq/email-recovery';
import { encode } from 'cborg';
import { combineShares, deriveVaultKeys, splitSecret, type VaultKeys } from './keys.js';

const { concat, fromBase64Url, toBase64Url, utf8 } = bytes;

export const SHARE_DEPOSIT_INFO = 'nido/email-recovery/v1/share-deposit';
export const SHARE_RELEASE_INFO = 'nido/email-recovery/v1/share-release';

/** The NSM call the vault needs (the Nitro `Attestation` request). */
export interface Nsm {
  attest(req: { publicKey?: Uint8Array; userData?: Uint8Array; nonce?: Uint8Array }): Uint8Array;
}

export interface CustodianEndpoint {
  url: string;
  /** The custodian's HPKE public key (uncompressed P-256). */
  publicKey: Uint8Array;
}

async function post(url: string, body: unknown, fetchImpl: typeof fetch): Promise<Record<string, unknown>> {
  const r = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  const b = (await r.json()) as Record<string, unknown>;
  if (!r.ok) throw new Error(`custodian ${new URL(url).host}: ${String(b.error ?? r.status)}`);
  return b;
}

const userData = (purpose: string, vault: Uint8Array) =>
  encode(new Map<string, unknown>([['purpose', purpose], ['vault', vault]]));

export async function genesis(
  nsm: Nsm,
  custodians: CustodianEndpoint[],
  fetchImpl: typeof fetch = fetch,
): Promise<VaultKeys> {
  if (custodians.length !== 3) throw new Error('genesis needs exactly three custodians');
  const k = new Uint8Array(randomBytes(32));
  const keys = await deriveVaultKeys(k);
  const shares = await splitSecret(k);
  for (const [i, c] of custodians.entries()) {
    const nonce = fromBase64Url(String((await post(`${c.url}/v1/challenge`, {}, fetchImpl)).nonce));
    const attestation = nsm.attest({ nonce, userData: userData('nido-share-deposit/v1', keys.vaultId) });
    const sealed = await seal(c.publicKey, utf8(SHARE_DEPOSIT_INFO), keys.vaultId, shares[i]!);
    await post(
      `${c.url}/v1/deposit`,
      {
        vault: toBase64Url(keys.vaultId),
        attestation: toBase64Url(attestation),
        share: { enc: toBase64Url(sealed.enc), ct: toBase64Url(sealed.ct) },
      },
      fetchImpl,
    );
  }
  return keys;
}

export interface RestoreReport {
  keys: VaultKeys;
  /** Per custodian: released, or why not. */
  outcomes: { url: string; ok: boolean; error?: string }[];
}

export async function restore(
  nsm: Nsm,
  custodians: CustodianEndpoint[],
  vaultId: Uint8Array,
  fetchImpl: typeof fetch = fetch,
): Promise<RestoreReport> {
  const suite = hpkeSuite();
  const shares: Uint8Array[] = [];
  const outcomes: RestoreReport['outcomes'] = [];
  for (const c of custodians) {
    try {
      const ephemeral = await suite.kem.generateKeyPair();
      const pk = new Uint8Array(await suite.kem.serializePublicKey(ephemeral.publicKey));
      const nonce = fromBase64Url(String((await post(`${c.url}/v1/challenge`, {}, fetchImpl)).nonce));
      const attestation = nsm.attest({
        nonce,
        publicKey: await spkiFromRawPublicKey(pk),
        userData: userData('nido-share-request/v1', vaultId),
      });
      const r = await post(
        `${c.url}/v1/release`,
        { vault: toBase64Url(vaultId), attestation: toBase64Url(attestation) },
        fetchImpl,
      );
      const share = await open(ephemeral, utf8(SHARE_RELEASE_INFO), concat(nonce, vaultId), {
        enc: fromBase64Url(String(r.enc)),
        ct: fromBase64Url(String(r.ct)),
      });
      shares.push(share);
      outcomes.push({ url: c.url, ok: true });
    } catch (e) {
      outcomes.push({ url: c.url, ok: false, error: (e as Error).message });
    }
    // Any two shares that re-derive the vault id are enough.
    for (let i = 0; i < shares.length; i++) {
      for (let j = i + 1; j < shares.length; j++) {
        try {
          return { keys: (await combineShares([shares[i]!, shares[j]!], vaultId)).keys, outcomes };
        } catch {
          // a wrong share: keep collecting
        }
      }
    }
  }
  throw Object.assign(new Error('fewer than two custodians released a valid share'), { outcomes });
}
