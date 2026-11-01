/**
 * The vault's key hierarchy (`docs/email-recovery/spec.md` §10.5). One
 * 32-byte master secret `K` exists only inside the enclave and, split 2-of-3,
 * at the custodians. Everything else is derived from it, so a restarted or
 * upgraded enclave that recovers `K` recovers the same keys:
 *
 *   hpke    = DeriveKeyPair(HKDF(K, "hpke"))         the key wallets seal to
 *   k_alert = HKDF(K, "alert-lookup")                 the record lookup key (§10)
 *   k_store = HKDF(K, "store")                        seals records at rest
 *   vapid   = HKDF(K, "vapid") mod (n - 1) + 1        the Web Push sender key
 *
 * each `HKDF-SHA-256(ikm = K, salt = "nido/email-recovery/v1/vault", info)`.
 */
import { createECDH } from 'node:crypto';
import { bytes, hpkeSuite } from '@nidohq/email-recovery';
import { combine, split } from 'shamir-secret-sharing';

const { concat, hkdfSha256, hmacSha256, sha256, utf8 } = bytes;

export const VAULT_SALT = 'nido/email-recovery/v1/vault';
export const LOOKUP_LABEL = 'nido/email-recovery/v1/alert-lookup';
export const VAULT_ID_LABEL = 'nido/email-recovery/v1/vault-id';
export const CUSTODIANS = 3;
export const THRESHOLD = 2;

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export interface VaultKeys {
  hpke: CryptoKeyPair;
  /** Uncompressed P-256 point. */
  hpkePublic: Uint8Array;
  kAlert: Uint8Array;
  kStore: Uint8Array;
  vapidPrivate: Uint8Array;
  vapidPublic: Uint8Array;
  /** `sha256(label || hpkePublic)`: names the vault at the custodians. */
  vaultId: Uint8Array;
}

const derive = (k: Uint8Array, info: string, n: number) => hkdfSha256(k, utf8(VAULT_SALT), utf8(info), n);

export async function deriveVaultKeys(k: Uint8Array): Promise<VaultKeys> {
  if (k.length !== 32) throw new Error('vault master secret is 32 bytes');
  const suite = hpkeSuite();
  const hpke = await suite.kem.deriveKeyPair(await derive(k, 'hpke', 32));
  const hpkePublic = new Uint8Array(await suite.kem.serializePublicKey(hpke.publicKey));
  const wide = await derive(k, 'vapid', 48);
  const d = (BigInt('0x' + Buffer.from(wide).toString('hex')) % (P256_N - 1n)) + 1n;
  const vapidPrivate = new Uint8Array(Buffer.from(d.toString(16).padStart(64, '0'), 'hex'));
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(vapidPrivate);
  return {
    hpke,
    hpkePublic,
    kAlert: await derive(k, 'alert-lookup', 32),
    kStore: await derive(k, 'store', 32),
    vapidPrivate,
    vapidPublic: new Uint8Array(ecdh.getPublicKey()),
    vaultId: await sha256(utf8(VAULT_ID_LABEL), hpkePublic),
  };
}

/** `lookup = HMAC-SHA-256(k_alert, label || account contract id)` (spec §10). */
export async function alertLookup(kAlert: Uint8Array, account: Uint8Array): Promise<Uint8Array> {
  if (account.length !== 32) throw new Error('account contract id is 32 bytes');
  return hmacSha256(kAlert, concat(utf8(LOOKUP_LABEL), account));
}

/** `K` as 3 Shamir shares over GF(2^8), any 2 of which reconstruct it. */
export const splitSecret = (k: Uint8Array): Promise<Uint8Array[]> => split(k, CUSTODIANS, THRESHOLD);

/**
 * Reconstruct `K` from shares and check it against the vault id the shares
 * were deposited under: a wrong or tampered share yields another `K`, hence
 * another key and id, and is refused.
 */
export async function combineShares(shares: Uint8Array[], vaultId: Uint8Array): Promise<{ k: Uint8Array; keys: VaultKeys }> {
  if (shares.length < THRESHOLD) throw new Error(`need ${THRESHOLD} shares`);
  const k = await combine(shares);
  const keys = await deriveVaultKeys(k);
  if (Buffer.compare(Buffer.from(keys.vaultId), Buffer.from(vaultId)) !== 0) {
    throw new Error('reconstructed key does not match the vault id');
  }
  return { k, keys };
}
