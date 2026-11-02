/**
 * The email recovery prover as this wallet ships it: the recovery circuit's
 * artifact and verification key as hashed static assets of this build, and
 * `RecoveryProver` (`@nidohq/email-recovery`), which proves in a Web Worker
 * with Barretenberg threads when the page is cross-origin isolated (the
 * recovery routes are; see `public/_headers`).
 *
 * `EMAIL_CIRCUIT_ID` is `sha256` of the verification key the on-chain
 * verifier embeds (`contracts/email-verifier/vk/email_recovery.vk`); the
 * prover refuses a key with another digest, and a guardian whose
 * `circuit_id` differs is not one this build can prove for.
 */

import { RecoveryProver, type ProverAssets } from '@nidohq/email-recovery';
import circuitUrl from '../../../../../circuits/email-recovery/artifacts/recovery.json?url';
import vkUrl from '../../../../../contracts/email-verifier/vk/email_recovery.vk?url';

export const EMAIL_CIRCUIT_ID = 'a998d03e2069b41c875235876c3aa9c54bbc054c16fab0c38296651d01a93dbc';

/** What a first proof downloads, in octets: the artifact (1,885,167), the key (1,760), and the CRS prefix and G2 point (16,777,408). */
export const FIRST_PROOF_DOWNLOAD = 1_885_167 + 1_760 + 16_777_408;

/** `crsBaseUrl`: where `g1.dat` and `g2.dat` are served, Barretenberg's own host unless set; either way the CRS must match the prover's pinned digests. */
export function emailProverAssets(crsBaseUrl?: string): ProverAssets {
  return {
    circuitUrl: new URL(circuitUrl, location.href).href,
    vkUrl: new URL(vkUrl, location.href).href,
    circuitId: EMAIL_CIRCUIT_ID,
    ...(crsBaseUrl ? { crsBaseUrl } : {}),
  };
}

export function emailProver(crsBaseUrl?: string): RecoveryProver {
  return new RecoveryProver(emailProverAssets(crsBaseUrl));
}

/** "18.8 MB" */
export function megabytes(octets: number): string {
  return `${(octets / 1e6).toFixed(1)} MB`;
}
