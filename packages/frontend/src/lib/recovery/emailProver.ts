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

export const EMAIL_CIRCUIT_ID = '2837d0cfd7ddad684006e3eb4eba4ff7f4ed732a9d93423a79e69523d4a43b64';

/** What a first proof downloads, in octets: the artifact (2,011,102), the key (1,760), and the CRS prefix and G2 point (16,777,408). */
export const FIRST_PROOF_DOWNLOAD = 2_011_102 + 1_760 + 16_777_408;

export function emailProverAssets(): ProverAssets {
  return {
    circuitUrl: new URL(circuitUrl, location.href).href,
    vkUrl: new URL(vkUrl, location.href).href,
    circuitId: EMAIL_CIRCUIT_ID,
  };
}

export function emailProver(): RecoveryProver {
  return new RecoveryProver(emailProverAssets());
}

/** "18.8 MB" */
export function megabytes(octets: number): string {
  return `${(octets / 1e6).toFixed(1)} MB`;
}
