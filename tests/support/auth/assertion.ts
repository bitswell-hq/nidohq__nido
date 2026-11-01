import { buildSyntheticAssertion, type SyntheticRelyingParty } from '../../../packages/passkey-sdk/src/syntheticAssertion';
import { privateKeyForCredentialId } from './vault';

export interface Assertion {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
}

/** Build a WebAuthn assertion over `challenge32` for the key behind
 *  `credentialId`, claiming `relyingParty`'s origin and rpId as a browser
 *  would. The on-chain verifier ignores origin/rpIdHash; the alert vault
 *  checks both. */
export async function makeAssertion(
  seed: Uint8Array,
  credentialId: Uint8Array,
  challenge32: Uint8Array,
  relyingParty?: SyntheticRelyingParty,
): Promise<Assertion> {
  const d = await privateKeyForCredentialId(seed, credentialId);
  return buildSyntheticAssertion(d, challenge32, relyingParty);
}
