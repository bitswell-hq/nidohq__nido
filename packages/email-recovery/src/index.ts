/**
 * Browser-side pieces of email recovery (`docs/email-recovery/spec.md`):
 * the per-attempt alert code, verification of the alert vault's Nitro
 * attestation, and sealed, passkey-authorized alert contacts. WebCrypto
 * only; runs in browsers and in Node 20+.
 */
export {
  ALERT_CODE_DIGITS,
  ALERT_CODE_KEY_LABEL,
  ALERT_CODE_LABEL,
  type AlertCodeInput,
  type AlertSubject,
  alertCode,
  deriveAlertCodeKey,
  formatAlertCode,
  subjectBytes,
} from './alertCode.js';
export {
  type AttestationDocument,
  MEASUREMENT_LABEL,
  type VaultUserData,
  type VerifiedAttestation,
  type VerifyOptions,
  decodeVaultUserData,
  enclaveMeasurement,
  encodeVaultUserData,
  parseAttestationPayload,
  verifyAttestation,
} from './attestation.js';
export * as bytes from './bytes.js';
export {
  AUTHORIZATION_LABEL,
  type Authorization,
  type ContactInput,
  type ContactOp,
  type ContactRequest,
  ENVELOPE_VERSION,
  PURPOSE_PRODUCT_UPDATES,
  PURPOSE_SECURITY_ALERTS,
  type PushChannel,
  type PushSubscriptionJSON,
  type SealedRequest,
  VAULT_REQUEST_INFO,
  type VaultKey,
  attestationNonce,
  attestedVaultKey,
  authorizationChallenge,
  checkChannels,
  confirmationRequest,
  contactRequest,
  decodeContactRequest,
  decodeSealedRequest,
  encodeContactRequest,
  encodeSealedRequest,
  openRequest,
  prepareConfirmation,
  prepareContactChange,
  rawLowS,
  removalRequest,
  sealRequest,
} from './enrollment.js';
export { HPKE_SUITE, type Sealed, hpkeSuite, open, rawPublicKeyFromSpki, seal, spkiFromRawPublicKey } from './hpke.js';
export { contractIdFromStrkey, strkeyFromContractId } from './strkey.js';
export { type Certificate, parseCertificate, validateChain } from './x509.js';
