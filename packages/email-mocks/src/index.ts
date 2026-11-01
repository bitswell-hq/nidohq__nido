/**
 * TEST-ONLY mocks of the third parties in email recovery: DKIM-signing mail
 * providers, the DNS that publishes their keys, the MX that receives mail at
 * the fixed recovery address, and the third parties of the alert service:
 * Stellar RPC's `getEvents`, the Nitro Enclaves attestation PKI, the vault's
 * key custodians, the EU sending services, Web Push, and a WebAuthn
 * authenticator.
 */
export { type Canon, type HeaderField, canonBody, canonHeader } from './canon.js';
export { DKIM_FIELD, type SignInput, type Signed, bodyHash, parseTags, selectSignedHeaders, signMessage } from './dkim.js';
export { MockDns, keyRecord, keyRecordName } from './dns.js';
export {
  DEFAULT_DATE,
  type GenerateOptions,
  type GeneratedEmail,
  RECOVERY_ADDRESS,
  type SignatureInfo,
  generateEmail,
  launchDns,
} from './generate.js';
export { type Delivered, type Envelope, InboundMx, SmtpReject, fromSmtpData, toSmtpData } from './inbound.js';
export { type KeyName, type TestKey, publicKeyBase64, testKey } from './keys.js';
export { type Message, parseMessage, serializeMessage } from './message.js';
export { PROVIDERS } from './providers/index.js';
export type { ComposeInput, ProviderId, ProviderProfile, SignerProfile } from './providers/types.js';
export { type AttackCase, type AttackInput, type Claim, type Verdict, SOURCES, buildAttacks, defaultAttackInput } from './attacks/index.js';
export { type FixtureSet, type HonestFixture, fixtureSet, honestFixtures } from './fixtures.js';
export { type RotationCase, postRotationDns, rotationScenario } from './rotation.js';
export {
  type AttestationRequest,
  type EnclaveImage,
  type LaunchOptions,
  type NitroChain,
  NitroHypervisorMock,
  type NodeVerified,
  NsmMock,
  imageMeasurement,
  nitroTestRoot,
  rogueTestRoot,
  testImage,
  verifyAttestationNode,
} from './nitro.js';
export {
  CustodianMock,
  type CustodianDecision,
  CustodianRefusal,
  DEPOSIT_PURPOSE,
  type MeasurementRegistryView,
  RELEASE_PURPOSE,
  SHARE_DEPOSIT_INFO,
  SHARE_RELEASE_INFO,
} from './custodian.js';
export { type InjectedFailure, LettermintMock, SCALEWAY_PATH, ScalewayTemMock, type SentEmail } from './sending.js';
export { type PushMessage, PushServiceMock, PushUserAgentMock, decryptWebPush } from './webpush.js';
export { type RpcEvent, SCAN_WINDOW_LEDGERS, StellarRpcMock, cursorLedger, eventId, ledgerCloseTime, toid } from './stellarRpc.js';
export { type AssertOptions, type Assertion, AuthenticatorMock, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV } from './webauthn.js';
