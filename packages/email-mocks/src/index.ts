/**
 * TEST-ONLY mocks of the third parties in email recovery: DKIM-signing mail
 * providers, the DNS that publishes their keys, and the MX that receives
 * mail at the fixed recovery address.
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
