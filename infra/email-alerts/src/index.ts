/**
 * Recovery alerts for Nido accounts (`docs/email-recovery/spec.md` §10):
 * a host service that watches Perch's recovery controller and a sealed vault
 * that alone holds the addresses.
 */
export { type BootInfo, InProcessVault, type NsmSpec, ProcessVault, type TranscriptEntry, type VaultApi } from './channel.js';
export {
  ALERTS,
  type AlertClass,
  alertEventId,
  type AlertName,
  type PerchEvent,
  type PerchEventName,
  type RpcEvent,
  alertSubject,
  decodePerchEvent,
} from './events.js';
export {
  type AttemptView,
  type ChainReads,
  type GetEventsResult,
  RpcError,
  StellarRpc,
  accountSigners,
  attemptView,
  chainReads,
  contractWasmHash,
} from './rpc.js';
export { RegistryEventsView } from './registryView.js';
export {
  AlertService,
  INBOUND_LIMIT,
  INBOUND_KEEP_MS,
  RECONCILE_EVERY_MS,
  RECONCILE_SCAN,
  type PollReport,
  type ServiceConfig,
  WindowLimiter,
  clientPrefix,
} from './service.js';
export { type HostState, emptyState, loadState, saveState } from './store.js';
export {
  NEVER_ASKS,
  PASSKEY_DEVICE_LEAD,
  alertText,
  confirmationText,
  contactChangeNotice,
  pushLapsedNotice,
  pushMovedNotice,
} from './vault/content.js';
export { type CustodianEndpoint, type Nsm, genesis, restore } from './vault/custody.js';
export { alertLookup, combineShares, deriveVaultKeys, splitSecret, type VaultKeys } from './vault/keys.js';
export { type SendingConfig, sendEmail } from './vault/send.js';
export {
  CONFIRMATION_ATTEMPTS,
  CONFIRMATION_TTL_MS,
  CONTACT_CHANGE_DELAY_SECONDS,
  type ChainTime,
  type ChainView,
  type ChannelStatus,
  PROBE_INTERVAL_MS,
  WATCH_MAX,
  changeDue,
  type ContactResult,
  type DispatchRequest,
  Vault,
  type VaultConfig,
  type Writes,
} from './vault/vault.js';
export { checkAuthorization, type RelyingParty } from './vault/webauthn.js';
export { encryptWebPush, pushMessage, vapidAuthorization } from './vault/webpush.js';
