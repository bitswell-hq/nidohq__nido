/**
 * Recovery alerts for Nido accounts (`docs/email-recovery/spec.md` §10):
 * a host service that watches Perch's recovery controller and a sealed vault
 * that alone holds the addresses.
 */
export { type BootInfo, InProcessVault, type NsmSpec, ProcessVault, type TranscriptEntry, type VaultApi } from './channel.js';
export { ALERTS, type AlertClass, type PerchEvent, type PerchEventName, type RpcEvent, alertSubject, decodePerchEvent } from './events.js';
export { type GetEventsResult, RpcError, StellarRpc, accountSigners } from './rpc.js';
export { RegistryEventsView } from './registryView.js';
export { AlertService, type PollReport, type ServiceConfig } from './service.js';
export { type HostState, emptyState, loadState, saveState } from './store.js';
export { alertText, confirmationText, contactChangeNotice } from './vault/content.js';
export { type CustodianEndpoint, type Nsm, genesis, restore } from './vault/custody.js';
export { alertLookup, combineShares, deriveVaultKeys, splitSecret, type VaultKeys } from './vault/keys.js';
export { type SendingConfig, sendEmail } from './vault/send.js';
export {
  CONFIRMATION_ATTEMPTS,
  CONFIRMATION_TTL_MS,
  CONTACT_CHANGE_DELAY_LEDGERS,
  type ChainView,
  type ContactResult,
  type DispatchRequest,
  Vault,
  type VaultConfig,
  type Writes,
} from './vault/vault.js';
export { checkAuthorization, type RelyingParty } from './vault/webauthn.js';
export { encryptWebPush, pushMessage, vapidAuthorization } from './vault/webpush.js';
