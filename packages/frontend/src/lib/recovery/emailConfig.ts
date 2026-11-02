/**
 * Where this build finds email recovery's contracts and services
 * (`docs/email-recovery/spec.md`), from `PUBLIC_EMAIL_RECOVERY` at build
 * time: a JSON object of the shape below, or `none`/unset when email
 * recovery is not deployed on this network (the pages then say so).
 */

import { EMAIL_CIRCUIT_ID } from './emailProver.js';

export interface EmailRecoveryDeployment {
  /** sha256 of the `nido_email_guardian` wasm uploaded on this network. */
  guardianWasmHash: string;
  /** The DKIM key registry every guardian names (spec §7.6). */
  registry: string;
  /** The email circuit's verifier (`nido_email_verifier`), and `sha256` of its key. */
  verifier: string;
  circuitId: string;
  /** `RECOVERY_INBOX`: the fixed address every recovery and enrollment email goes to (spec §4.1). */
  recoveryInbox: string;
  /** The alert service host (spec §10.2): contacts, attestation, and the sealed inbound mail. */
  alertService: string;
  /** The static list of every DKIM key the registry knows, on this origin (spec §7.7). */
  keyList: string;
  /** A DNS-over-HTTPS JSON resolver, used only for a key the list does not have, after telling the user. */
  dohResolver?: string;
  /** The enclave-image registry the vault's measurement must be active in (spec §10.4). */
  enclaveImageRegistry: string;
  /** DER attestation roots the wallet pins, base64. */
  attestationRoots: string[];
  /** TEST-ONLY: accept `http://127.0.0.1` push endpoints (a local push-service mock). */
  testOnlyLoopbackPush?: boolean;
}

const HEX32 = /^[0-9a-f]{64}$/;
const CONTRACT = /^C[A-Z2-7]{55}$/;

export function parseEmailRecoveryDeployment(value: unknown): EmailRecoveryDeployment {
  if (typeof value !== 'object' || value === null) throw new Error('email recovery deployment: expected an object');
  const v = value as Record<string, unknown>;
  for (const k of ['registry', 'verifier', 'enclaveImageRegistry']) {
    if (!CONTRACT.test(String(v[k]))) throw new Error(`email recovery deployment: ${k} is not a contract`);
  }
  for (const k of ['guardianWasmHash', 'circuitId']) {
    if (!HEX32.test(String(v[k]))) throw new Error(`email recovery deployment: ${k} is not 32-byte hex`);
  }
  if (v.circuitId !== EMAIL_CIRCUIT_ID) {
    throw new Error('email recovery deployment: its verifier belongs to another circuit than this build proves');
  }
  if (!/^[^@\s]+@[^@\s]+$/.test(String(v.recoveryInbox))) throw new Error('email recovery deployment: recoveryInbox is not an address');
  for (const k of ['alertService', 'keyList']) {
    if (typeof v[k] !== 'string' || !v[k]) throw new Error(`email recovery deployment: missing ${k}`);
  }
  if (!Array.isArray(v.attestationRoots) || v.attestationRoots.length === 0) {
    throw new Error('email recovery deployment: attestationRoots is empty');
  }
  return value as EmailRecoveryDeployment;
}

let cached: EmailRecoveryDeployment | undefined | null = null;

export function emailRecoveryDeployment(): EmailRecoveryDeployment | undefined {
  if (cached !== null) return cached;
  const raw = import.meta.env.PUBLIC_EMAIL_RECOVERY as string | undefined;
  cached = !raw || raw === 'none' ? undefined : parseEmailRecoveryDeployment(JSON.parse(raw));
  return cached;
}

export function requireEmailRecovery(): EmailRecoveryDeployment {
  const d = emailRecoveryDeployment();
  if (!d) throw new Error('Email recovery is not available on this network yet.');
  return d;
}

/** How long the guardian's key pin lasts (spec §7.4), in seconds of ledger
 *  close time: 30 days, within the 365-day cap. */
export const PIN_LIFETIME_SECONDS = 30 * 86_400;
