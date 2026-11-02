/**
 * Email recovery against the chain and its services: finding an account's
 * email guardian, the signing key and its path (pin or registry), the alert
 * vault's attested key, the sealed inbound mail, the per-attempt alert
 * code, and submitting an approval. The pages (`emailStep.ts`,
 * `emailEnrollPage.ts`) call these; the rules they apply are in
 * `emailModel.ts`.
 */

import {
  type KeyPath,
  type ProofResult,
  type VaultKey,
  alertCode,
  alignedSignatures,
  alignedSignedBlock,
  attestationNonce,
  attestedVaultKey,
  bytes,
  bytesToBigInt,
  claimedMeasurement,
  contractIdFromStrkey,
  deriveAlertCodeKey,
  dohTxtRecords,
  initHashes,
  inboundRegistration,
  keyCandidates,
  keyHash,
  merkleRoot,
  openInboundMessage,
  parseDkimKeyRecord,
  parseKeyList,
  parseMessage,
  pinTree,
  registryLeaf,
  type InboxSecret,
  type KeyList,
} from '@nidohq/email-recovery';
import { Account, Address, TransactionBuilder, rpc, xdr } from '@stellar/stellar-sdk';
import { Buffer } from 'buffer';
import { NETWORK_PASSPHRASE, RELAYER_URL, RPC_URL } from '../network.js';
import { submitPermissionlessOp } from '../recoverySubmit.js';
import { getSubmitter } from '../primaryPasskeySigner.js';
import { relayerSubmitAndConfirm } from '../signing/submit.js';
import { DUMMY_SOURCE, simulateRead } from '../simulateRead.js';
import { latestCloseTime, latestLedger } from './chain.js';
import { type EmailRecoveryDeployment, requireEmailRecovery } from './emailConfig.js';
import {
  type GuardianConfig,
  contractWasmHash,
  emailApprovalEntry,
  randomNonce,
  readGuardianConfig,
  submitGuardianOperation,
} from './emailGuardian.js';
import { chooseKeyPath } from './emailModel.js';

const { toHex, fromHex, toBase64Url, fromBase64Url, sha256 } = bytes;
const server = () => new rpc.Server(RPC_URL);
const bigHex = (b: Uint8Array) => bytesToBigInt(b);

/** The account's email guardian among `guardians`: the one running this deployment's guardian wasm. */
export async function findEmailGuardian(
  guardians: string[],
  d: EmailRecoveryDeployment = requireEmailRecovery(),
): Promise<{ address: string; config: GuardianConfig } | undefined> {
  for (const g of guardians.filter((x) => x.startsWith('C'))) {
    if ((await contractWasmHash(g)) !== d.guardianWasmHash) continue;
    const config = await readGuardianConfig(g);
    if (config) return { address: g, config };
  }
  return undefined;
}

// --- the signing key ------------------------------------------------------

let keyListCache: Promise<KeyList | undefined> | undefined;

/** The static key list (spec §7.7), or `undefined` when this origin has none. */
export function keyList(d: EmailRecoveryDeployment = requireEmailRecovery()): Promise<KeyList | undefined> {
  keyListCache ??= fetch(d.keyList, { credentials: 'omit' })
    .then((r) => (r.ok ? r.json() : undefined))
    .then((j) => (j ? parseKeyList(j) : undefined))
    .catch(() => undefined);
  return keyListCache;
}

/** The registry's view of one key: its leaf, and the current root with whether the registry accepts it. */
export async function registryKeyView(registry: string, domain: string, modulus: bigint) {
  const s = server();
  await initHashes();
  const kh = keyHash(modulus);
  const record = (await simulateRead(s, registry, 'leaf', [
    xdr.ScVal.scvBytes(Buffer.from(domain)),
    xdr.ScVal.scvBytes(Buffer.from(kh.toString(16).padStart(64, '0'), 'hex')),
  ])) as { index: number; present: boolean } | null;
  const rootBytes = (await simulateRead(s, registry, 'root', [])) as Uint8Array | null;
  if (!rootBytes) return { present: false } as const;
  const root = bigHex(new Uint8Array(rootBytes));
  const accepted = (await simulateRead(s, registry, 'is_accepted_root', [xdr.ScVal.scvBytes(Buffer.from(rootBytes))])) === true;
  if (!record?.present) return { present: false, root, accepted } as const;
  const sib = (await simulateRead(s, registry, 'siblings', [xdr.ScVal.scvU32(record.index)])) as Uint8Array[] | null;
  const siblings = (sib ?? []).map((x) => bigHex(new Uint8Array(x)));
  return { present: true, root, accepted, path: { index: record.index, siblings, root } } as const;
}

/** A key the wallet found, where it came from, and the path the proof will use. */
export interface ResolvedKey {
  modulus: bigint;
  source: 'list' | 'dns';
  keyPath: KeyPath;
  via: 'pin' | 'registry';
}

/** The `d=` and `s=` of an email's signature aligned with its From domain (spec §4.3 rule 1). */
export function signer(eml: Uint8Array): { domain: string; selector: string } {
  const [aligned] = alignedSignatures(parseMessage(eml));
  const domain = aligned?.tags.get('d')?.toLowerCase();
  const selector = aligned?.tags.get('s');
  if (!domain || !selector) throw new Error('This email carries no signature from its sender’s provider.');
  return { domain, selector };
}

/** A key from DNS over HTTPS, for a key the list does not have. */
export async function dnsKey(d: EmailRecoveryDeployment, domain: string, selector: string): Promise<bigint> {
  if (!d.dohResolver) throw new Error('Your provider’s key is not in Nido’s key list, and no DNS lookup is configured.');
  const name = `${selector}._domainkey.${domain}`;
  const res = await fetch(`${d.dohResolver}?name=${encodeURIComponent(name)}&type=TXT`, {
    headers: { accept: 'application/dns-json' },
    credentials: 'omit',
  });
  const [record] = dohTxtRecords(await res.json());
  if (!record) throw new Error(`Your provider does not publish the key ${name}.`);
  return parseDkimKeyRecord(record);
}

/**
 * The key that signed `eml`, and the path a proof uses: the key list's
 * candidates first (each checked against the email's signature), then, if
 * `allowDns()` agrees after telling the user, DNS. A key is used only when
 * the guardian's pin or the registry's accepted root holds it.
 */
export async function resolveRecoveryKey(opts: {
  eml: Uint8Array;
  guardian: GuardianConfig;
  accountCode: bigint;
  allowDns: () => Promise<boolean>;
  d?: EmailRecoveryDeployment;
}): Promise<ResolvedKey> {
  const d = opts.d ?? requireEmailRecovery();
  await initHashes();
  const { domain, selector } = signer(opts.eml);
  const candidates: { modulus: bigint; source: 'list' | 'dns' }[] = [];
  const list = await keyList(d);
  for (const k of list ? keyCandidates(list, domain, selector) : []) candidates.push({ modulus: BigInt(k.modulus), source: 'list' });
  const now = await latestCloseTime();
  const tryKey = async (c: { modulus: bigint; source: 'list' | 'dns' }): Promise<ResolvedKey | string> => {
    if (!(await alignedSignedBlock(opts.eml, c.modulus).then(() => true, () => false))) return 'mismatch';
    const pin = opts.guardian.keyPin[0];
    let pinPath: { index: number; siblings: bigint[]; root: bigint } | undefined;
    if (pin) {
      const tree = pinTree(opts.accountCode, [{ domain, modulus: c.modulus }]);
      if (tree.root === bigHex(pin.root)) pinPath = tree.path(0);
    }
    const reg = await registryKeyView(opts.guardian.registry, domain, c.modulus);
    const choice = chooseKeyPath({
      now,
      pin: pin ? { root: bigHex(pin.root), validUntil: pin.validUntil, path: pinPath } : undefined,
      registry: 'root' in reg && reg.root !== undefined ? { root: reg.root, accepted: reg.accepted, path: reg.present ? reg.path : undefined } : undefined,
    });
    if (choice.kind === 'none') return choice.why;
    const { kind, ...keyPath } = choice;
    return { modulus: c.modulus, source: c.source, keyPath, via: kind };
  };
  let why = '';
  for (const c of candidates) {
    const r = await tryKey(c);
    if (typeof r !== 'string') return r;
    if (r !== 'mismatch') why = r;
  }
  if (await opts.allowDns()) {
    const r = await tryKey({ modulus: await dnsKey(d, domain, selector), source: 'dns' });
    if (typeof r !== 'string') return r;
    if (r !== 'mismatch') why = r;
  }
  throw new Error(why || 'No key Nido trusts signed this email. It may have been changed after your provider sent it.');
}

/**
 * The key that signed an enrollment email, from the list or (after telling
 * the user) DNS; the signature check makes a substituted key fail.
 */
export async function resolveEnrollmentKey(eml: Uint8Array, allowDns: () => Promise<boolean>, d: EmailRecoveryDeployment = requireEmailRecovery()): Promise<{ modulus: bigint; source: 'list' | 'dns'; domain: string; selector: string }> {
  await initHashes();
  const { domain, selector } = signer(eml);
  const list = await keyList(d);
  for (const k of list ? keyCandidates(list, domain, selector) : []) {
    const modulus = BigInt(k.modulus);
    if (await alignedSignedBlock(eml, modulus).then(() => true, () => false)) return { modulus, source: 'list', domain, selector };
  }
  if (!(await allowDns())) throw new Error('Your provider’s key is not in Nido’s key list.');
  return { modulus: await dnsKey(d, domain, selector), source: 'dns', domain, selector };
}

/** The leaf a modulus has for `domain`, as the registry and pin trees hold it. */
export const leafOf = (domain: string, modulus: bigint) => registryLeaf(domain, keyHash(modulus));
export { merkleRoot };

// --- the alert vault and the sealed inbound mail ---------------------------

/** The vault's attested key: its measurement must be active in the enclave-image registry. */
export async function vaultKey(d: EmailRecoveryDeployment = requireEmailRecovery()): Promise<VaultKey> {
  const nonce = attestationNonce();
  const res = await fetch(`${d.alertService}/v1/attestation?nonce=${toBase64Url(nonce)}`, { credentials: 'omit' });
  if (!res.ok) throw new Error('The alert service did not answer.');
  const attestation = fromBase64Url(((await res.json()) as { attestation: string }).attestation);
  const measurement = await claimedMeasurement(attestation);
  const active = await simulateRead(server(), d.enclaveImageRegistry, 'is_active', [xdr.ScVal.scvBytes(Buffer.from(measurement, 'hex'))]);
  if (active !== true) throw new Error('The alert vault runs an enclave image the public registry has not approved.');
  return attestedVaultKey(attestation, {
    roots: d.attestationRoots.map((b) => Uint8Array.from(atob(b), (c) => c.charCodeAt(0))),
    allowedMeasurements: [measurement],
    nonce,
  });
}

/**
 * Ask the vault to seal the email whose Subject ends with `valueHex` to this
 * browser; `expiresAt` is when the registration stops accepting mail (24
 * hours, spec §4.6).
 */
export async function registerInbound(
  valueHex: string,
  d: EmailRecoveryDeployment = requireEmailRecovery(),
): Promise<{ secret: InboxSecret; expiresAt: number }> {
  const vault = await vaultKey(d);
  const { envelope, secret } = await inboundRegistration(vault.publicKey, valueHex);
  const res = await fetch(`${d.alertService}/v1/inbound`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ envelope: toBase64Url(envelope) }),
    credentials: 'omit',
  });
  const body = (await res.json().catch(() => ({}))) as { error?: string; expiresAt?: number };
  if (res.status === 429) throw new Error('Too many emails were set up from this network in the last hour. Try again later, or import the email instead.');
  if (!res.ok) throw new Error(body.error ?? 'The alert service refused the registration.');
  return { secret, expiresAt: body.expiresAt ?? Date.now() + 24 * 3600_000 };
}

/** The emails the vault sealed to this browser so far, opened. */
export async function fetchInbound(secret: InboxSecret, d: EmailRecoveryDeployment = requireEmailRecovery()): Promise<Uint8Array[]> {
  const res = await fetch(`${d.alertService}/v1/inbound/${secret.id}`, { credentials: 'omit' });
  if (!res.ok) return [];
  const { messages } = (await res.json()) as { messages: string[] };
  const out: Uint8Array[] = [];
  for (const m of messages) out.push(await openInboundMessage(secret, fromBase64Url(m)).catch(() => new Uint8Array(0)));
  return out.filter((m) => m.length > 0);
}

// --- alerts --------------------------------------------------------------

/** The code every alert about this attempt carries (spec §10.1). */
export async function attemptAlertCode(accountCode: Uint8Array, controller: string, account: string, attemptId: bigint): Promise<string> {
  return alertCode({
    key: await deriveAlertCodeKey(accountCode),
    networkId: await sha256(new TextEncoder().encode(NETWORK_PASSPHRASE)),
    controller: contractIdFromStrkey(controller),
    account: contractIdFromStrkey(account),
    subject: { kind: 'attempt', attemptId },
  });
}

// --- submitting the approval -------------------------------------------------

/**
 * `submit_guardian` with the email approval in the guardian's authorization
 * entry: through the relayer when this build has one, else paid by this
 * browser's submitter. Either way the entry needs no signature but the
 * proof, so anyone could submit it.
 */
export async function submitEmailApproval(p: {
  controller: string;
  account: string;
  attemptId: bigint;
  domain: number;
  guardian: string;
  statement: Uint8Array;
  proof: ProofResult;
}): Promise<string> {
  const digest = await sha256(p.statement);
  const keyRoot = p.proof.publicInputs.slice(96, 128);
  const entry = emailApprovalEntry({
    guardian: p.guardian,
    controller: p.controller,
    fnName: 'submit_guardian',
    digest,
    approval: { statement: p.statement, keyRoot, proof: p.proof.proof },
    nonce: randomNonce(),
    expirationLedger: (await latestLedger()) + 1_000,
  });
  const op = submitGuardianOperation({ ...p, entry });
  if (RELAYER_URL) {
    // The relayer reads the host function and the entry from an envelope; it signs and pays itself.
    const envelope = new TransactionBuilder(new Account(DUMMY_SOURCE, '0'), { fee: '100', networkPassphrase: NETWORK_PASSPHRASE })
      .addOperation(op)
      .setTimeout(60)
      .build();
    return (await relayerSubmitAndConfirm(envelope)).hash;
  }
  await getSubmitter();
  return (await submitPermissionlessOp(op, 'enforce')).hash;
}

export { Address, fromHex, toHex };
