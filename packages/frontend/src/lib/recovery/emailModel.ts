/**
 * The pure rules of email recovery in the wallet
 * (`docs/email-recovery/spec.md`): which email to send and how to show it,
 * which key path a proof uses, what is still needed after the email
 * approval, and the copy the pages show. Chain reads and DOM live in
 * `emailRecovery.ts` and the pages; this module is what the unit tests pin.
 */

import { bytes, fieldHex, recoverySubject } from '@nidohq/email-recovery';
import { StrKey } from '@stellar/stellar-sdk';
import { PIN_LIFETIME_SECONDS, type WalletApex } from './emailConfig.js';

export type { WalletApex };
import { ledgersToText, SECONDS_PER_LEDGER } from './model.js';

/** The privacy claim the pages make, scoped as the spec states it (§10.7). */
export const PRIVACY_CLAIM = 'Nido’s servers and staff can’t read your address.';

/** What the mail provider, and someone watching the chain, can tell from a recovery or enrollment email (spec §10.7). */
export const PROVIDER_SEES =
  'Your mail provider sees that you sent a Nido recovery email and when; someone watching the blockchain at the same moment may be able to tell which Nido it was for.';

/** The email services that deliver alerts (spec §10.6), as the pages name them. */
export const SENDING_SERVICES = 'Lettermint, or Scaleway if Lettermint fails (both EU email services)';

/** Where the enrolled address goes once enrollment has read it (spec §10.7). */
export const ENROLLED_ADDRESS_NOTE =
  'On chain there is only a salted fingerprint of it. Nido stores the address itself only if you also send alerts to it, and then only inside its sealed alert vault; ' +
  `the email services that deliver alerts, ${SENDING_SERVICES}, then see it with every alert.`;

/** The version of the consent text below; the vault records which one the user saw. */
export const CONSENT_VERSION = 4;
export const CONSENT_TEXT =
  'Nido will email this address and send a notification to this device whenever your Nido’s recovery needs your attention: ' +
  'when a recovery is approved or completes, when your recovery email approves a recovery, its cancellation or a settings change, ' +
  'or when the recovery settings change. ' +
  'Alerts carry a six-digit code and never name your Nido or contain a link. Recovery attempts that are only opened, ' +
  `which anyone can do, show in your wallet instead. Alert emails are sent through ${SENDING_SERVICES}, which see this address and each alert. ` +
  'About once a month this device asks you to tap a notification, to confirm that alerts still reach you.';

/** What the user sends, from their own inbox (spec §4.1). */
export interface EmailToSend {
  to: string;
  subject: string;
  /** Body text: unconstrained for recovery; the backup block for enrollment. */
  body: string;
}

/** A `mailto:` link that fills in everything (RFC 6068). */
export function mailtoLink(e: EmailToSend): string {
  const q = [`subject=${encodeURIComponent(e.subject)}`];
  if (e.body) q.push(`body=${encodeURIComponent(e.body.replace(/\r?\n/g, '\r\n'))}`);
  return `mailto:${encodeURIComponent(e.to).replace(/%40/g, '@')}?${q.join('&')}`;
}

/** The line every recovery email's body starts with: whoever asked for this email is the attacker. */
export const NOBODY_ASKS_LINE = 'If anyone asked you to send this email, stop. Nido never asks for this.';

/** The recovery email for a statement digest and `rho` (spec §4.2). The body is unconstrained (§4.4): it warns. */
export function recoveryEmail(inbox: string, digest: Uint8Array, rho: bigint): EmailToSend {
  return {
    to: inbox,
    subject: recoverySubject(digest, rho),
    body: `${NOBODY_ASKS_LINE}\n\nI lost every device with my passkey and I am recovering my own Nido.`,
  };
}

/** What a device holding the account's passkey reads first about a recovery: it does not need one. */
export const PASSKEY_DEVICE_CANCEL =
  'This device has your passkey, so you do not need a recovery. Cancel it unless you are deliberately replacing this passkey.';

/** The account's recovery page, on the wallet's apex (spec §5.7). */
export function recoveryPageUrl(account: string, apex: WalletApex): string {
  return `${apex.scheme}//${account.toLowerCase()}.${apex.host}/security/recover/`;
}

/**
 * Where the recovery code is typed: nobody asks for it, and how to tell
 * this page is the user's own: the whole address against the recovery
 * kit's, and the wallet's apex, both from this build's constants.
 */
export function codeEntryWarning(account: string, apex: WalletApex): string {
  return (
    'Nobody from Nido will ask for this code, and nobody else should either: type it only here, yourself, after losing every device with your passkey. ' +
    `Check the address bar first: it must show exactly ${recoveryPageUrl(account, apex)}, the Recovery page line of your recovery kit, ` +
    `and every Nido page ends in .${apex.host}. If any character differs, close this page.`
  );
}

/** The warning enrollment shows when alerts would go to the inbox being enrolled (spec §5.4). */
export function alertAddressWarning(alertAddress: string, factorAddress: string): string | undefined {
  if (alertAddress.trim().toLowerCase() !== factorAddress.trim().toLowerCase()) return undefined;
  return (
    'This is the inbox you are setting up for recovery. Someone who takes over that inbox can delete the alerts sent to it before you see them. ' +
    'Use an address at another provider (a work or family address, for example), so a recovery attempt reaches you even if this inbox is taken.'
  );
}

/** Where to keep the recovery kit: anywhere but the account behind the inbox. */
export const KIT_STORAGE_ADVICE =
  'Keep it outside the account behind the inbox you will use: not in that provider’s password manager or cloud drive ' +
  '(for a Gmail address, not in Google Password Manager or Drive; for iCloud Mail, not in iCloud Keychain or Files). ' +
  'Whoever takes over that account would then have both your inbox and this code.';

/**
 * What an iPhone or iPad must do before this page can ask for
 * notifications, or `undefined` when nothing is needed: there Web Push works
 * only in a web app added to the Home Screen ("Web Push for Web Apps on iOS
 * and iPadOS", https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/),
 * and each Nido is its own subdomain, so the icon must be added from this
 * Nido's own address (`host`). An iPad's Safari reports a Mac user agent;
 * its touch points tell it apart.
 */
export function homeScreenNeeded(o: { userAgent: string; standalone: boolean; maxTouchPoints: number; host: string }): string | undefined {
  const ios = /iPhone|iPad|iPod/.test(o.userAgent) || (/Macintosh/.test(o.userAgent) && o.maxTouchPoints > 1);
  if (!ios || o.standalone) return undefined;
  return (
    'On an iPhone or iPad, notifications reach only Nido opened from your Home Screen, added from this Nido’s own address. ' +
    `In Safari, with this page open at ${o.host}, tap Share, then Add to Home Screen. Then open Nido from that icon and come back here.`
  );
}

/** What the page says next to Copy: the clipboard is another place the code goes. */
export const COPY_KIT_NOTE =
  'Copy puts the code on this device’s clipboard, which can sync it to your other devices (Universal Clipboard on Apple devices, clipboard sync on Windows) ' +
  'and which keyboard apps can read. Paste it at once into a password manager outside your inbox’s provider, then copy something else.';

/**
 * How the kit is best saved on this device (spec §5.6). On an iPhone or iPad
 * a download goes to iCloud Drive unless Safari's download location was
 * changed, the place to avoid for an iCloud Mail inbox: there printing
 * comes first, and the page says where a download goes.
 */
export function kitActions(userAgent: string): { primary: 'print' | 'download'; note?: string } {
  if (!/iPhone|iPad|iPod/.test(userAgent)) return { primary: 'download' };
  return {
    primary: 'print',
    note:
      'On an iPhone or iPad, Download saves the kit to iCloud Drive (Files) unless you changed Safari’s download location ' +
      '(Settings, Apps, Safari, Downloads). If your recovery inbox is iCloud Mail, print the kit, or keep it somewhere other than iCloud.',
  };
}

/**
 * A passkey's backup state as its authenticator data states it (W3C
 * WebAuthn Level 3 §6.1): flag BE (0x08) backup eligible, BS (0x10) backed
 * up, that is synced; with attested credential data (AT, 0x40, present when
 * the passkey is created), the AAGUID of the credential manager.
 */
export interface PasskeyBackup {
  eligible: boolean;
  synced: boolean;
  aaguid?: string;
}

export function passkeyBackup(authenticatorData: Uint8Array): PasskeyBackup | undefined {
  if (authenticatorData.length < 37) return undefined;
  const flags = authenticatorData[32]!;
  const out: PasskeyBackup = { eligible: (flags & 0x08) !== 0, synced: (flags & 0x10) !== 0 };
  if (flags & 0x40 && authenticatorData.length >= 53) {
    const h = bytes.toHex(authenticatorData.subarray(37, 53));
    if (/[^0]/.test(h)) out.aaguid = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  return out;
}

/** The syncing platforms named by the AAGUID they report (passkeydeveloper/passkey-authenticator-aaguids, `aaguid.json`, read 2026-11-02). */
const PLATFORM_AAGUIDS: Record<string, 'google' | 'apple'> = {
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'google', // Google Password Manager
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'apple', // Apple Passwords
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'apple', // iCloud Keychain (Managed)
};

const PLATFORMS = {
  google: { name: 'Google', keychain: 'Google Password Manager', domains: ['gmail.com', 'googlemail.com'] },
  apple: { name: 'Apple', keychain: 'iCloud Keychain', domains: ['icloud.com', 'me.com', 'mac.com'] },
} as const;

/**
 * The note enrollment shows when the inbox's provider is the platform that
 * syncs this device's passkey (spec §5.4): losing that one account would
 * lose the passkey and the inbox together. From the passkey's own flags
 * when an assertion gave them (`backup`): none for a passkey that is not
 * synced, the platform from its AAGUID where one is known, and none for
 * another credential manager's. The user agent stands in for what they do
 * not say. `undefined` when the two accounts differ or nothing suggests
 * they match.
 */
export function syncedPasskeyNote(domain: string, userAgent: string, backup?: PasskeyBackup): string | undefined {
  const d = domain.trim().toLowerCase();
  if (backup && !backup.synced) return undefined;
  const named = backup?.aaguid ? (PLATFORM_AAGUIDS[backup.aaguid] ?? 'other') : undefined;
  if (named === 'other') return undefined;
  const guess =
    /iPhone|iPad|iPod|Macintosh/.test(userAgent)
      ? 'apple'
      : /Android/.test(userAgent) || (/Chrome\/|CriOS\//.test(userAgent) && !/Edg\/|EdgA\/|OPR\/|SamsungBrowser\//.test(userAgent))
        ? 'google'
        : undefined;
  const key = named ?? guess;
  if (!key || !(PLATFORMS[key].domains as readonly string[]).includes(d)) return undefined;
  const p = PLATFORMS[key];
  const lead = named
    ? `The passkey on this device is saved in your ${p.name} account (${p.keychain}), which syncs it to your other devices.`
    : backup?.synced
      ? `The passkey on this device is synced to your other devices, probably by your ${p.name} account (${p.keychain}).`
      : `The passkey on this device is probably saved in your ${p.name} account (${p.keychain}), which syncs it to your other devices.`;
  return (
    `${lead} If ${d} is that same account, losing it loses your passkey and this inbox together, and email recovery would not help. ` +
    'Use an inbox at another provider, or add another helper.'
  );
}

/** The groups of the kit code (of seven) enrollment asks to have typed back: two distinct ones. */
export function kitCheckGroups(random: () => number = Math.random): [number, number] {
  const a = Math.floor(random() * 7);
  const b = (a + 1 + Math.floor(random() * 6)) % 7;
  return a < b ? [a, b] : [b, a];
}

/** Whether `typed` holds kit groups `groups` (case and spaces forgiven). */
export function kitCheckMatches(kit: string, groups: readonly number[], typed: readonly string[]): boolean {
  const parts = kit.split(' ');
  return groups.every((g, i) => (typed[i] ?? '').replace(/\s+/g, '').toUpperCase() === parts[g]);
}

/** The recovery kit file: the code, the Nido it recovers, where recovery starts, and Nido's apex (spec §5.6). */
export function recoveryKitText(o: { kit: string; account: string; apex: WalletApex }): string {
  return [
    'Nido recovery kit',
    '',
    `Recovery code: ${o.kit}`,
    `Nido: ${o.account}`,
    `Recovery page: ${recoveryPageUrl(o.account, o.apex)}`,
    `Nido's address: ${o.apex.scheme}//${o.apex.host} (every Nido page ends in .${o.apex.host})`,
    '',
    'If you lose every device with your passkey, open the recovery page (or paste the Nido address above at the start of',
    'Nido’s recovery page) and follow the email step. Before typing the code, check that the address bar shows exactly',
    'the recovery page above. Nobody from Nido will ask for this code.',
    '',
    KIT_STORAGE_ADVICE,
    '',
  ].join('\n');
}

/** What the apex recovery page makes of an address pasted from a recovery kit: an account address, or a name. */
export function accountFromKitInput(text: string): { account: string } | { name: string } | undefined {
  const t = text.trim();
  const c = /\b(C[A-Z2-7]{55})\b/i.exec(t);
  if (c && StrKey.isValidContract(c[1]!.toUpperCase())) return { account: c[1]!.toUpperCase() };
  const host = /^(?:https?:\/\/)?([a-z0-9-]+)\./i.exec(t);
  const label = host?.[1] ?? (/^[a-z][a-z0-9]*$/i.test(t) ? t : undefined);
  if (label && StrKey.isValidContract(label.toUpperCase())) return { account: label.toUpperCase() };
  if (label && /^[a-z][a-z0-9]{0,14}$/i.test(label)) return { name: label.toLowerCase() };
  return undefined;
}

/** The sealed-inbound registration's deadline (spec §4.6), as the recovery page shows it. */
export function inboundDeadline(expiresAt: number, now: number): { expired: boolean; text: string } {
  const left = expiresAt - now;
  if (left <= 0) {
    return { expired: true, text: 'The 24 hours for this email are over, so an email sent now is no longer picked up. Get a new email to send.' };
  }
  const hours = Math.floor(left / 3600_000);
  const minutes = Math.ceil((left % 3600_000) / 60_000);
  const span = hours > 0 ? `${hours} h ${minutes} min` : `${minutes} min`;
  return {
    expired: false,
    text: `This page picks up the email until ${new Date(expiresAt).toLocaleString()} (${span} left). If you need longer, get a new email to send then.`,
  };
}

/** How long after a device last acknowledged a probe the wallet still calls it confirmed: two 30-day probe intervals (spec §10.6). */
export const RECENT_ACK_MS = 60 * 24 * 3600_000;

/** One push device as the vault's `status` read answers (spec §10.3 rule 7). */
export interface DeviceChannel {
  id: string;
  state: 'live' | 'unacknowledged' | 'lapsed';
  addedAt: number;
  ackedAt: number;
}

/** This device's own push registration for the account, as the browser and its service worker know it. */
export interface ThisDevice {
  /** `live` while this browser still holds the subscription it registered; `gone` when it lost it. */
  state: 'live' | 'gone';
  /** Its id in a `status` answer. */
  id: string;
  /** When this device last acknowledged a probe (ms), as its service worker recorded it. */
  ackedAt?: number;
}

/**
 * The second alert channel at runtime (spec §9.3 rule 2): `here` when this
 * device receives the notifications and confirmed so recently; `elsewhere`
 * when another device does; `unacknowledged` when no device confirmed the
 * last two probes; `lapsed` when none is left; `unknown` until the vault is
 * asked (with the passkey).
 */
export type SecondChannel = 'here' | 'elsewhere' | 'unacknowledged' | 'lapsed' | 'unknown';

/** What the alert channels section shows. `rule2` is broken while no device is known to receive and confirm alerts. */
export interface ChannelView {
  state: SecondChannel;
  rule2: 'ok' | 'broken';
  text: string;
  /** Offer "Add this device". */
  offerAdd: boolean;
  /** Offer "Add another helper": the channel is broken and the email vote alone authorizes. */
  offerHelper: boolean;
}

/**
 * Whether the email vote alone authorizes an attempt under a recovery
 * member: guardian-only mode with a quorum of one and the email helper
 * listed (spec §9.3 rule 3, email plus delay). In combined mode the
 * recovery kit is always needed as well.
 */
export function emailAloneAuthorizes(o: { mode: string; quorum: number; emailListed: boolean }): boolean {
  return o.emailListed && o.mode === 'guardian-only' && o.quorum <= 1;
}

/**
 * What the wallet says while no device is known to receive and confirm the
 * notifications (spec §9.3 rule 2): nothing on chain changed, so the email
 * helper still counts, and under email plus delay (`emailAlone`) it still
 * approves a recovery alone.
 */
export function secondChannelWarning(state: 'lapsed' | 'unacknowledged', emailAlone: boolean): string {
  const cause =
    state === 'lapsed'
      ? 'Notifications for your recovery alerts no longer reach any of your devices.'
      : 'Nido could not confirm that your recovery notifications reach you: no device has confirmed the last two checks, which ask you to tap a notification.';
  return emailAlone
    ? 'Your email helper can still approve a recovery alone, and your second alert channel is not working: fix the channel now, or add another helper. ' +
        `${cause} A recovery your email approves finishes after its waiting period unless you cancel it, and you may hear of it only by email. ` +
        'Until a device receives them again, Nido will not save settings in which your email helper can approve alone (rule 2).'
    : `Your second alert channel is not working: fix it now. ${cause} Your email helper still counts as one approval, and you would hear of its approvals only by email (rule 2).`;
}

/** Why the settings page refuses a save while the channel is broken (spec §9.3 rule 2). */
export const EMAIL_ALONE_REFUSED =
  'Your second alert channel is not working, so Nido will not save settings in which your email helper can approve a recovery alone (rule 2). ' +
  'Add this device, require another helper’s approval as well (2 or more must approve), or remove the email helper.';

/**
 * The channel as this page sees it: the vault's devices once the owner
 * asked (`vault`), else this device's own registration; `now` and `date`
 * for the copy; `emailAlone` when the applied member lets the email vote
 * authorize alone. "They reach this device" is said only on a device the
 * vault lists as live, or that confirmed a probe within [`RECENT_ACK_MS`].
 */
export function channelView(o: {
  vault?: DeviceChannel[];
  device?: ThisDevice;
  now: number;
  date?: (ms: number) => string;
  emailAlone?: boolean;
}): ChannelView {
  const date = o.date ?? ((ms: number) => new Date(ms).toLocaleDateString());
  const alone = o.emailAlone ?? false;
  const broken = (state: 'lapsed' | 'unacknowledged'): ChannelView => ({
    state,
    rule2: 'broken',
    text: secondChannelWarning(state, alone),
    offerAdd: true,
    offerHelper: alone,
  });
  const ok = (state: SecondChannel, text: string, offerAdd: boolean): ChannelView => ({ state, rule2: 'ok', text, offerAdd, offerHelper: false });
  if (o.vault) {
    const live = o.vault.filter((d) => d.state === 'live');
    if (!live.length) return broken(o.vault.some((d) => d.state === 'unacknowledged') ? 'unacknowledged' : 'lapsed');
    const mine = o.device?.state === 'live' ? live.find((d) => d.id === o.device!.id) : undefined;
    if (mine) {
      const confirmed = Math.max(mine.ackedAt, o.device?.ackedAt ?? 0);
      return ok('here', `Alert notifications: they reach this device (last confirmed ${date(confirmed)}).`, false);
    }
    const first = live.reduce((a, b) => (b.addedAt < a.addedAt ? b : a));
    return ok('elsewhere', `Recovery notifications go to another device (set up on ${date(first.addedAt)}). Add this device too.`, true);
  }
  if (o.device?.state === 'gone') return broken('lapsed');
  if (o.device?.ackedAt !== undefined && o.now - o.device.ackedAt <= RECENT_ACK_MS) {
    return ok('here', `Alert notifications: they reach this device (you last confirmed ${date(o.device.ackedAt)}).`, false);
  }
  return o.device
    ? ok('unknown', 'Alert notifications: this device is set up for them. Checking that they reach you needs your passkey.', false)
    : ok('unknown', 'Alert notifications: this device does not receive them. Check your alert channels to see which device does, or add this one.', true);
}

/** How often the wallet asks the owner to check the recovery code: about twice a year, in the wallet only, never as a notification. */
export const CODE_CHECK_EVERY_MS = 182 * 24 * 3600_000;

/**
 * The reminder the email card shows when the recovery code was last checked
 * on this device more than [`CODE_CHECK_EVERY_MS`] ago, or never here
 * (`lastCheckedAt` undefined); `undefined` otherwise.
 */
export function codeCheckReminder(lastCheckedAt: number | undefined, now: number): string | undefined {
  if (lastCheckedAt !== undefined && now - lastCheckedAt < CODE_CHECK_EVERY_MS) return undefined;
  const when = lastCheckedAt === undefined ? 'You have not checked your recovery code on this device yet.' : 'It is six months since you last checked your recovery code here.';
  return `${when} Check that you can still find it: recovering by email needs it, and Nido never has it.`;
}

/** The result of the recovery-code check (spec §5.6): the code against the guardian's pin root. */
export function codeCheckText(r: 'match' | 'mismatch' | 'no-pin'): string {
  switch (r) {
    case 'match':
      return 'This is the recovery code of your email helper. Keep it where you found it.';
    case 'mismatch':
      return 'This code does not match your email helper. Look for another copy (your recovery kit, or the encrypted block in your Sent folder with its passphrase). ' +
        'If you cannot find the right one, set up email recovery again now, while you still have your passkey: that makes a new code.';
    case 'no-pin':
      return 'Your email helper keeps no fingerprint this check can compare against, so it cannot tell. Set up email recovery again to get a helper it can check.';
  }
}

/**
 * Check a typed recovery code against the guardian's pin (spec §7.4): the
 * pin's leaf 0 is `P2(DOM_PIN_SALT, account_code)` and its other leaves the
 * pinned keys, so the code is right exactly when, with some key the wallet
 * knows, it rebuilds the pin root on chain. Nothing new is stored.
 */
export function checkCodeAgainstPin(o: {
  accountCode: bigint;
  pinRoot: bigint | undefined;
  keys: { domain: string; modulus: bigint }[];
  root: (accountCode: bigint, key: { domain: string; modulus: bigint }) => bigint;
}): 'match' | 'mismatch' | 'no-pin' {
  if (o.pinRoot === undefined) return 'no-pin';
  return o.keys.some((k) => o.root(o.accountCode, k) === o.pinRoot) ? 'match' : 'mismatch';
}

/** The 64 hex characters that end a recovery or enrollment Subject: what the sealed inbound path routes by. */
export function subjectValue(subject: string): string {
  const m = /(?:APPROVE|ENROLL) NIDO ACCOUNT RECOVERY ([0-9a-f]{64})$/.exec(subject);
  if (!m) throw new Error('not a Nido recovery or enrollment Subject');
  return m[1]!;
}

/** What the page keeps between reloads for one email approval: never `account_code`. */
export interface PendingEmailApproval {
  /** When the sealed inbound registration stops accepting the email (ms), as the vault answered. */
  inboxExpiresAt?: number;
  /** The attempt the approval is for. */
  attemptId: string;
  /** `sha256(statement)` when the Subject was built, hex. */
  digest: string;
  /** `rho`, hex. It never leaves this browser. */
  rho: string;
  /** The sealed inbound registration (spec §4.6): the inbox id and the device key's seed. */
  inbox?: { id: string; seed: string };
}

export function newPendingApproval(attemptId: bigint, digest: Uint8Array, rho: bigint): PendingEmailApproval {
  return { attemptId: attemptId.toString(), digest: bytes.toHex(digest), rho: fieldHex(rho) };
}

/** Why a saved approval no longer fits the attempt's current statement, or `undefined` when it does. */
export function pendingApprovalProblem(p: PendingEmailApproval, attemptId: bigint, digest: Uint8Array): string | undefined {
  if (p.attemptId !== attemptId.toString()) return 'That email was for an earlier recovery attempt. Send a new one.';
  if (p.digest !== bytes.toHex(digest)) {
    return 'The recovery attempt changed since you sent the email (for example its settings moved on), so the email no longer matches. Send a new one.';
  }
  return undefined;
}

/** How the proof shows that the signing key is trusted (spec §7.3, §7.4). */
export type KeyPathChoice =
  | { kind: 'pin'; root: bigint; index: number; siblings: bigint[] }
  | { kind: 'registry'; root: bigint; index: number; siblings: bigint[] };

/**
 * The key path a proof should use: the guardian's pin when it holds this
 * key and has not expired at close time `now` (Unix seconds; the pin is
 * accepted without asking the registry), else the registry's current tree
 * when the key is a leaf of a root the registry accepts.
 */
export function chooseKeyPath(opts: {
  now: number;
  pin?: { root: bigint; validUntil: number; path?: { index: number; siblings: bigint[]; root: bigint } };
  registry?: { root: bigint; accepted: boolean; path?: { index: number; siblings: bigint[]; root: bigint } };
}): KeyPathChoice | { kind: 'none'; why: string } {
  const pin = opts.pin;
  if (pin?.path && pin.path.root === pin.root && opts.now <= pin.validUntil) {
    return { kind: 'pin', ...pin.path };
  }
  const reg = opts.registry;
  if (reg?.path && reg.accepted && reg.path.root === reg.root) return { kind: 'registry', ...reg.path };
  if (pin?.path && opts.now > pin.validUntil && !reg?.path) {
    return { kind: 'none', why: 'Your email guardian’s key pin has expired and the key registry does not list your provider’s key yet.' };
  }
  return {
    kind: 'none',
    why: 'Your mail provider signed this email with a key that neither your email guardian nor the key registry trusts yet. If your provider changed its key recently, try again after the registry adds it.',
  };
}

/** Progress copy for each prover stage, in plain language. */
export function stageText(stage: 'download' | 'witness' | 'proving' | 'verifying', p: { loaded?: number; total?: number; cached?: boolean }): string {
  switch (stage) {
    case 'download':
      if (p.loaded !== undefined && p.total) {
        return p.cached ? 'Loading the prover from this browser…' : `Downloading the prover (${(p.loaded / 1e6).toFixed(1)} of ${(p.total / 1e6).toFixed(1)} MB)…`;
      }
      return 'Getting the prover ready…';
    case 'witness':
      return 'Reading your email…';
    case 'proving':
      return 'Proving it came from your inbox. This can take up to two minutes on a phone.';
    case 'verifying':
      return 'Checking the proof…';
  }
}

/** "1:05" for a duration in milliseconds. */
export function clock(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

/** What an attempt still needs once the email has voted (the email guardian is one of `guardians`). */
export function remainingFactors(opts: {
  quorum: number;
  approvals: string[];
  guardians: string[];
  emailGuardian: string;
  zkNeeded: boolean;
  zkRecorded: boolean;
}): { emailApproved: boolean; othersNeeded: number; zkNeeded: boolean; text: string } {
  const emailApproved = opts.approvals.includes(opts.emailGuardian);
  const counted = opts.approvals.filter((a) => opts.guardians.includes(a)).length;
  const othersNeeded = Math.max(0, opts.quorum - counted - (emailApproved ? 0 : 1));
  const zkNeeded = opts.zkNeeded && !opts.zkRecorded;
  const parts: string[] = [emailApproved ? 'Your email approval is recorded.' : 'Your email approval is not recorded yet.'];
  if (othersNeeded > 0) parts.push(`${othersNeeded} more ${othersNeeded === 1 ? 'helper needs' : 'helpers need'} to approve.`);
  if (zkNeeded) parts.push('Your recovery kit still needs to prove it is you.');
  if (othersNeeded === 0 && !zkNeeded && emailApproved) parts.push('Nothing else is needed: the waiting period starts now.');
  return { emailApproved, othersNeeded, zkNeeded, text: parts.join(' ') };
}

/** The countdown until `executableAfter`, from the latest ledger and when it was read. */
export function delayCountdown(executableAfter: number, ledger: number, readAtMs: number, nowMs: number): { remainingMs: number; text: string } {
  const remainingMs = Math.max(0, (executableAfter - ledger) * SECONDS_PER_LEDGER * 1000 - (nowMs - readAtMs));
  const ledgers = Math.ceil(remainingMs / (SECONDS_PER_LEDGER * 1000));
  return {
    remainingMs,
    text: remainingMs === 0 ? 'The waiting period is over.' : `About ${ledgersToText(ledgers)} left (${clock(remainingMs)} at five seconds a ledger).`,
  };
}

/** The verification code as alerts print it: "169 328". */
export function spacedCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

/** The enrollment steps, in order; each needs the ones before it. */
export const ENROLL_STEPS = ['code', 'email', 'check', 'alerts', 'deploy', 'apply'] as const;
export type EnrollStep = (typeof ENROLL_STEPS)[number];

export function nextEnrollStep(done: Partial<Record<EnrollStep, boolean>>): EnrollStep | 'done' {
  for (const s of ENROLL_STEPS) if (!done[s]) return s;
  return 'done';
}

/** The `valid_until` of a pin the wallet deploys when the latest ledger closed
 *  at `now` (Unix seconds; spec §7.4, §13 question 2). */
export function pinValidUntil(now: number): number {
  return now + PIN_LIFETIME_SECONDS;
}
