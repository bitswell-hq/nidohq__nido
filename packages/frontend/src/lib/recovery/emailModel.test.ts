import { describe, expect, it } from 'vitest';
import { Address, StrKey, xdr } from '@stellar/stellar-sdk';
import { initHashes, recoverySubject } from '@nidohq/email-recovery';
import {
  KIT_STORAGE_ADVICE,
  NOBODY_ASKS_LINE,
  PASSKEY_DEVICE_CANCEL,
  CONSENT_TEXT,
  CONSENT_VERSION,
  ENROLLED_ADDRESS_NOTE,
  PRIVACY_CLAIM,
  PROVIDER_SEES,
  RECENT_ACK_MS,
  SECOND_CHANNEL_LAPSED,
  SECOND_CHANNEL_UNACKNOWLEDGED,
  accountFromKitInput,
  channelView,
  kitActions,
  recoveryPageUrl,
  syncedPasskeyNote,
  alertAddressWarning,
  checkCodeAgainstPin,
  chooseKeyPath,
  codeCheckText,
  codeEntryWarning,
  inboundDeadline,
  kitCheckGroups,
  kitCheckMatches,
  pinValidUntil,
  recoveryKitText,
  clock,
  delayCountdown,
  mailtoLink,
  newPendingApproval,
  nextEnrollStep,
  pendingApprovalProblem,
  recoveryEmail,
  remainingFactors,
  spacedCode,
  stageText,
  subjectValue,
} from './emailModel';
import {
  emailApprovalEntry,
  emailApprovalScVal,
  deployedAddress,
  guardianConfigFromNative,
  guardianConfigScVal,
  submitGuardianOperation,
} from './emailGuardian';
import { PIN_LIFETIME_SECONDS, parseEmailRecoveryDeployment, walletApex } from './emailConfig';
import { EMAIL_CIRCUIT_ID } from './emailProver';

const contract = (n: number) => StrKey.encodeContract(Buffer.alloc(32, n));

describe('the email to send', () => {
  it('is a mailto: link with the exact Subject, which routes by its value', async () => {
    await initHashes();
    const digest = new Uint8Array(32).fill(3);
    const email = recoveryEmail('recover@recovery.test', digest, 9n);
    expect(email.subject).toBe(recoverySubject(digest, 9n));
    const link = mailtoLink(email);
    expect(link.startsWith('mailto:recover@recovery.test?subject=APPROVE%20NIDO%20ACCOUNT%20RECOVERY%20')).toBe(true);
    expect(decodeURIComponent(new URL(link).searchParams.get('subject')!)).toBe(email.subject);
    expect(subjectValue(email.subject)).toBe(email.subject.slice(-64));
    expect(() => subjectValue(`Re: ${email.subject} x`)).toThrow();
    expect(mailtoLink({ to: 'a@b.c', subject: 'S', body: 'one\ntwo' })).toBe('mailto:a@b.c?subject=S&body=one%0D%0Atwo');
  });

  it('a saved approval fits only the attempt and statement it was built for', () => {
    const digest = new Uint8Array(32).fill(1);
    const p = newPendingApproval(4n, digest, 77n);
    expect(pendingApprovalProblem(p, 4n, digest)).toBeUndefined();
    expect(pendingApprovalProblem(p, 5n, digest)).toMatch(/earlier recovery attempt/);
    expect(pendingApprovalProblem(p, 4n, new Uint8Array(32).fill(2))).toMatch(/changed/);
    expect(JSON.stringify(p)).not.toMatch(/account_?code/i);
  });

  it('the body opens by telling a talked-into sender to stop', async () => {
    await initHashes();
    const email = recoveryEmail('recover@recovery.test', new Uint8Array(32).fill(3), 9n);
    expect(email.body.startsWith('If anyone asked you to send this email, stop. Nido never asks for this.')).toBe(true);
    expect(email.body.startsWith(NOBODY_ASKS_LINE)).toBe(true);
    const body = new URL(mailtoLink(email)).searchParams.get('body')!;
    expect(body.startsWith(NOBODY_ASKS_LINE)).toBe(true);
  });

  it('the privacy claim is the scoped one', () => {
    expect(PRIVACY_CLAIM).toBe('Nido’s servers and staff can’t read your address.');
  });

  it('the privacy copy around the claim says what the provider, a chain watcher and the sending services see', () => {
    expect(PROVIDER_SEES).toBe(
      'Your mail provider sees that you sent a Nido recovery email and when; someone watching the blockchain at the same moment may be able to tell which Nido it was for.',
    );
    expect(PROVIDER_SEES).not.toMatch(/only/);
    expect(ENROLLED_ADDRESS_NOTE).toBe(
      'On chain there is only a salted fingerprint of it. Nido stores the address itself only if you also send alerts to it, and then only inside its sealed alert vault; ' +
        'the email services that deliver alerts, Lettermint, or Scaleway if Lettermint fails (both EU email services), then see it with every alert.',
    );
    expect(ENROLLED_ADDRESS_NOTE).not.toMatch(/never leaves this browser/);
    expect(CONSENT_VERSION).toBe(3);
    expect(CONSENT_TEXT).toContain('Alert emails are sent through Lettermint, or Scaleway if Lettermint fails (both EU email services), which see this address and each alert.');
    expect(CONSENT_TEXT).toContain('About once a month this device asks you to tap a notification');
    expect(CONSENT_TEXT).not.toMatch(/once a week|quiet notification/);
  });
});

describe('the key path', () => {
  const path = (root: bigint) => ({ index: 1, siblings: [], root });
  it('prefers a live pin that holds the key, else an accepted registry root', () => {
    // The pin's expiry is a close time in seconds.
    const T = 1_793_500_000;
    expect(chooseKeyPath({ now: T, pin: { root: 5n, validUntil: T, path: path(5n) } })).toMatchObject({ kind: 'pin', root: 5n });
    expect(
      chooseKeyPath({ now: T + 1, pin: { root: 5n, validUntil: T, path: path(5n) }, registry: { root: 6n, accepted: true, path: path(6n) } }),
    ).toMatchObject({ kind: 'registry', root: 6n });
    expect(chooseKeyPath({ now: T + 1, pin: { root: 5n, validUntil: T, path: path(5n) } })).toMatchObject({ kind: 'none', why: /pin has expired/ });
    expect(chooseKeyPath({ now: T, registry: { root: 6n, accepted: false, path: path(6n) } })).toMatchObject({ kind: 'none' });
    // A pin path that does not open to the guardian's pin root is no path.
    expect(chooseKeyPath({ now: T, pin: { root: 5n, validUntil: T, path: path(7n) } })).toMatchObject({ kind: 'none' });
  });
});

describe('progress and what remains', () => {
  it('stage copy, clock, and the code as alerts print it', () => {
    expect(stageText('download', { loaded: 2e6, total: 18.8e6, cached: false })).toBe('Downloading the prover (2.0 of 18.8 MB)…');
    expect(stageText('download', { loaded: 1, total: 1, cached: true })).toMatch(/from this browser/);
    expect(stageText('proving', {})).toMatch(/two minutes on a phone/);
    expect(clock(65_400)).toBe('1:05');
    expect(spacedCode('169328')).toBe('169 328');
  });

  it('remaining factors after the email vote', () => {
    const base = { guardians: ['E', 'F', 'G'], emailGuardian: 'E', zkNeeded: false, zkRecorded: false };
    expect(remainingFactors({ ...base, quorum: 2, approvals: [] })).toMatchObject({ emailApproved: false, othersNeeded: 1 });
    expect(remainingFactors({ ...base, quorum: 2, approvals: ['E'] })).toMatchObject({ emailApproved: true, othersNeeded: 1 });
    expect(remainingFactors({ ...base, quorum: 2, approvals: ['E', 'F'] }).text).toMatch(/Nothing else is needed/);
    expect(remainingFactors({ ...base, quorum: 1, approvals: ['E'], zkNeeded: true }).text).toMatch(/recovery kit still needs/);
  });

  it('the delay counts down from the ledger read', () => {
    expect(delayCountdown(130, 100, 0, 0).remainingMs).toBe(150_000);
    expect(delayCountdown(130, 100, 0, 60_000).remainingMs).toBe(90_000);
    expect(delayCountdown(130, 100, 0, 200_000)).toEqual({ remainingMs: 0, text: 'The waiting period is over.' });
  });

  it('enrollment steps run in order', () => {
    expect(nextEnrollStep({})).toBe('code');
    expect(nextEnrollStep({ code: true, email: true })).toBe('check');
    expect(nextEnrollStep({ code: true, email: true, check: true, alerts: true, deploy: true, apply: true })).toBe('done');
  });
});

describe('the email guardian on chain', () => {
  const cfg = {
    account: contract(1),
    controller: contract(2),
    commitment: new Uint8Array(32).fill(3),
    registry: contract(4),
    keyPin: [{ root: new Uint8Array(32).fill(5), validUntil: 1_796_092_000 }],
    allowedActions: 31,
    verifier: contract(6),
    circuitId: new Uint8Array(32).fill(7),
  };

  it('GuardianConfig is the contract type: a map of its fields in sorted order', () => {
    const v = guardianConfigScVal(cfg);
    const keys = v.map()!.map((e) => e.key().sym().toString());
    expect(keys).toEqual(['account', 'allowed_actions', 'circuit_id', 'commitment', 'controller', 'key_pin', 'registry', 'verifier']);
    const pin = v.map()![5]!.val().vec()![0]!;
    expect(pin.map()!.map((e) => e.key().sym().toString())).toEqual(['root', 'valid_until']);
    expect(pin.map()![1]!.val().u64().toBigInt()).toBe(1_796_092_000n);
    // Round trip through the XDR and the native form `config()` returns.
    const back = xdr.ScVal.fromXDR(v.toXDR());
    expect(back.toXDR('base64')).toBe(v.toXDR('base64'));
  });

  it('the approval entry authorizes exactly (digest,) on the controller’s submit_guardian', () => {
    const approval = { statement: new Uint8Array([1, 2, 3]), keyRoot: new Uint8Array(32).fill(9), proof: new Uint8Array(16_224) };
    const sig = emailApprovalScVal(approval);
    expect(sig.map()!.map((e) => e.key().sym().toString())).toEqual(['key_root', 'proof', 'statement']);
    const entry = emailApprovalEntry({
      guardian: contract(8),
      controller: contract(2),
      fnName: 'submit_guardian',
      digest: new Uint8Array(32).fill(4),
      approval,
      nonce: 42n,
      expirationLedger: 1_000,
    });
    const creds = entry.credentials().address();
    expect(Address.fromScAddress(creds.address()).toString()).toBe(contract(8));
    expect(creds.nonce().toString()).toBe('42');
    const fn = entry.rootInvocation().function().contractFn();
    expect(Address.fromScAddress(fn.contractAddress()).toString()).toBe(contract(2));
    expect(fn.functionName().toString()).toBe('submit_guardian');
    expect(fn.args().map((a) => Buffer.from(a.bytes()).toString('hex'))).toEqual(['04'.repeat(32)]);
    expect(entry.rootInvocation().subInvocations()).toEqual([]);
    const op = submitGuardianOperation({ controller: contract(2), account: contract(1), attemptId: 3n, domain: 0, guardian: contract(8), entry });
    const args = op.body().invokeHostFunctionOp().hostFunction().invokeContract().args();
    expect(args.map((a) => a.switch().name)).toEqual(['scvAddress', 'scvU64', 'scvU32', 'scvAddress']);
    expect(op.body().invokeHostFunctionOp().auth()).toHaveLength(1);
  });

  it('config() reads back into the same configuration', () => {
    const native = {
      account: cfg.account,
      controller: cfg.controller,
      commitment: cfg.commitment,
      registry: cfg.registry,
      key_pin: [{ root: cfg.keyPin[0]!.root, valid_until: 1_796_092_000n }],
      allowed_actions: 31,
      verifier: cfg.verifier,
      circuit_id: cfg.circuitId,
    };
    expect(guardianConfigFromNative(native)).toEqual(cfg);
  });

  it('the deployed address is the CAP-46 derivation of deployer and salt', () => {
    const deployer = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 9));
    const salt = new Uint8Array(32).fill(1);
    const a = deployedAddress(deployer, salt, 'Test SDF Network ; September 2015');
    expect(a).toMatch(/^C[A-Z2-7]{55}$/);
    expect(deployedAddress(deployer, salt, 'Standalone Network ; February 2017')).not.toBe(a);
    expect(deployedAddress(deployer, new Uint8Array(32).fill(2), 'Test SDF Network ; September 2015')).not.toBe(a);
  });
});

describe('the email recovery deployment', () => {
  const ok = {
    guardianWasmHash: 'ab'.repeat(32),
    registry: contract(1),
    verifier: contract(2),
    circuitId: EMAIL_CIRCUIT_ID,
    recoveryInbox: 'recover@recovery.test',
    alertService: 'https://alerts.test',
    keyList: '/dkim-keys.json',
    enclaveImageRegistry: contract(3),
    attestationRoots: ['AAAA'],
  };
  it('is checked before use', () => {
    expect(parseEmailRecoveryDeployment(ok)).toEqual(ok);
    expect(() => parseEmailRecoveryDeployment({ ...ok, circuitId: 'cd'.repeat(32) })).toThrow(/another circuit/);
    expect(() => parseEmailRecoveryDeployment({ ...ok, registry: 'G' })).toThrow(/registry/);
    expect(() => parseEmailRecoveryDeployment({ ...ok, attestationRoots: [] })).toThrow(/attestationRoots/);
  });
});

describe('phishing and the recovery code', () => {
  const account = contract(7);
  it('the code entry says nobody asks for it and how to check the origin against the kit', () => {
    const apex = walletApex('mainnet');
    const w = codeEntryWarning(account, apex);
    expect(w).toMatch(/^Nobody from Nido will ask for this code/);
    // The whole recovery page address, built from the build's apex, never from the page's own host.
    expect(w).toContain(`it must show exactly https://${account.toLowerCase()}.nido.fyi/security/recover/, the Recovery page line of your recovery kit`);
    expect(w).toContain('every Nido page ends in .nido.fyi');
    expect(PASSKEY_DEVICE_CANCEL).toBe('This device has your passkey, so you do not need a recovery. Cancel it unless you are deliberately replacing this passkey.');
  });

  it('the apex is a constant of the network; only a local-network build takes the host it runs on', () => {
    expect(walletApex('mainnet', { scheme: 'http:', host: 'evil.example' })).toEqual({ scheme: 'https:', host: 'nido.fyi' });
    expect(walletApex('testnet')).toEqual({ scheme: 'https:', host: 'test.nido.fyi' });
    expect(walletApex('testnet', { scheme: 'http:', host: 'localhost:4399' })).toEqual({ scheme: 'http:', host: 'localhost:4399' });
    expect(recoveryPageUrl(account, walletApex('testnet'))).toBe(`https://${account.toLowerCase()}.test.nido.fyi/security/recover/`);
  });

  it('enrollment warns, without blocking, when alerts would go to the enrolled inbox', () => {
    expect(alertAddressWarning(' Ada.Lovelace@proton.me ', 'ada.lovelace@proton.me')).toMatch(/can delete the alerts sent to it/);
    expect(alertAddressWarning('ada@posteo.de', 'ada.lovelace@proton.me')).toBeUndefined();
    expect(alertAddressWarning('', 'ada.lovelace@proton.me')).toBeUndefined();
  });

  it('enrollment asks for two distinct groups of the kit back, and only they pass', () => {
    const kit = 'ABCD EFGH IJKL MNOP QRST UVWX YZ';
    for (const r of [0, 0.3, 0.5, 0.99]) {
      const [a, b] = kitCheckGroups(() => r);
      expect(a).toBeLessThan(b);
      expect(b).toBeLessThan(7);
    }
    expect(kitCheckMatches(kit, [1, 6], ['efgh', ' Y Z '])).toBe(true);
    expect(kitCheckMatches(kit, [1, 6], ['EFGH', 'YX'])).toBe(false);
    expect(kitCheckMatches(kit, [1, 6], ['EFGH'])).toBe(false);
  });

  it('the kit names its Nido and where recovery starts, and advises keeping it away from the inbox’s account', () => {
    const text = recoveryKitText({ kit: 'ABCD EFGH', account, apex: walletApex('mainnet') });
    expect(text).toContain('Recovery code: ABCD EFGH');
    expect(text).toContain(`Nido: ${account}`);
    expect(text).toContain(`Recovery page: https://${account.toLowerCase()}.nido.fyi/security/recover/`);
    expect(text).toContain("Nido's address: https://nido.fyi (every Nido page ends in .nido.fyi)");
    expect(text).toContain('check that the address bar shows exactly');
    expect(text).toContain(KIT_STORAGE_ADVICE);
    expect(KIT_STORAGE_ADVICE).toMatch(/Google Password Manager/);
  });

  it('on an iPhone or iPad the kit is printed first, and the page names where a download goes', () => {
    const iphone = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
    expect(kitActions(iphone)).toEqual({ primary: 'print', note: expect.stringMatching(/saves the kit to iCloud Drive \(Files\) unless you changed Safari’s download location/) });
    expect(kitActions('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36')).toEqual({ primary: 'download' });
  });

  it('enrollment notes when the inbox is at the platform that likely syncs this passkey', () => {
    const android = 'Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36';
    const iphone = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
    const firefox = 'Mozilla/5.0 (Windows NT 10.0; rv:133.0) Gecko/20100101 Firefox/133.0';
    expect(syncedPasskeyNote('gmail.com', android)).toMatch(/^The passkey on this device is probably saved in your Google account \(Google Password Manager\)/);
    expect(syncedPasskeyNote('GMail.com', android)).toMatch(/Use an inbox at another provider, or add another helper\.$/);
    expect(syncedPasskeyNote('icloud.com', iphone)).toMatch(/your Apple account \(iCloud Keychain\)/);
    expect(syncedPasskeyNote('me.com', iphone)).toBeDefined();
    expect(syncedPasskeyNote('gmail.com', iphone)).toBeUndefined();
    expect(syncedPasskeyNote('icloud.com', android)).toBeUndefined();
    expect(syncedPasskeyNote('proton.me', android)).toBeUndefined();
    expect(syncedPasskeyNote('gmail.com', firefox)).toBeUndefined();
  });

  it('the apex recovery page starts from the Nido address in a kit, its URL, or a name', () => {
    expect(accountFromKitInput(`  Nido: ${account}  `)).toEqual({ account });
    expect(accountFromKitInput(`https://${account.toLowerCase()}.nido.test/security/recover/`)).toEqual({ account });
    expect(accountFromKitInput('alice')).toEqual({ name: 'alice' });
    expect(accountFromKitInput('https://alice.nido.fyi/')).toEqual({ name: 'alice' });
    expect(accountFromKitInput(account.slice(0, -1) + (account.endsWith('A') ? 'B' : 'A'))).toBeUndefined();
    expect(accountFromKitInput('not an address!')).toBeUndefined();
  });

  it('the sealed inbound deadline is shown, and its end offers a new email', () => {
    const now = Date.UTC(2026, 10, 1, 12);
    const open = inboundDeadline(now + 23 * 3600_000 + 5 * 60_000, now);
    expect(open.expired).toBe(false);
    expect(open.text).toContain('(23 h 5 min left)');
    const over = inboundDeadline(now - 1, now);
    expect(over).toEqual({ expired: true, text: expect.stringMatching(/Get a new email to send/) });
  });
});

describe('the second alert channel at runtime (rule 2)', () => {
  const now = Date.UTC(2026, 10, 2);
  const date = (ms: number) => new Date(ms).toISOString().slice(0, 10);
  const dev = (id: string, state: 'live' | 'unacknowledged' | 'lapsed', addedAt = now - 90 * 86_400_000) => ({ id, state, addedAt, ackedAt: now - 86_400_000 });

  it('"they reach this device" only on the device the vault lists as live, or that confirmed recently', () => {
    expect(channelView({ vault: [dev('aa', 'live')], device: { state: 'live', id: 'aa' }, now, date })).toEqual({
      state: 'here',
      rule2: 'ok',
      offerAdd: false,
      text: 'Alert notifications: they reach this device (last confirmed 2026-11-01).',
    });
    expect(channelView({ device: { state: 'live', id: 'aa', ackedAt: now - 3_600_000 }, now, date }).state).toBe('here');
    const stale = channelView({ device: { state: 'live', id: 'aa', ackedAt: now - RECENT_ACK_MS - 1 }, now, date });
    expect(stale).toMatchObject({ state: 'unknown', rule2: 'ok', offerAdd: false });
    expect(stale.text).toMatch(/needs your passkey/);
  });

  it('on another device than the one subscribed, it says where notifications go and offers this device', () => {
    const v = channelView({ vault: [dev('aa', 'live', Date.UTC(2026, 5, 3))], now, date });
    expect(v).toEqual({ state: 'elsewhere', rule2: 'ok', offerAdd: true, text: 'Recovery notifications go to another device (set up on 2026-06-03). Add this device too.' });
    expect(channelView({ vault: [dev('aa', 'live')], device: { state: 'live', id: 'bb' }, now, date }).state).toBe('elsewhere');
    expect(channelView({ now, date })).toMatchObject({ state: 'unknown', offerAdd: true, text: expect.stringMatching(/does not receive them/) });
  });

  it('unacknowledged and lapsed devices break rule 2, as a lost subscription on this device does', () => {
    expect(channelView({ vault: [dev('aa', 'unacknowledged')], device: { state: 'live', id: 'aa' }, now, date })).toEqual({ state: 'unacknowledged', rule2: 'broken', offerAdd: true, text: SECOND_CHANNEL_UNACKNOWLEDGED });
    expect(channelView({ vault: [dev('aa', 'lapsed')], now, date })).toMatchObject({ state: 'lapsed', rule2: 'broken' });
    expect(channelView({ vault: [], now, date })).toMatchObject({ state: 'lapsed', rule2: 'broken' });
    expect(channelView({ device: { state: 'gone', id: 'aa' }, now, date })).toMatchObject({ state: 'lapsed', rule2: 'broken', offerAdd: true });
    // One live device keeps rule 2, whatever the others.
    expect(channelView({ vault: [dev('aa', 'unacknowledged'), dev('bb', 'live')], device: { state: 'live', id: 'bb' }, now, date }).state).toBe('here');
    expect(SECOND_CHANNEL_LAPSED).toMatch(/rule 2/);
    expect(SECOND_CHANNEL_UNACKNOWLEDGED).toMatch(/rule 2/);
  });
});

describe('checking a recovery code against the pin', () => {
  it('matches only the code whose salted leaf, with a known key, rebuilds the pin root', async () => {
    await initHashes();
    const { pinTree } = await import('@nidohq/email-recovery');
    const keys = [
      { domain: 'gmail.com', modulus: (1n << 2047n) + 12345n },
      { domain: 'proton.me', modulus: (1n << 2047n) + 999n },
    ];
    const root = (code: bigint, k: { domain: string; modulus: bigint }) => pinTree(code, [k]).root;
    const pinRoot = root(42n, keys[1]!);
    expect(checkCodeAgainstPin({ accountCode: 42n, pinRoot, keys, root })).toBe('match');
    expect(checkCodeAgainstPin({ accountCode: 43n, pinRoot, keys, root })).toBe('mismatch');
    expect(checkCodeAgainstPin({ accountCode: 42n, pinRoot, keys: [keys[0]!], root })).toBe('mismatch');
    expect(checkCodeAgainstPin({ accountCode: 42n, pinRoot: undefined, keys, root })).toBe('no-pin');
    expect(codeCheckText('mismatch')).toMatch(/set up email recovery again now/);
  });
});

describe('the key pin the wallet deploys', () => {
  it('lasts 30 days of close time: past the registry 7-day timelock, within the guardian 365-day cap', () => {
    expect(PIN_LIFETIME_SECONDS).toBe(30 * 86_400);
    expect(pinValidUntil(1_793_500_000)).toBe(1_793_500_000 + 2_592_000);
    expect(PIN_LIFETIME_SECONDS).toBeGreaterThan(7 * 86_400);
    expect(PIN_LIFETIME_SECONDS).toBeLessThanOrEqual(365 * 86_400);
  });
});
