// The recovery settings page with an email helper: rule 2 of
// docs/email-recovery/spec.md §9.3 at runtime. Once no device is known to
// receive and confirm the helper's alert notifications (lapsed, or
// unacknowledged), the page says what still holds on chain: the helper still
// approves, alone under email plus delay. It offers this device and, under
// email plus delay, another helper; it refuses a save in which the email vote
// alone authorizes, and accepts one that needs another approval as well.
// While the notifications work, a save keeps the helper under the wallet's
// email rules. On a device without the subscription it says where
// notifications go and adds this device at once.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { StrKey } from '@stellar/stellar-sdk';
import { buildPolicyDoc, perch, type PolicyDoc } from '@nidohq/passkey-sdk';

const contract = (n: number) => StrKey.encodeContract(Buffer.alloc(32, n));
const NETWORK = 'Test SDF Network ; September 2015';
const ACCOUNT = contract(30);
const KEY = '04' + 'ab'.repeat(64);
const EMAIL = contract(40);
const HELPER = contract(41);

const deployment: perch.PerchDeployment = {
  network: NETWORK,
  factory: contract(1),
  webauthnVerifier: contract(2),
  statelessRegistry: contract(3),
  docCompiler: contract(4),
  interpreter: contract(5),
  spendingLimit: contract(6),
  recoveryController: contract(7),
  zkPool: contract(8),
  zkAdapter: contract(9),
  circuitId: 'c1'.repeat(32),
  treeDepth: 32,
  accountWasmHash: 'aa'.repeat(32),
};

type Device = { state: 'gone' | 'live'; id: string; ackedAt?: number } | undefined;
const page = vi.hoisted(() => ({ state: undefined as unknown, device: undefined as Device, channels: [] as unknown[] }));

vi.mock('./chain.js', () => ({
  readRecoveryState: vi.fn(async () => page.state),
  recoveryClient: () => ({}),
  applyDoc: vi.fn(async () => 'hash'),
  currentOrFirstDoc: vi.fn(),
  latestLedger: vi.fn(async () => 100),
  // testnet's and mainnet's target ledger close time
  targetCloseMs: vi.fn(async () => 5_000),
  submitOpen: vi.fn(async () => ({ hash: 'h' })),
}));
vi.mock('./deployment.js', () => ({ perchDeployment: () => deployment, requireDeployment: () => deployment }));
vi.mock('./emailConfig.js', () => ({ emailRecoveryDeployment: () => ({ guardianWasmHash: 'ab'.repeat(32) }) }));
vi.mock('./emailRecovery.js', () => ({
  findEmailGuardian: vi.fn(async () => ({ address: EMAIL, config: { allowedActions: 31, keyPin: [] } })),
  keyList: vi.fn(),
  vaultKey: vi.fn(),
}));
vi.mock('./emailAlerts.js', () => ({
  deviceChannel: vi.fn(async () => page.device),
  alertChannels: vi.fn(async () => page.channels),
  addThisDevice: vi.fn(async () => {
    page.device = { state: 'live', id: 'cc' };
  }),
  homeScreenStep: vi.fn(() => undefined),
}));
vi.mock('./liveAttempts.js', () => ({ liveAttemptsSection: vi.fn(async () => undefined) }));
vi.mock('./ui.js', async (orig) => ({ ...(await orig<typeof import('./ui.js')>()), collectCondition: vi.fn() }));
vi.mock('./zk.js', () => ({ newRecoveryKit: vi.fn(), kitFile: vi.fn(), proveWithKit: vi.fn() }));
vi.mock('../toast.js', () => ({ toast: vi.fn() }));
vi.mock('../recoveryBackupPrompt.js', () => ({ markBackupSetUp: vi.fn() }));

import { applyDoc } from './chain.js';
import { addThisDevice, homeScreenStep } from './emailAlerts.js';
import { rememberCodeChecked } from './emailBackup';
import { mountRecoverySettings } from './settingsPage';
import { summarizeRecovery } from './model';

function enrolled(quorum = 2): PolicyDoc {
  const doc = buildPolicyDoc({
    network: NETWORK,
    signers: [{ id: 'admin', kind: 'passkey', verifier: deployment.webauthnVerifier, publicKey: KEY }],
    permissions: [{ name: 'admin', on: 'self-admin', by: ['admin'] }],
  });
  return perch.withRecovery(
    doc,
    perch.recoverySpec(deployment, {
      profile: 'loss',
      mode: 'guardian-only',
      guardians: quorum === 1 ? [{ kind: 'email', address: EMAIL, allowedActions: 31 }] : [{ kind: 'email', address: EMAIL, allowedActions: 31 }, HELPER],
      quorum,
      secondAlertChannel: 'web-push',
      replaceable: ['admin'],
      ledgerCloseMs: 5_000,
    }),
  );
}

async function mount(quorum = 2): Promise<HTMLElement> {
  const doc = enrolled(quorum);
  page.state = {
    doc,
    revision: 6n,
    summary: summarizeRecovery(doc),
    wiring: { controller: doc.recovery!.controller, adopted: true },
    gate: { authorized_attempt: undefined, frozen: false },
    epoch: 2n,
  };
  const root = document.createElement('div');
  await mountRecoverySettings(root, ACCOUNT);
  return root;
}

const save = (root: HTMLElement) => [...root.querySelectorAll('button')].find((b) => /Save recovery settings/.test(b.textContent!))!.click();

beforeEach(() => {
  vi.clearAllMocks();
  URL.createObjectURL = vi.fn(() => 'blob:kit');
});

const click = (root: HTMLElement, sel: string) => root.querySelector<HTMLButtonElement>(sel)!.click();
const device = (id: string, state: string, addedAt = Date.UTC(2026, 5, 3)) => ({ id, state, addedAt, ackedAt: Date.now() });

const field = (root: HTMLElement, name: string) => root.querySelector<HTMLInputElement>(`[name="${name}"]`)!;

describe('rule 2 at runtime', () => {
  it('a lapsed channel under email plus delay: the helper still approves alone; the page offers this device or another helper, and refuses a save that keeps email alone', async () => {
    page.device = { state: 'gone', id: 'aa' };
    const root = await mount(1);
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>('[data-channel-lapsed]')!.hidden).toBe(false));
    expect(root.querySelector('[data-channel-lapsed]')!.textContent).toMatch(
      /^Your email helper can still approve a recovery alone, and your second alert channel is not working: fix the channel now, or add another helper\. /,
    );
    expect(root.querySelector('[data-channel-lapsed]')!.textContent).not.toMatch(/not allowed/);
    expect(root.querySelector<HTMLElement>('[data-add-device]')!.hidden).toBe(false);
    expect(root.querySelector<HTMLElement>('[data-add-helper]')!.hidden).toBe(false);
    save(root);
    await vi.waitFor(() => expect(root.textContent).toMatch(/will not save settings in which your email helper can approve a recovery alone \(rule 2\)/));
    expect(applyDoc).not.toHaveBeenCalled();
  });

  it('"Add another helper" sets up a save that needs a second approval, which goes through while the channel is broken', async () => {
    page.device = { state: 'gone', id: 'aa' };
    const root = await mount(1);
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>('[data-add-helper]')!.hidden).toBe(false));
    click(root, '[data-add-helper]');
    expect(field(root, 'quorum').value).toBe('2');
    expect(root.querySelector('[data-add-helper-hint]')!.textContent).toMatch(/their approval as well as your email’s/);
    field(root, 'guardians').value = `${EMAIL}\n${HELPER}`;
    save(root);
    await vi.waitFor(() => expect(applyDoc).toHaveBeenCalled());
    const mode = (vi.mocked(applyDoc).mock.calls[0]![1] as PolicyDoc).recovery as { mode: { guardians: string[]; quorum: number } };
    expect(mode.mode.guardians).toEqual(expect.arrayContaining([EMAIL, HELPER]));
    expect(mode.mode.quorum).toBe(2);
  });

  it('a device that confirmed no probe for two intervals breaks rule 2 like a lapsed one; with another helper needed, the email helper still counts', async () => {
    page.device = { state: 'live', id: 'aa' };
    page.channels = [{ contact: '00'.repeat(16), state: 'active', push: 'unacknowledged', devices: [device('aa', 'unacknowledged')] }];
    const root = await mount();
    click(root, '[data-check-channels]');
    await vi.waitFor(() => expect(root.querySelector('[data-channel-lapsed]')!.textContent).toMatch(/could not confirm that your recovery notifications reach you/));
    expect(root.querySelector('[data-channel-lapsed]')!.textContent).toMatch(/Your email helper still counts as one approval, and you would hear of its approvals only by email \(rule 2\)\.$/);
    expect(root.querySelector<HTMLElement>('[data-add-helper]')!.hidden).toBe(true);
    field(root, 'quorum').value = '1';
    save(root);
    await vi.waitFor(() => expect(root.textContent).toMatch(/\(rule 2\)\. Add this device/));
    expect(applyDoc).not.toHaveBeenCalled();
  });

  it('on a device without the subscription it says where notifications go, and adds this device at once', async () => {
    page.device = undefined;
    page.channels = [{ contact: '11'.repeat(16), state: 'active', push: 'live', devices: [device('aa', 'live')] }];
    const root = await mount();
    await vi.waitFor(() => expect(root.querySelector('[data-channel-state]')!.textContent).toMatch(/this device does not receive them/));
    expect(root.querySelector('[data-channel-state]')!.textContent).not.toMatch(/reach your device|reach this device/);
    click(root, '[data-check-channels]');
    await vi.waitFor(() => expect(root.querySelector('[data-channel-state]')!.textContent).toMatch(/^Recovery notifications go to another device \(set up on .+\)\. Add this device too\.$/));
    click(root, '[data-add-device]');
    await vi.waitFor(() => expect(root.querySelector('[data-channel-state]')!.textContent).toMatch(/they reach this device/));
    expect(vi.mocked(addThisDevice).mock.calls[0]![1]).toBe('11'.repeat(16));
    expect(root.querySelector<HTMLElement>('[data-add-device]')!.hidden).toBe(true);
  });

  it('on an iPhone outside its Home Screen app, "Add this device" says what to install first and asks for nothing', async () => {
    page.device = { state: 'gone', id: 'aa' };
    vi.mocked(homeScreenStep).mockReturnValue('On an iPhone or iPad, notifications reach only Nido opened from your Home Screen.');
    const root = await mount();
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>('[data-add-device]')!.hidden).toBe(false));
    click(root, '[data-add-device]');
    await vi.waitFor(() => expect(root.textContent).toMatch(/notifications reach only Nido opened from your Home Screen/));
    expect(addThisDevice).not.toHaveBeenCalled();
    vi.mocked(homeScreenStep).mockReturnValue(undefined);
  });

  it('opens the recovery-code check with a reminder until the code was checked on this device within six months', async () => {
    localStorage.clear();
    page.device = { state: 'live', id: 'aa' };
    let root = await mount();
    await vi.waitFor(() => expect(root.querySelector('[data-code-check-due]')).not.toBeNull());
    expect(root.querySelector<HTMLDetailsElement>('[data-code-check]')!.open).toBe(true);
    expect(root.querySelector('[data-code-check-due]')!.textContent).toMatch(/^You have not checked your recovery code on this device yet\./);
    rememberCodeChecked(ACCOUNT, Date.now() - 30 * 86_400_000);
    root = await mount();
    expect(root.querySelector('[data-code-check-due]')).toBeNull();
    expect(root.querySelector<HTMLDetailsElement>('[data-code-check]')!.open).toBe(false);
  });

  it('with the channel not known to have lapsed, a save keeps the email helper under the wallet rules', async () => {
    page.device = { state: 'live', id: 'aa' };
    const root = await mount();
    await vi.waitFor(() => expect(root.querySelector('[data-channel-state]')!.textContent).toMatch(/needs your passkey/));
    save(root);
    await vi.waitFor(() => expect(applyDoc).toHaveBeenCalled());
    const next = vi.mocked(applyDoc).mock.calls[0]![1] as PolicyDoc;
    expect((next.recovery as { mode: { guardians: string[] } }).mode.guardians).toContain(EMAIL);
  });
});
