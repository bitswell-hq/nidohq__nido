// The settings page's move of recovery from an earlier controller to the
// deployment's: every setting kept, the switch approved (under Protected) at
// the controller being left, and the published baseline carried over, even
// when its publication fails or the page reloads before it lands.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { StrKey } from '@stellar/stellar-sdk';
import { buildPolicyDoc, docHash, parsePolicyDocJson, perch, type PolicyDoc } from '@nidohq/passkey-sdk';

const contract = (n: number) => StrKey.encodeContract(Buffer.alloc(32, n));
const NETWORK = 'Test SDF Network ; September 2015';
const ACCOUNT = contract(30);
const KEY = '04' + 'ab'.repeat(64);
const BASELINE = '{"restore":"point"}';

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
/** The stack the account enrolled with, before the redeploy. */
const EARLIER = { ...deployment, recoveryController: contract(50), zkPool: contract(51), zkAdapter: contract(52) };

/** The chain as the page sees it: the controller the account adopted, and
 *  the baseline each controller holds. */
const page = vi.hoisted(() => ({
  state: undefined as unknown,
  events: [] as string[],
  controller: '',
  published: new Map<string, string>(),
  failPublications: 0,
}));
const client = {
  baseline: vi.fn(async () => {
    page.events.push('baseline read');
    return page.published.get(page.controller);
  }),
  publishBaseline: vi.fn(async (_account: string, json: string) => ({
    operations: [{ __op: 'publish_baseline', controller: page.controller, json }],
  })),
};

vi.mock('./chain.js', () => ({
  readRecoveryState: vi.fn(async () => page.state),
  recoveryClient: () => client,
  applyDoc: vi.fn(async (_account: string, doc: PolicyDoc) => {
    page.events.push('applied');
    page.controller = doc.recovery!.controller;
    return 'hash';
  }),
  currentOrFirstDoc: vi.fn(),
  latestLedger: vi.fn(async () => 100),
  submitAsOwner: vi.fn(),
  submitOpen: vi.fn(async (op: { __op: string; controller: string; json: string }) => {
    if (op.__op === 'publish_baseline') {
      if (page.failPublications > 0) {
        page.failPublications--;
        throw new Error('The network is unreachable.');
      }
      page.published.set(op.controller, op.json);
      page.events.push('baseline published');
    }
    return { hash: 'h' };
  }),
}));
vi.mock('./deployment.js', () => ({
  perchDeployment: () => deployment,
  requireDeployment: () => deployment,
}));
vi.mock('./ui.js', async (orig) => ({
  ...(await orig<typeof import('./ui.js')>()),
  collectCondition: vi.fn(async () => {
    page.events.push('approved');
    return 777;
  }),
}));
const NEW_KIT = { enrollmentId: new Uint8Array(32).fill(0x0e), commitment: new Uint8Array(32).fill(0x0f) };
vi.mock('./zk.js', () => ({
  newRecoveryKit: vi.fn(async () => ({ kit: { account: ACCOUNT }, enrollment: NEW_KIT })),
  kitFile: vi.fn(() => new Blob(['kit'])),
  proveWithKit: vi.fn(),
}));
vi.mock('../toast.js', () => ({ toast: vi.fn() }));
vi.mock('../recoveryBackupPrompt.js', () => ({ markBackupSetUp: vi.fn() }));

import { applyDoc, submitOpen } from './chain.js';
import { collectCondition } from './ui.js';
import { mountRecoverySettings } from './settingsPage';
import { summarizeRecovery } from './model';

const GUARDIANS = [contract(20), contract(21), contract(22)];

function enrolled(on: perch.PerchDeployment, choice: Partial<perch.RecoveryChoice>): PolicyDoc {
  const doc = buildPolicyDoc({
    network: NETWORK,
    signers: [{ id: 'admin', kind: 'passkey', verifier: deployment.webauthnVerifier, publicKey: KEY }],
    permissions: [{ name: 'admin', on: 'self-admin', by: ['admin'] }],
  });
  return perch.withRecovery(
    doc,
    perch.recoverySpec(on, {
      profile: 'loss',
      mode: 'guardian-only',
      guardians: GUARDIANS,
      quorum: 2,
      replaceable: ['admin'],
      baselineDocHash: 'ef'.repeat(32),
      ...choice,
    }),
  );
}

function at(doc: PolicyDoc, gate: Partial<perch.ActivityGate> = {}) {
  page.controller = doc.recovery!.controller;
  page.state = {
    doc,
    revision: 6n,
    summary: summarizeRecovery(doc),
    wiring: { controller: doc.recovery!.controller, adopted: true },
    gate: { authorized_attempt: undefined, frozen: false, ...gate },
    epoch: 2n,
  };
}

async function mount(): Promise<HTMLElement> {
  const root = document.createElement('div');
  await mountRecoverySettings(root, ACCOUNT);
  return root;
}

const button = (root: HTMLElement, label: RegExp) =>
  [...root.querySelectorAll('button')].find((b) => label.test(b.textContent!))!;
const moved = () => vi.mocked(applyDoc).mock.calls[0]![1] as PolicyDoc;
/** `begin_compromise` refuses with `BaselineNotPublished` until the
 *  controller the account adopted holds its baseline. */
const compromiseCanOpen = () => page.published.has(page.controller);
const savedInBrowser = () => Object.keys(localStorage).some((k) => k.includes(`recovery:baseline:${ACCOUNT}`));

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  page.events = [];
  page.published = new Map([[EARLIER.recoveryController, BASELINE]]);
  page.failPublications = 0;
  URL.createObjectURL = vi.fn(() => 'blob:kit');
});

describe('settings page: moving recovery to the current controller', () => {
  it('offers nothing to move on the deployment’s stack', async () => {
    at(enrolled(deployment, {}));
    const root = await mount();
    expect(root.textContent).not.toMatch(/Move recovery/);
  });

  it('offers no move while an attempt is authorized', async () => {
    at(enrolled(EARLIER, {}), { authorized_attempt: 3n });
    const root = await mount();
    expect(root.textContent).toMatch(/A recovery is under way/);
    expect(root.textContent).not.toMatch(/Move recovery/);
  });

  it('moves a Loss configuration with the owner alone, keeping its settings and restore point', async () => {
    const doc = enrolled(EARLIER, {});
    at(doc);
    const root = await mount();
    expect(root.textContent).toContain(EARLIER.recoveryController);
    button(root, /Move my recovery/).click();
    await vi.waitFor(() => expect(submitOpen).toHaveBeenCalled());

    expect(collectCondition).not.toHaveBeenCalled();
    expect(vi.mocked(applyDoc).mock.calls[0]![2]).toEqual({ baseRevision: 6n, approvalValidUntil: 0 });
    const { controller, ...kept } = moved().recovery!;
    expect(controller).toBe(deployment.recoveryController);
    const { controller: _was, ...before } = doc.recovery!;
    expect(kept).toEqual(before);
    // The restore point is read where it was published, before the switch,
    // and published again at the new controller after it.
    expect(page.events).toEqual(['baseline read', 'applied', 'baseline read', 'baseline published']);
    expect(client.publishBaseline).toHaveBeenCalledWith(ACCOUNT, BASELINE);
    expect(page.published.get(deployment.recoveryController)).toBe(BASELINE);
    expect(compromiseCanOpen()).toBe(true);
    expect(savedInBrowser()).toBe(false);
  });

  it('keeps the restore point when its publication fails after the move, and publishes it on retry', async () => {
    at(enrolled(EARLIER, {}));
    page.failPublications = 1;
    const root = await mount();
    button(root, /Move my recovery/).click();
    await vi.waitFor(() => expect(root.textContent).toMatch(/The network is unreachable/));

    expect(page.controller).toBe(deployment.recoveryController);
    expect(compromiseCanOpen()).toBe(false);
    expect(savedInBrowser()).toBe(true);

    const retry = button(root, /Try again/);
    expect(retry.hidden).toBe(false);
    retry.click();
    await vi.waitFor(() => expect(root.textContent).toMatch(/Restore point saved/));
    expect(page.published.get(deployment.recoveryController)).toBe(BASELINE);
    expect(compromiseCanOpen()).toBe(true);
    expect(savedInBrowser()).toBe(false);
  });

  it('resumes publishing the restore point after a reload', async () => {
    at(enrolled(EARLIER, {}));
    page.failPublications = 1;
    const first = await mount();
    button(first, /Move my recovery/).click();
    await vi.waitFor(() => expect(first.textContent).toMatch(/The network is unreachable/));

    // The page reloads onto the moved document; nothing is left to move.
    at(moved());
    const root = await mount();
    expect(root.textContent).not.toMatch(/Move recovery/);
    await vi.waitFor(() => expect(root.textContent).toMatch(/Restore point saved/));
    expect(page.published.get(deployment.recoveryController)).toBe(BASELINE);
    expect(compromiseCanOpen()).toBe(true);
    expect(savedInBrowser()).toBe(false);
  });

  it('resumes nothing when the move a restore point was saved for never landed', async () => {
    at(enrolled(EARLIER, {}));
    vi.mocked(applyDoc).mockRejectedValueOnce(new Error('Cancelled.'));
    const first = await mount();
    button(first, /Move my recovery/).click();
    await vi.waitFor(() => expect(first.textContent).toMatch(/Cancelled\./));
    expect(savedInBrowser()).toBe(true);

    const root = await mount();
    expect(root.textContent).toMatch(/Move recovery/);
    expect(root.textContent).not.toMatch(/Saving your restore point/);
    expect(client.publishBaseline).not.toHaveBeenCalled();
  });

  it('moves a Protected kit to the deployment’s pool with a new kit, approved before the switch', async () => {
    const doc = enrolled(EARLIER, {
      profile: 'protected',
      mode: 'combined',
      zk: { enrollmentId: new Uint8Array(32).fill(5), commitment: new Uint8Array(32).fill(6) },
    });
    at(doc);
    const root = await mount();
    expect(root.textContent).toMatch(/recovery kit cannot move/);
    expect(root.textContent).toMatch(/helpers approve the move first, at the service you are leaving/);

    button(root, /Move my recovery/).click();
    await vi.waitFor(() => expect(root.textContent).toMatch(/Create your new recovery kit first/));
    expect(applyDoc).not.toHaveBeenCalled();

    button(root, /Create my new recovery kit/).click();
    await vi.waitFor(() => expect(root.querySelector('[data-kit-saved]')).not.toBeNull());
    const saved = root.querySelector<HTMLInputElement>('[data-kit-saved]')!;
    saved.checked = true;
    saved.dispatchEvent(new Event('change'));
    button(root, /Move my recovery/).click();
    await vi.waitFor(() => expect(submitOpen).toHaveBeenCalled());

    const next = moved();
    expect(next.recovery!.controller).toBe(deployment.recoveryController);
    expect(next.recovery!.mode).toMatchObject({
      type: 'combined',
      guardians: GUARDIANS,
      quorum: 2,
      pool: deployment.zkPool,
      adapter: deployment.zkAdapter,
      'circuit-id': deployment.circuitId,
      'enrollment-id': '0e'.repeat(32),
      commitment: '0f'.repeat(32),
    });
    // The helpers approve exactly this configuration, and the owner's apply
    // carries their approvals' bound.
    const [, account, change, condition] = vi.mocked(collectCondition).mock.calls[0]!;
    expect(account).toBe(ACCOUNT);
    expect(change).toEqual({ kind: 'reconfigure-set', configHash: perch.configHash(next) });
    expect(condition).toEqual({ guardians: 2, zk: true });
    expect(vi.mocked(applyDoc).mock.calls[0]![2]).toEqual({ baseRevision: 6n, approvalValidUntil: 777 });
    expect(page.events).toEqual(['baseline read', 'approved', 'applied', 'baseline read', 'baseline published']);
  });

  it('publishes a newly enrolled restore point after a reload when saving it failed', async () => {
    at(enrolled(deployment, {}));
    page.failPublications = 1;
    const first = await mount();
    button(first, /Save recovery settings/).click();
    await vi.waitFor(() => expect(first.textContent).toMatch(/The network is unreachable/));
    expect(compromiseCanOpen()).toBe(false);

    const saved = moved();
    at(saved);
    const root = await mount();
    await vi.waitFor(() => expect(root.textContent).toMatch(/Restore point saved/));
    const published = page.published.get(deployment.recoveryController)!;
    expect(docHash(parsePolicyDocJson(published))).toBe(saved.recovery!.baseline!['doc-hash']);
    expect(compromiseCanOpen()).toBe(true);
    expect(savedInBrowser()).toBe(false);
  });

  it('refuses to save settings that would keep a kit enrolled in an earlier pool', async () => {
    at(enrolled(EARLIER, { mode: 'zk-only', zk: { enrollmentId: new Uint8Array(32).fill(5), commitment: new Uint8Array(32).fill(6) } }));
    const root = await mount();
    button(root, /Save recovery settings/).click();
    await vi.waitFor(() => expect(root.textContent).toMatch(/Create a new recovery kit to save these settings/));
    expect(applyDoc).not.toHaveBeenCalled();
  });
});
