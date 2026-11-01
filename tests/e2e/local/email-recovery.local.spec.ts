import { readFileSync } from 'node:fs';
import type { Browser, BrowserContext, Page } from '@playwright/test';
import { Address, Contract, Keypair, TransactionBuilder, rpc, scValToNative, xdr } from '@stellar/stellar-sdk';
import { test, expect, SEED_HEX, useIdentity } from '../../support/fixtures';
import { getInitScript } from '../../support/auth/bundle';
import { credentialFor, seedCredential } from '../../support/auth/seed';

/**
 * Email recovery end to end, on a local Stellar network (`stellar/quickstart
 * --local`), in Chromium, with the wallet's real in-browser proof:
 * `scripts/email-recovery-e2e.sh` deploys Perch's stack and Nido's email
 * contracts, starts the alert service and every third-party mock
 * (tests/support/emailServices.mjs), builds the wallet for that network, and
 * runs this test.
 *
 * The owner's Nido turns on recovery with one helper (a Stellar account this
 * test holds), then enrolls email recovery on /security/recovery/email/: the
 * test plays the owner's mail app and has the Gmail mock sign the enrollment
 * email to the recovery address, the alert vault seals it back to the page,
 * the page checks it, registers the alert contact with a Web Push
 * subscription (the push-service mock's, since a test browser cannot
 * subscribe to a real one), deploys the guardian with its key pin, and lists
 * it with a quorum of two.
 *
 * Then, from a new device with a new passkey, /security/recover/ opens a
 * lost-key attempt; the page shows the email to send; the test sends it from
 * the same inbox; the page receives it sealed, proves it in the browser,
 * and submits `submit_guardian`; the other helper approves; the alert the
 * vault emails carries the verification code the page shows; and after the
 * delay the page finishes the recovery.
 */

const root = `${process.cwd()}/`;
const PORT = Number(process.env.E2E_PORT || 4399);
const INBOX = 'first.last@gmail.com';
// What scripts/email-recovery-e2e.sh deployed and started; read when the test
// runs, so other tiers can load this file without them.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let stack: any;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let services: any;
let PASSPHRASE: string;
let server: rpc.Server;
function loadStack(): void {
  stack = JSON.parse(readFileSync(root + 'target/email-e2e/stack.json', 'utf8'));
  services = JSON.parse(readFileSync(root + 'target/email-e2e/services.json', 'utf8'));
  PASSPHRASE = stack.deployment.network;
  server = new rpc.Server(`${stack.base}/rpc`, { allowHttp: true });
}
/** Uncaught errors in any page: the test fails on the first one (see the hooks below). */
const pageErrors: string[] = [];

async function friendbot(kp: Keypair): Promise<void> {
  const r = await fetch(`${stack.base}/friendbot?addr=${kp.publicKey()}`);
  if (!r.ok) throw new Error(`friendbot ${r.status}`);
}

async function send(signer: Keypair, op: xdr.Operation): Promise<xdr.ScVal | undefined> {
  const tx = new TransactionBuilder(await server.getAccount(signer.publicKey()), { fee: '10000000', networkPassphrase: PASSPHRASE })
    .addOperation(op)
    .setTimeout(120)
    .build();
  const prepared = await server.prepareTransaction(tx);
  prepared.sign(signer);
  const sent = await server.sendTransaction(prepared);
  if (sent.status === 'ERROR') throw new Error(`rejected: ${sent.errorResult?.toXDR('base64')}`);
  const done = await server.pollTransaction(sent.hash, { attempts: 60 });
  if (done.status !== 'SUCCESS') throw new Error(`${done.status}: ${sent.hash}`);
  return (done as rpc.Api.GetSuccessfulTransactionResponse).returnValue;
}

/** A Nido from the local factory whose admin passkey is the shim's `label` identity. */
async function createNido(page: Page, label: string): Promise<{ account: string; host: string }> {
  const { publicKeyHex } = await credentialFor(SEED_HEX, label);
  const payer = Keypair.random();
  await friendbot(payer);
  const ret = await send(
    payer,
    new Contract(stack.deployment.factory).call(
      'create_account',
      xdr.ScVal.scvBytes(Buffer.from(crypto.getRandomValues(new Uint8Array(32)))),
      xdr.ScVal.scvBytes(Buffer.from(publicKeyHex, 'hex')),
    ),
  );
  const account = scValToNative(ret!) as string;
  const host = `${account.toLowerCase()}.localhost:${PORT}`;
  await page.goto(`http://${host}/security/`, { waitUntil: 'domcontentloaded' });
  await seedCredential(page, account, SEED_HEX, label);
  return { account, host };
}

/** A browser of its own (its own storage, so its own passkeys), with the shim and the push-service mock's subscription. */
async function device(browser: Browser, label: string): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.addInitScript({ content: `window.__TEST_AUTH_CONFIG__=${JSON.stringify({ seedHex: SEED_HEX })};` });
  await context.addInitScript({ content: await getInitScript() });
  const subscription = await (await fetch(`${services.control}/test/push-subscription`)).json();
  await context.addInitScript((sub) => {
    const fake = { endpoint: sub.endpoint, expirationTime: null, toJSON: () => sub, unsubscribe: async () => true };
    if ('PushManager' in window) {
      PushManager.prototype.subscribe = async () => fake as unknown as PushSubscription;
      PushManager.prototype.getSubscription = async () => null;
    }
    Notification.requestPermission = async () => 'granted';
  }, subscription);
  const page = await context.newPage();
  page.on('dialog', (d) => void d.accept());
  page.on('pageerror', (e) => {
    console.log(`[${label}] pageerror: ${e.message}`);
    pageErrors.push(`[${label}] ${e.message}`);
    // Stop here: the next step fails at once, and afterEach names the error.
    void context.close();
  });
  page.on('console', (m) => m.type() === 'error' && console.log(`[${label}] ${m.text()}`));
  await useIdentity(page, label).catch(() => {});
  return { context, page };
}

/** The test as the owner's mail app: the Gmail mock signs `subject` from the inbox and sends it to the recovery address. */
async function sendEmail(subject: string): Promise<void> {
  const r = await fetch(`${services.control}/test/mail`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ from: INBOX, displayName: 'First Last', subject }),
  });
  const body = (await r.json()) as { delivered: number };
  expect(body.delivered).toBe(1);
}

async function emailsTo(address: string): Promise<{ subject: string; text?: string }[]> {
  return (await fetch(`${services.control}/test/emails?to=${encodeURIComponent(address)}`)).json();
}

test.describe('@local email recovery', () => {
  test.describe.configure({ timeout: 15 * 60_000 });
  test.use({ actionTimeout: 60_000 });
  test.beforeAll(loadStack);
  test.afterEach(() => expect(pageErrors).toEqual([]));

  test('enroll an inbox, lose the passkey, recover with one email and a second helper', async ({ browser }) => {
    const owner = await device(browser, 'email-owner');
    const { account, host } = await createNido(owner.page, 'email-owner');
    const friend = Keypair.random();
    await friendbot(friend);

    // Recovery with one helper, on the quick timing.
    await owner.page.goto(`http://${host}/security/recovery/`, { waitUntil: 'networkidle' });
    expect(await owner.page.evaluate(() => crossOriginIsolated)).toBe(true);
    await owner.page.locator('input[name="profile"][value="loss"]').check();
    await owner.page.locator('input[name="mode"][value="guardian-only"]').check();
    await owner.page.locator('textarea[name="guardians"]').fill(friend.publicKey());
    await owner.page.locator('input[name="quorum"]').fill('1');
    await owner.page.locator('select[name="timing"]').selectOption('quick');
    await owner.page.getByRole('button', { name: /Turn on recovery/ }).click();
    await expect(owner.page.getByText('Recovery saved')).toBeVisible({ timeout: 180_000 });

    // Enrollment.
    await owner.page.goto(`http://${host}/security/recovery/email/`, { waitUntil: 'networkidle' });
    const kit = (await owner.page.locator('[data-kit-code]').textContent({ timeout: 60_000 }))!.trim();
    expect(kit.replace(/ /g, '')).toMatch(/^[A-Z2-7]{26}$/);
    await owner.page.locator('[name="kit-saved"]').check();
    await owner.page.getByRole('button', { name: 'Continue' }).click();
    const enrollSubject = (await owner.page.locator('[data-subject]').textContent({ timeout: 60_000 }))!.trim();
    expect(enrollSubject).toMatch(/^ENROLL NIDO ACCOUNT RECOVERY [0-9a-f]{64}$/);
    await expect(owner.page.locator('[data-inbound]')).toContainText('Waiting for your email', { timeout: 60_000 });
    await sendEmail(enrollSubject);
    await expect(owner.page.locator('[data-address]')).toHaveText(INBOX, { timeout: 120_000 });
    await owner.page.getByRole('button', { name: 'Turn on alerts on this device' }).click();
    await expect(owner.page.locator('[name="confirm-code"]')).toBeVisible({ timeout: 120_000 });
    const confirmation = (await emailsTo(INBOX)).map((m) => m.text?.match(/confirmation code for Nido recovery alerts is (\d{6})/)?.[1]).find(Boolean);
    expect(confirmation).toMatch(/^\d{6}$/);
    await owner.page.locator('[name="confirm-code"]').fill(confirmation!);
    await owner.page.getByRole('button', { name: 'Confirm' }).click();
    await owner.page.getByRole('button', { name: 'Create my email helper' }).click({ timeout: 120_000 });
    await expect(owner.page.locator('[name="quorum"]')).toBeVisible({ timeout: 180_000 });
    await owner.page.locator('[name="quorum"]').fill('2');
    await owner.page.getByRole('button', { name: 'Save' }).click();
    await expect(owner.page.getByText('Email recovery is on', { exact: true }).first()).toBeVisible({ timeout: 180_000 });

    // A new device, a new passkey.
    const phone = await device(browser, 'email-owner-new-device');
    await phone.page.goto(`http://${host}/security/recover/`, { waitUntil: 'networkidle' });
    expect(await phone.page.evaluate(() => crossOriginIsolated)).toBe(true);
    await phone.page.getByRole('button', { name: 'Create my new passkey' }).click();
    await expect(phone.page.locator('[data-email-step]')).toBeVisible({ timeout: 180_000 });
    await phone.page.locator('[name="kit-code"]').fill(kit);
    await phone.page.locator('[data-use-code]').click();
    const code = (await phone.page.locator('[data-code]').textContent({ timeout: 60_000 }))!.replace(/\s/g, '');
    expect(code).toMatch(/^\d{6}$/);
    const subject = (await phone.page.locator('[data-subject]').textContent({ timeout: 60_000 }))!.trim();
    expect(subject).toMatch(/^APPROVE NIDO ACCOUNT RECOVERY [0-9a-f]{64}$/);
    const mailto = await phone.page.locator('[data-mailto]').getAttribute('href');
    expect(decodeURIComponent(new URL(mailto!).searchParams.get('subject')!)).toBe(subject);
    await expect(phone.page.locator('[data-inbound]')).toContainText('Waiting for your email', { timeout: 60_000 });
    await sendEmail(subject);
    // The page proves it in the browser and records the guardian's vote.
    await expect(phone.page.locator('[data-prove-stage]')).toHaveAttribute('data-stage', /proving|verifying/, { timeout: 180_000 });
    await expect(phone.page.locator('[data-remaining]')).toContainText('Your email approval is recorded', { timeout: 300_000 });
    await expect(phone.page.locator('[data-remaining]')).toContainText('1 more helper needs to approve');

    // The other helper approves from its own account.
    const attemptId = BigInt(
      await phone.page.evaluate((a) => JSON.parse(localStorage.getItem(`nido:recover:${a}`)!).attemptId, account),
    );
    await send(
      friend,
      new Contract(stack.deployment.recoveryController).call(
        'submit_guardian',
        Address.fromString(account).toScVal(),
        xdr.ScVal.scvU64(xdr.Uint64.fromString(attemptId.toString())),
        xdr.ScVal.scvU32(0),
        Address.fromString(friend.publicKey()).toScVal(),
      ),
    );
    await expect(phone.page.getByText(/Approved\. You can finish/)).toBeVisible({ timeout: 120_000 });
    await expect(phone.page.locator('[data-countdown]')).toBeVisible();

    // The required alert: email and push, both with the code the page showed.
    await expect
      .poll(async () => (await emailsTo(INBOX)).filter((m) => m.text?.includes(`${code.slice(0, 3)} ${code.slice(3)}`)).length, { timeout: 120_000 })
      .toBeGreaterThan(0);
    await expect
      .poll(async () => ((await (await fetch(`${services.control}/test/pushes`)).json()) as { code?: string }[]).some((p) => p.code === code), { timeout: 60_000 })
      .toBe(true);

    // The delay, then completion.
    await expect(phone.page.getByRole('button', { name: 'Finish recovery' })).toBeVisible({ timeout: 10 * 60_000 });
    await phone.page.getByRole('button', { name: 'Finish recovery' }).click();
    await expect(phone.page.getByText('Recovery finished')).toBeVisible({ timeout: 180_000 });
  });
});
