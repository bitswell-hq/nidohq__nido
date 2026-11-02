/**
 * `/security/recovery/email/`: making the owner's inbox one recovery
 * helper (`docs/email-recovery/spec.md` §5), while this browser holds the
 * account's passkey:
 *
 * 1. Draw `account_code` and save a backup of it (§5.6, `emailBackup.ts`).
 * 2. Send the enrollment email from the inbox (`ENROLL NIDO ACCOUNT
 *    RECOVERY <hex(E)>`, §5.4) to the recovery address, and get it back
 *    here (sealed by the alert vault, or imported).
 * 3. Check it locally (§5.4): the signature, the From address, the Subject.
 * 4. Register the alert contact with the Web Push channel that email
 *    recovery requires (§9.3 rule 2, §10.3), and confirm it. The address
 *    field starts empty, with a warning (not a block) when it is the
 *    enrolled inbox itself, whose thief could delete the alerts, and a note
 *    when the inbox's provider is the platform that likely syncs this
 *    device's passkey (`syncedPasskeyNote`).
 * 5. Deploy the account's email guardian with `C` and the key pin (§7.4,
 *    §8.2), and check what was deployed (§5.5).
 * 6. Apply the document that lists it among the recovery helpers, built by
 *    `recoverySpec`, whose rules refuse email-alone setups (§9.3).
 *
 * Progress lives in this tab's `sessionStorage` so leaving for the mail app
 * and coming back keeps it; `account_code` is there until enrollment ends,
 * never anywhere else.
 */

import {
  bigIntToBytes,
  bytes,
  bytesToBigInt,
  checkEnrollmentEmail,
  enrollmentSubject,
  initHashes,
  pinTree,
  randomRho,
  type InboxSecret,
} from '@nidohq/email-recovery';
import { perch } from '@nidohq/passkey-sdk';
import { esc } from '../html.js';
import { submitPermissionlessOp } from '../recoverySubmit.js';
import { getSubmitter } from '../primaryPasskeySigner.js';
import { toast } from '../toast.js';
import { currentOrFirstDoc, latestCloseTime, readRecoveryState, targetCloseMs } from './chain.js';
import { perchDeployment, requireDeployment } from './deployment.js';
import { backupPanel } from './emailBackup.js';
import { CONSENT_TEXT, confirmAlertContact, pushSubscription, registerAlertContact } from './emailAlerts.js';
import { emailRecoveryDeployment, thisWalletApex } from './emailConfig.js';
import { emailCircuit } from './emailProver.js';
import { ALLOW_ALL, contractWasmHash, deployGuardianOperation, deployedAddress, readGuardianConfig, type GuardianConfig } from './emailGuardian.js';
import {
  ENROLLED_ADDRESS_NOTE,
  PRIVACY_CLAIM,
  PROVIDER_SEES,
  alertAddressWarning,
  mailtoLink,
  nextEnrollStep,
  pinValidUntil,
  subjectValue,
  syncedPasskeyNote,
  type EmailToSend,
  type EnrollStep,
} from './emailModel.js';
import { fetchInbound, registerInbound, resolveEnrollmentKey, vaultKey } from './emailRecovery.js';
import { confirmDnsLookup } from './emailStep.js';
import { adminSignerIds } from './model.js';
import { apply } from './settingsPage.js';
import { busy, card, el, errorText } from './ui.js';

const { toHex, fromHex } = bytes;

interface Progress {
  done: Partial<Record<EnrollStep, boolean>>;
  accountCode: string;
  rhoE: string;
  emailBlock?: string;
  inbox?: InboxSecret;
  checked?: { address: string; domain: string; modulus: string; commitment: string };
  contact?: string;
  guardian?: string;
}

const key = (account: string) => `nido:email-enroll:${account}`;
const load = (account: string): Progress | undefined => {
  try {
    const raw = sessionStorage.getItem(key(account));
    return raw ? (JSON.parse(raw) as Progress) : undefined;
  } catch {
    return undefined;
  }
};
const save = (account: string, p: Progress | undefined) =>
  p ? sessionStorage.setItem(key(account), JSON.stringify(p)) : sessionStorage.removeItem(key(account));

export async function mountEmailEnroll(root: HTMLElement, accountOrNull: string | null): Promise<void> {
  if (!accountOrNull) {
    root.append(el('p', { class: 'mut' }, 'Open this page from your Nido to add email recovery.'));
    return;
  }
  const account: string = accountOrNull;
  const d = emailRecoveryDeployment();
  if (!perchDeployment() || !d) {
    root.append(el('div', { class: 'alert', role: 'note' }, 'Email recovery is not available on this network yet.'));
    return;
  }
  root.append(
    card(
      'How email recovery works',
      `<p style="margin:0;font-size:13.5px;line-height:1.5;">If you lose your passkey, you send one email from your inbox and this browser proves your mail provider signed it.
        It counts as <strong>one</strong> of your recovery helpers: your other helpers and the waiting period still apply, and you are alerted when your email approves a recovery and when a recovery is approved.
        ${esc(PRIVACY_CLAIM)} ${esc(PROVIDER_SEES)}</p>`,
    ),
  );
  // The enrollment Subject (E) and the commitment are Poseidon2 hashes (bb.js).
  await initHashes();
  let p = load(account);
  if (!p) {
    p = { done: {}, accountCode: toHex(crypto.getRandomValues(new Uint8Array(16))), rhoE: randomRho().toString(16) };
    save(account, p);
  }
  const progress = p;
  const accountId = perch.contractId(account);
  const accountCode = fromHex(progress.accountCode);
  const rhoE = BigInt(`0x${progress.rhoE}`);
  const host = el('div');
  root.append(host);
  const redraw = () => {
    save(account, progress);
    host.innerHTML = '';
    host.append(render());
  };
  const step = (s: EnrollStep) => {
    progress.done[s] = true;
    redraw();
  };

  function render(): HTMLElement {
    const next = nextEnrollStep(progress.done);
    const status = el('div', { class: 'mut', style: 'font-size:12.5px;', role: 'status' });
    switch (next) {
      case 'code': {
        const c = card('1. Your recovery code');
        const body = c.querySelector('.card') as HTMLElement;
        const go = el('button', { class: 'btn primary', type: 'button', disabled: '' }, 'Continue') as HTMLButtonElement;
        body.append(
          backupPanel(accountCode, { address: account, id: accountId, apex: thisWalletApex() }, (s) => {
            go.disabled = !s.saved;
            progress.emailBlock = s.emailBlock;
            save(account, progress);
          }),
          go,
        );
        go.addEventListener('click', () => step('code'));
        return c;
      }
      case 'email': {
        const email: EmailToSend = {
          to: d!.recoveryInbox,
          subject: enrollmentSubject(accountId, rhoE),
          body: `Setting up email recovery for my Nido.${progress.emailBlock ? `\r\n\r\n${progress.emailBlock}\r\n` : ''}`,
        };
        const c = card(
          '2. Send the enrollment email',
          `<div style="font-size:13.5px;">Send this email from the inbox you want to use, exactly as written. Use the address you will still have if you lose this device.</div>
           <div class="card" style="padding:12px;display:grid;gap:6px;font-size:12.5px;">
             <div><span class="mut">To</span> <code class="mono" data-to>${esc(email.to)}</code></div>
             <div style="word-break:break-all;"><span class="mut">Subject</span> <code class="mono" data-subject>${esc(email.subject)}</code></div>
           </div>
           <a class="btn primary" data-mailto href="${esc(mailtoLink(email))}">Open my mail app</a>
           <div data-inbound class="mut" style="font-size:12.5px;"></div>
           <label class="pol-input-label">Or import the email you sent (.eml), from your Sent folder
             <input type="file" accept=".eml,message/rfc822" data-eml>
           </label>`,
        );
        const body = c.querySelector('.card') as HTMLElement;
        body.append(status);
        const received = async (eml: Uint8Array) => {
          try {
            await initHashes();
            status.textContent = 'Checking your email…';
            const signerKey = await resolveEnrollmentKey(eml, () => confirmDnsLookup());
            const circuit = await emailCircuit();
            const checked = await checkEnrollmentEmail({ circuit, eml, accountId, rhoE, accountCode: bytesToBigInt(accountCode), modulus: signerKey.modulus });
            progress.checked = {
              address: checked.address,
              domain: checked.domain,
              modulus: signerKey.modulus.toString(16),
              commitment: toHex(bigIntToBytes(checked.commitment, 32)),
            };
            progress.done.email = true;
            step('check');
          } catch (e) {
            status.textContent = `${errorText(e)} Send the email again exactly as shown, or import it.`;
          }
        };
        body.querySelector<HTMLInputElement>('[data-eml]')!.addEventListener('change', (e) => {
          const f = (e.target as HTMLInputElement).files?.[0];
          if (f) void f.arrayBuffer().then((b) => received(new Uint8Array(b)));
        });
        const line = body.querySelector<HTMLElement>('[data-inbound]')!;
        void (async () => {
          try {
            progress.inbox ??= (await registerInbound(subjectValue(email.subject))).secret;
            save(account, progress);
            line.textContent = 'Waiting for your email to arrive. This page picks it up by itself, sealed so only this browser can read it.';
            const poll = async () => {
              const [m] = await fetchInbound(progress.inbox!).catch(() => []);
              if (m) await received(m);
              else if (nextEnrollStep(progress.done) === 'email') setTimeout(() => void poll(), 4_000);
            };
            void poll();
          } catch (e) {
            line.textContent = `The email can’t be picked up automatically right now (${errorText(e)}). Import it instead.`;
          }
        })();
        return c;
      }
      case 'check':
      case 'alerts': {
        const synced = syncedPasskeyNote(progress.checked!.domain, navigator.userAgent);
        const c = card(
          '3. Alerts',
          `<div style="font-size:13.5px;">Enrolled address, exactly as your provider writes it: <code class="mono" data-address>${esc(progress.checked!.address)}</code>. ${esc(ENROLLED_ADDRESS_NOTE)}</div>
           ${synced ? `<div class="alert warn" role="note" style="font-size:12.5px;" data-synced-passkey>${esc(synced)}</div>` : ''}
           <div style="font-size:13px;">${esc(CONSENT_TEXT)} Because email can help recover your Nido, alerts also go to this device as notifications.</div>
           <label class="pol-input-label">Send alerts to
             <input name="alert-address" class="input" type="email" autocomplete="email" placeholder="An address at another provider">
           </label>
           <div class="mut" style="font-size:12.5px;">Pick an inbox other than the one you just enrolled: if someone takes over that inbox, alerts sent elsewhere still reach you.</div>
           <div class="alert warn" role="alert" data-alert-same hidden></div>`,
        );
        const body = c.querySelector('.card') as HTMLElement;
        const addressInput = body.querySelector<HTMLInputElement>('[name="alert-address"]');
        const same = body.querySelector<HTMLElement>('[data-alert-same]');
        addressInput?.addEventListener('input', () => {
          const warning = alertAddressWarning(addressInput.value, progress.checked!.address);
          same!.hidden = !warning;
          same!.textContent = warning ?? '';
        });
        if (!progress.contact) {
          const go = el('button', { class: 'btn primary', type: 'button' }, 'Turn on alerts on this device') as HTMLButtonElement;
          body.append(go, status);
          go.addEventListener('click', () =>
            busy(go, status, 'Setting up alerts…', async () => {
              const vault = await vaultKey();
              const { push, deviceKey } = await pushSubscription(vault.vapid);
              status.textContent = 'Confirm with your passkey…';
              const address = addressInput!.value.trim();
              if (!address) throw new Error('Enter the address alerts should go to.');
              const contact = await registerAlertContact({
                account,
                address,
                accountCode,
                push,
                deviceKey,
                vault,
              });
              progress.contact = toHex(contact);
              redraw();
            }),
          );
          return c;
        }
        body.append(
          el(
            'label',
            { class: 'pol-input-label' },
            'We emailed that address a six-digit code. Enter it here:<input name="confirm-code" class="input mono" inputmode="numeric" autocomplete="one-time-code">',
          ),
        );
        const go = el('button', { class: 'btn primary', type: 'button' }, 'Confirm') as HTMLButtonElement;
        body.append(go, status);
        go.addEventListener('click', () =>
          busy(go, status, 'Confirming…', async () => {
            await confirmAlertContact({
              account,
              contact: fromHex(progress.contact!),
              code: (body.querySelector('[name="confirm-code"]') as HTMLInputElement).value,
              vault: await vaultKey(),
            });
            step('alerts');
          }),
        );
        return c;
      }
      case 'deploy': {
        const c = card(
          '4. Your email helper',
          `<div style="font-size:13.5px;">Nido now creates the contract that counts your email as one helper. It holds only a salted fingerprint of your address, never the address.</div>`,
        );
        const body = c.querySelector('.card') as HTMLElement;
        const go = el('button', { class: 'btn primary', type: 'button' }, 'Create my email helper') as HTMLButtonElement;
        body.append(go, status);
        go.addEventListener('click', () =>
          busy(go, status, 'Creating it…', async () => {
            const perchD = requireDeployment();
            const chk = progress.checked!;
            const now = await latestCloseTime();
            const pin = pinTree(bytesToBigInt(accountCode), [{ domain: chk.domain, modulus: BigInt(`0x${chk.modulus}`) }]);
            const config: GuardianConfig = {
              account,
              controller: perchD.recoveryController,
              commitment: fromHex(chk.commitment),
              registry: d!.registry,
              keyPin: [{ root: bigIntToBytes(pin.root, 32), validUntil: pinValidUntil(now) }],
              allowedActions: ALLOW_ALL,
              verifier: d!.verifier,
              circuitId: fromHex(d!.circuitId),
            };
            const deployer = (await getSubmitter()).publicKey();
            const salt = crypto.getRandomValues(new Uint8Array(32));
            await submitPermissionlessOp(deployGuardianOperation({ deployer, wasmHash: fromHex(d!.guardianWasmHash), salt, config }));
            const address = deployedAddress(deployer, salt);
            // §5.5: check what was deployed before listing it.
            status.textContent = 'Checking it…';
            if ((await contractWasmHash(address)) !== d!.guardianWasmHash) throw new Error('The deployed helper runs other code than expected.');
            const got = await readGuardianConfig(address);
            const same = (a: GuardianConfig, b: GuardianConfig) =>
              a.account === b.account &&
              a.controller === b.controller &&
              toHex(a.commitment) === toHex(b.commitment) &&
              a.registry === b.registry &&
              a.verifier === b.verifier &&
              toHex(a.circuitId) === toHex(b.circuitId) &&
              a.allowedActions === b.allowedActions &&
              a.keyPin.length === 1 &&
              toHex(a.keyPin[0]!.root) === toHex(b.keyPin[0]!.root) &&
              a.keyPin[0]!.validUntil === b.keyPin[0]!.validUntil;
            if (!got || !same(got, config)) throw new Error('The deployed helper is not configured as intended.');
            progress.guardian = address;
            step('deploy');
          }),
        );
        return c;
      }
      case 'apply':
        return applyCard(status);
      case 'done': {
        save(account, undefined);
        return card(
          'Email recovery is on',
          `<p style="margin:0;font-size:13.5px;">Your inbox now counts as one recovery helper. If you lose your passkey, open
            <strong>Get back in</strong> on your Nido and follow the email step. Keep your recovery kit safe; you can check the code any time
            in recovery settings.</p>
           <a class="btn primary" href="/security/recovery/">Back to recovery settings</a>`,
        );
      }
    }
  }

  function applyCard(status: HTMLElement): HTMLElement {
    const c = card('5. Add it to your recovery helpers');
    const body = c.querySelector('.card') as HTMLElement;
    body.append(el('div', { class: 'skeleton', style: 'height:60px;' }));
    void (async () => {
      const state = await readRecoveryState(account);
      const s = state.summary;
      const others = (s?.guardians ?? []).filter((g) => g !== progress.guardian);
      body.innerHTML = `
        <div style="font-size:13.5px;">Your other helpers: ${others.length ? others.map((g) => `<code class="mono">${esc(g.slice(0, 6))}…</code>`).join(', ') : 'none yet'}.</div>
        <label class="pol-input-label">Helpers needed to approve a recovery (your email counts as one)
          <input name="quorum" class="input" type="number" min="1" max="${others.length + 1}" value="${Math.min(s?.quorum ?? 2, others.length + 1)}">
        </label>
        <div class="mut" style="font-size:12.5px;">With only your email needed, a recovery must wait at least ${esc(`${perch.EMAIL_ONLY_MIN_DELAY_SECONDS / 86_400} days`)} and protect against a lost passkey only. Nido refuses anything weaker.</div>`;
      const go = el('button', { class: 'btn primary', type: 'button' }, 'Save') as HTMLButtonElement;
      body.append(go, status);
      go.addEventListener('click', () =>
        busy(go, status, 'Preparing…', async () => {
          const base = state.doc ?? (await currentOrFirstDoc(account)).doc;
          const quorum = Number((body.querySelector('[name="quorum"]') as HTMLInputElement).value);
          const mode = s?.mode === 'zk-only' || s?.mode === 'combined' ? 'combined' : 'guardian-only';
          const spec = perch.recoverySpec(requireDeployment(), {
            profile: s?.profile ?? 'loss',
            mode,
            guardians: [...others, { kind: 'email', address: progress.guardian!, allowedActions: ALLOW_ALL }],
            quorum,
            secondAlertChannel: 'web-push',
            zk: s?.zk ? { enrollmentId: fromHex(s.zk.enrollmentId), commitment: zkCommitment(state.doc) } : undefined,
            replaceable: s?.replaceable.length ? s.replaceable : adminSignerIds(base),
            baselineDocHash: s?.baselineDocHash,
            delayLedgers: s?.delayLedgers ?? perch.RECOVERY_DEFAULTS.delayLedgers,
            expiryLedgers: s?.expiryLedgers ?? perch.RECOVERY_DEFAULTS.expiryLedgers,
            maxCancels: s?.maxCancels,
            ledgerCloseMs: await targetCloseMs(),
          });
          await apply(account, state, perch.withRecovery(base, spec), status);
          toast({ msg: 'Email recovery is on', icon: 'check' });
          step('apply');
        }),
      );
    })().catch((e) => (body.innerHTML = `<p class="mut">Couldn’t read this Nido’s recovery: ${esc(errorText(e))}</p>`));
    return c;
  }

  redraw();
}

function zkCommitment(doc: unknown): Uint8Array {
  const mode = (doc as { recovery: { mode: Record<string, string> } }).recovery.mode;
  return fromHex(mode.commitment!);
}
