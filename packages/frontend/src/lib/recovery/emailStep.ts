/**
 * The recover page's email approval (`docs/email-recovery/spec.md` §4, §6,
 * §8): the user enters their recovery code, sends one email from the inbox
 * they enrolled to the fixed recovery address, the email comes back to this
 * browser (sealed by the alert vault, or imported as an `.eml`), the browser
 * proves it, and the approval is submitted as the email guardian's vote.
 *
 * `rho` is drawn here and kept in this browser only; `account_code` is held
 * in memory while the page is open and never stored.
 */

import {
  addressCommitment,
  bigIntToBytes,
  bytes,
  bytesToBigInt,
  decryptBackup,
  encodeRecoveryEmail,
  initHashes,
  parseRecoveryKitCode,
  randomRho,
  type InboxSecret,
  type ProofResult,
} from '@nidohq/email-recovery';
import { perch } from '@nidohq/passkey-sdk';
import { esc } from '../html.js';
import { toast } from '../toast.js';
import { recoveryClient } from './chain.js';
import { requireEmailRecovery } from './emailConfig.js';
import type { GuardianConfig } from './emailGuardian.js';
import {
  PRIVACY_CLAIM,
  clock,
  mailtoLink,
  newPendingApproval,
  pendingApprovalProblem,
  recoveryEmail,
  spacedCode,
  stageText,
  subjectValue,
  type PendingEmailApproval,
} from './emailModel.js';
import { emailProver } from './emailProver.js';
import {
  attemptAlertCode,
  fetchInbound,
  registerInbound,
  resolveRecoveryKey,
  submitEmailApproval,
  toHex,
} from './emailRecovery.js';
import { el, errorText } from './ui.js';

const pendingKey = (account: string) => `nido:email-approval:${account}`;

function loadPending(account: string): PendingEmailApproval | undefined {
  try {
    const raw = localStorage.getItem(pendingKey(account));
    return raw ? (JSON.parse(raw) as PendingEmailApproval) : undefined;
  } catch {
    return undefined;
  }
}

function savePending(account: string, p: PendingEmailApproval | undefined): void {
  if (p) localStorage.setItem(pendingKey(account), JSON.stringify(p));
  else localStorage.removeItem(pendingKey(account));
}

/** The DNS notice: the resolver learns the provider, never the address. */
export async function confirmDnsLookup(domain = 'your mail provider'): Promise<boolean> {
  return confirm(
    `Nido’s key list does not have the key ${domain} signed this email with yet. ` +
      'To find it, this browser can ask a public DNS resolver. That resolver will see that someone at this ' +
      'internet address uses this mail provider (not your email address). Continue?',
  );
}

export interface EmailStepOptions {
  account: string;
  attemptId: bigint;
  guardian: { address: string; config: GuardianConfig };
  /** Called while the step needs the page to stay put (typing, proving), and when it may reload again. */
  hold: (held: boolean) => void;
  onApproved: () => void;
}

/** The panel for the email guardian's approval of one attempt. */
export function emailApprovalStep(o: EmailStepOptions): HTMLElement {
  const d = requireEmailRecovery();
  const wrap = el('div', { class: 'pol-fieldset', 'data-email-step': '' });
  wrap.append(
    el(
      'div',
      { style: 'font-size:13.5px;line-height:1.5;' },
      '<strong>Approve with your email.</strong> Send one email from the inbox you set up for recovery. ' +
        'It counts as one approval: the waiting period and your other helpers still apply. ' +
        `${esc(PRIVACY_CLAIM)} The email and its proof stay in this browser until the proof is made.`,
    ),
  );
  const status = el('div', { class: 'mut', style: 'font-size:12.5px;', role: 'status', 'data-email-status': '' });
  let accountCode: Uint8Array | undefined;
  let busy = false;

  // 1. The recovery code: the kit's 26 characters, or the backup block and its passphrase.
  const codeBox = el(
    'div',
    { style: 'display:grid;gap:8px;' },
    `<label class="pol-input-label">Your recovery code (26 letters and digits, from your recovery kit)
       <input name="kit-code" class="input mono" autocomplete="off" spellcheck="false" placeholder="ABCD EFGH IJKL MNOP QRST UVWX YZ">
     </label>
     <details><summary style="font-size:12.5px;cursor:pointer;">I have the recovery code block from my enrollment email instead</summary>
       <div style="display:grid;gap:6px;margin-top:6px;">
         <textarea name="backup-block" class="input mono" rows="4" style="font-size:11px;" placeholder="-----BEGIN NIDO RECOVERY CODE-----"></textarea>
         <input name="backup-passphrase" class="input" autocomplete="off" placeholder="The five-word passphrase">
       </div>
     </details>`,
  );
  const useCode = el('button', { class: 'btn primary', type: 'button', 'data-use-code': '' }, 'Continue') as HTMLButtonElement;
  codeBox.append(useCode);
  const alertLine = el('div', { style: 'font-size:13px;', 'data-alert-code': '' });
  const emailBox = el('div', { style: 'display:grid;gap:8px;', hidden: '' });
  const proveBox = el('div', { style: 'display:grid;gap:6px;', hidden: '' });
  const bar = el('div', { style: 'height:6px;border-radius:3px;background:var(--line);overflow:hidden;' }, '<div style="height:100%;width:0;background:var(--acc);transition:width .2s;"></div>');
  const stage = el('div', { style: 'font-size:13px;', 'data-prove-stage': '' });
  proveBox.append(stage, bar);
  wrap.append(codeBox, alertLine, emailBox, proveBox, status);

  codeBox.addEventListener('input', () => o.hold(true));

  useCode.addEventListener('click', () => {
    void (async () => {
      try {
        const kit = (codeBox.querySelector('[name="kit-code"]') as HTMLInputElement).value.trim();
        const block = (codeBox.querySelector('[name="backup-block"]') as HTMLTextAreaElement).value;
        useCode.disabled = true;
        if (kit) accountCode = parseRecoveryKitCode(kit);
        else {
          status.textContent = 'Unlocking your recovery code…';
          const pass = (codeBox.querySelector('[name="backup-passphrase"]') as HTMLInputElement).value;
          accountCode = await decryptBackup(block, pass, perch.contractId(o.account));
        }
        const code = await attemptAlertCode(accountCode, o.guardian.config.controller, o.account, o.attemptId);
        alertLine.innerHTML = `Alerts about this recovery show the code <strong class="mono" data-code>${esc(spacedCode(code))}</strong>. If an alert shows another code, it is not about the recovery you started.`;
        codeBox.hidden = true;
        status.textContent = '';
        await showEmail();
      } catch (e) {
        status.textContent = errorText(e);
        useCode.disabled = false;
      }
    })();
  });

  // 2. The email to send, and where it comes back.
  async function showEmail(): Promise<void> {
    o.hold(true);
    await initHashes();
    const client = recoveryClient();
    const current = await client.statement(o.account, o.attemptId, perch.EvidenceDomain.Initiate);
    const statement = perch.encodeStatement(current);
    const digest = perch.statementDigest(current);
    let pending = loadPending(o.account);
    if (pending && pendingApprovalProblem(pending, o.attemptId, digest)) pending = undefined;
    pending ??= newPendingApproval(o.attemptId, digest, randomRho());
    savePending(o.account, pending);
    const rho = BigInt(`0x${pending.rho}`);
    const email = recoveryEmail(d.recoveryInbox, digest, rho);

    emailBox.hidden = false;
    emailBox.innerHTML = `
      <div style="font-size:13.5px;"><strong>Send this email</strong> from the inbox you set up, exactly as written. Your mail app may add a signature; that is fine.</div>
      <div class="card" style="padding:12px;display:grid;gap:6px;font-size:12.5px;">
        <div><span class="mut">To</span> <code class="mono" data-to>${esc(email.to)}</code> <button class="btn ghost sm" type="button" data-copy="to">Copy</button></div>
        <div style="word-break:break-all;"><span class="mut">Subject</span> <code class="mono" data-subject>${esc(email.subject)}</code> <button class="btn ghost sm" type="button" data-copy="subject">Copy</button></div>
      </div>
      <a class="btn primary" data-mailto href="${esc(mailtoLink(email))}">Open my mail app</a>
      <div class="mut" style="font-size:12px;">Send it directly, not as a reply or forward, and do not change the Subject. Anything else in the email does not matter.</div>
      <div data-inbound class="mut" style="font-size:12.5px;"></div>
      <label class="pol-input-label">Or import the email you sent (.eml), from your Sent folder
        <input type="file" accept=".eml,message/rfc822" data-eml>
      </label>`;
    emailBox.querySelectorAll<HTMLButtonElement>('[data-copy]').forEach((b) =>
      b.addEventListener('click', () => {
        void navigator.clipboard.writeText(b.dataset.copy === 'to' ? email.to : email.subject).then(() => toast({ msg: 'Copied', icon: 'check' }));
      }),
    );
    emailBox.querySelector<HTMLInputElement>('[data-eml]')!.addEventListener('change', (e) => {
      const f = (e.target as HTMLInputElement).files?.[0];
      if (f) void f.arrayBuffer().then((b) => prove(new Uint8Array(b), statement, rho));
    });

    const inboundLine = emailBox.querySelector<HTMLElement>('[data-inbound]')!;
    try {
      let secret: InboxSecret | undefined = pending.inbox ? { id: pending.inbox.id, seed: pending.inbox.seed } : undefined;
      if (!secret) {
        secret = await registerInbound(subjectValue(email.subject));
        pending.inbox = { id: secret.id, seed: secret.seed };
        savePending(o.account, pending);
      }
      inboundLine.textContent = 'Waiting for your email to arrive. This page picks it up by itself, sealed so only this browser can read it.';
      const poll = async () => {
        if (busy) return;
        const messages = await fetchInbound(secret!).catch(() => []);
        if (messages[0]) await prove(messages[0], statement, rho);
        else setTimeout(() => void poll(), 4_000);
      };
      void poll();
    } catch (e) {
      inboundLine.textContent = `The email can’t be picked up automatically right now (${errorText(e)}). Import it instead.`;
    }
  }

  // 3. Check, prove, submit.
  async function prove(eml: Uint8Array, statement: Uint8Array, rho: bigint): Promise<void> {
    if (busy || !accountCode) return;
    busy = true;
    o.hold(true);
    proveBox.hidden = false;
    const fill = bar.firstElementChild as HTMLElement;
    try {
      await initHashes();
      const code = bytesToBigInt(accountCode);
      stage.textContent = 'Finding your provider’s key…';
      const key = await resolveRecoveryKey({ eml, guardian: o.guardian.config, accountCode: code, allowDns: () => confirmDnsLookup() });
      const encoded = await encodeRecoveryEmail({ eml, accountCode: code, rho, statement, modulus: key.modulus, keyPath: key.keyPath });
      if (toHex(bigIntToBytes(addressCommitment(encoded.address, code), 32)) !== toHex(o.guardian.config.commitment)) {
        throw new Error('This email is from another address than the one you set up, or the recovery code belongs to another setup.');
      }
      const started = performance.now();
      const tick = setInterval(() => (stage.dataset.clock = clock(performance.now() - started)), 500);
      let result: ProofResult;
      try {
        result = await emailProver().prove(
          { eml, accountCode: code, rho, statement, modulus: key.modulus, keyPath: key.keyPath },
          {
            onProgress: (e) => {
              stage.textContent = `${stageText(e.stage, e)} (${clock(e.elapsedMs)})`;
              stage.dataset.stage = e.stage;
              const share = { download: 0.1, witness: 0.25, proving: 0.4, verifying: 0.95 }[e.stage];
              const within = e.stage === 'download' && e.total ? ((e.loaded ?? 0) / e.total) * 0.15 : 0;
              fill.style.width = `${Math.round((share + within) * 100)}%`;
            },
          },
        );
      } finally {
        clearInterval(tick);
      }
      fill.style.width = '100%';
      stage.textContent = `Proved in ${clock(result.timings.witness + result.timings.proving + result.timings.verifying)}. Recording your approval…`;
      // The statement must still be the one the email approved.
      const now = await recoveryClient().statement(o.account, o.attemptId, perch.EvidenceDomain.Initiate);
      if (toHex(perch.statementDigest(now)) !== toHex(await bytes.sha256(statement))) {
        throw new Error('The recovery attempt changed while proving. Send a new email.');
      }
      await submitEmailApproval({
        controller: o.guardian.config.controller,
        account: o.account,
        attemptId: o.attemptId,
        domain: perch.EvidenceDomain.Initiate,
        guardian: o.guardian.address,
        statement,
        proof: result,
      });
      savePending(o.account, undefined);
      stage.textContent = 'Your email approval is recorded.';
      toast({ msg: 'Email approval recorded', icon: 'check' });
      o.hold(false);
      o.onApproved();
    } catch (e) {
      stage.textContent = errorText(e);
      status.textContent = 'You can try again with a new email.';
      busy = false;
    }
  }

  return wrap;
}
