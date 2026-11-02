/**
 * The `account_code` backups enrollment offers (`docs/email-recovery/spec.md`
 * §5.6): the recovery kit (26 characters to save in a password manager or
 * on paper, with the Nido it recovers, where recovery starts, and Nido's
 * apex) and, optionally, a passphrase-encrypted copy in the enrollment
 * email's body, so it sits in the user's Sent folder (the account rides
 * inside its ciphertext, never in clear). Which of these a wallet offers is
 * an open question (§13 question 4); this component is the only place that
 * decides, so the choice can change here alone.
 *
 * Saving is not taken on trust: once the user says the code is saved, the
 * code leaves the screen and two groups of it are typed back from wherever
 * it was saved, before enrollment continues. On an iPhone or iPad, printing
 * comes first, since a download goes to iCloud Drive by default
 * (`kitActions`).
 */

import { encryptBackup, generatePassphrase, recoveryKitCode } from '@nidohq/email-recovery';
import { nidoKey } from '@nidohq/passkey-sdk';
import { esc } from '../html.js';
import { toast } from '../toast.js';
import { COPY_KIT_NOTE, KIT_STORAGE_ADVICE, type WalletApex, kitActions, kitCheckGroups, kitCheckMatches, recoveryKitText } from './emailModel.js';
import { el } from './ui.js';

const checkedKey = (account: string) => nidoKey(`code-checked:${account}`);

/** Record that the owner just showed, on this device, that they hold `account`'s recovery code. */
export function rememberCodeChecked(account: string, at = Date.now()): void {
  try {
    localStorage.setItem(checkedKey(account), String(at));
  } catch {
    /* storage unavailable: the reminder shows again */
  }
}

/** When the owner last showed on this device that they hold the code, if ever. */
export function codeCheckedAt(account: string): number | undefined {
  try {
    const v = Number(localStorage.getItem(checkedKey(account)));
    return v > 0 ? v : undefined;
  } catch {
    return undefined;
  }
}

export interface BackupState {
  /** The user typed back part of the saved recovery code correctly. */
  saved: boolean;
  /** The block to put in the enrollment email's body, when the user chose the encrypted copy. */
  emailBlock?: string;
}

const ORDINAL = ['first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh'];

/** Print `text` alone, from a frame of its own. */
function printText(text: string): void {
  const frame = document.createElement('iframe');
  frame.style.cssText = 'position:fixed;width:0;height:0;border:0;';
  frame.srcdoc = `<!doctype html><title>Nido recovery kit</title><pre style="font:14px/1.5 ui-monospace,monospace;white-space:pre-wrap;">${esc(text)}</pre>`;
  frame.addEventListener('load', () => {
    frame.contentWindow?.print();
    setTimeout(() => frame.remove(), 60_000);
  });
  document.body.append(frame);
}

export function backupPanel(
  accountCode: Uint8Array,
  account: { address: string; id: Uint8Array; apex: WalletApex },
  onChange: (s: BackupState) => void,
  userAgent: string = navigator.userAgent,
): HTMLElement {
  const kit = recoveryKitCode(accountCode);
  const groups = kitCheckGroups();
  const state: BackupState = { saved: false };
  const actions = kitActions(userAgent);
  const download = `<a class="btn ${actions.primary === 'download' ? 'primary' : 'ghost'} sm" data-download-kit download="nido-recovery-kit.txt">Download the kit</a>`;
  const print = `<button class="btn ${actions.primary === 'print' ? 'primary' : 'ghost'} sm" type="button" data-print-kit>Print the kit</button>`;
  const wrap = el(
    'div',
    { class: 'pol-fieldset', 'data-backup': '' },
    `<div data-kit-save style="display:grid;gap:8px;">
       <div style="font-size:13.5px;"><strong>Save your recovery code.</strong> Recovering by email needs it, and Nido never has it. Anyone with this code and access to your inbox could approve a recovery, so keep it as safe as a password.</div>
       <code class="mono" style="font-size:17px;letter-spacing:.04em;" data-kit-code>${esc(kit)}</code>
       <div class="mut" style="font-size:12.5px;word-break:break-all;">It recovers the Nido <code class="mono" data-kit-account>${esc(account.address)}</code>. The kit holds both, the address of the recovery page, and Nido’s own address.</div>
       <div style="display:flex;gap:8px;flex-wrap:wrap;">
         ${actions.primary === 'print' ? print + download : download + print}
         <button class="btn ghost sm" type="button" data-copy-kit>Copy</button>
       </div>
       <div class="mut" style="font-size:12.5px;" data-kit-copy-note>${esc(COPY_KIT_NOTE)}</div>
       ${actions.note ? `<div class="mut" style="font-size:12.5px;" data-kit-device-note>${esc(actions.note)}</div>` : ''}
       <div class="mut" style="font-size:12.5px;" data-kit-advice>${esc(KIT_STORAGE_ADVICE)}</div>
       <label class="pol-check"><input type="checkbox" name="email-copy"> Also put an encrypted copy in the enrollment email, so it stays in my Sent folder</label>
       <div data-passphrase hidden style="display:grid;gap:6px;font-size:13px;"></div>
       <button class="btn soft sm" type="button" data-kit-saved-now>I saved it: check it</button>
     </div>
     <div style="display:grid;gap:6px;font-size:13px;" data-kit-check hidden>
       <div>The code is off the screen now. Type the <strong>${ORDINAL[groups[0]]}</strong> and <strong>${ORDINAL[groups[1]]}</strong> groups of your code, from where you saved it:</div>
       <div style="display:flex;gap:8px;">
         <input class="input mono" name="kit-group-a" data-kit-group="${groups[0]}" autocomplete="off" spellcheck="false" maxlength="5" style="width:7em;" aria-label="The ${ORDINAL[groups[0]]} group">
         <input class="input mono" name="kit-group-b" data-kit-group="${groups[1]}" autocomplete="off" spellcheck="false" maxlength="5" style="width:7em;" aria-label="The ${ORDINAL[groups[1]]} group">
       </div>
       <div class="mut" data-kit-check-status role="status"></div>
       <button class="btn ghost sm" type="button" data-kit-show-again>Show the code again</button>
     </div>`,
  );
  const text = recoveryKitText({ kit, account: account.address, apex: account.apex });
  const saveBox = wrap.querySelector<HTMLElement>('[data-kit-save]')!;
  const checkBox = wrap.querySelector<HTMLElement>('[data-kit-check]')!;
  const codeEl = wrap.querySelector<HTMLElement>('[data-kit-code]')!;
  wrap.querySelector<HTMLAnchorElement>('[data-download-kit]')!.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  wrap.querySelector('[data-print-kit]')!.addEventListener('click', () => printText(text));
  wrap.querySelector('[data-copy-kit]')!.addEventListener('click', () => {
    void navigator.clipboard.writeText(kit.replace(/ /g, '')).then(() => toast({ msg: 'Recovery code copied', icon: 'check' }));
  });
  const groupA = wrap.querySelector<HTMLInputElement>('[name="kit-group-a"]')!;
  const groupB = wrap.querySelector<HTMLInputElement>('[name="kit-group-b"]')!;
  const checkStatus = wrap.querySelector<HTMLElement>('[data-kit-check-status]')!;
  const update = () => {
    const typed = [groupA.value, groupB.value];
    state.saved = kitCheckMatches(kit, groups, typed);
    if (state.saved) rememberCodeChecked(account.address);
    const complete = groups.every((g, i) => typed[i]!.replace(/\s+/g, '').length >= kit.split(' ')[g]!.length);
    checkStatus.textContent = state.saved ? 'That matches.' : complete ? 'That does not match. Check the copy you saved, or show the code again.' : '';
    onChange({ ...state });
  };
  // The check happens with the code gone from the page, so it cannot be read off the screen.
  const showCheck = (on: boolean) => {
    saveBox.hidden = on;
    checkBox.hidden = !on;
    codeEl.textContent = on ? '' : kit;
    if (on) groupA.focus();
  };
  wrap.querySelector('[data-kit-saved-now]')!.addEventListener('click', () => showCheck(true));
  wrap.querySelector('[data-kit-show-again]')!.addEventListener('click', () => {
    groupA.value = groupB.value = '';
    update();
    showCheck(false);
  });
  groupA.addEventListener('input', update);
  groupB.addEventListener('input', update);
  const passBox = wrap.querySelector<HTMLElement>('[data-passphrase]')!;
  wrap.querySelector<HTMLInputElement>('[name="email-copy"]')!.addEventListener('change', (e) => {
    const on = (e.target as HTMLInputElement).checked;
    passBox.hidden = !on;
    state.emailBlock = undefined;
    if (!on) return update();
    const passphrase = generatePassphrase();
    passBox.innerHTML = `<div>Your passphrase for the encrypted copy. Write it down: without it the copy cannot be opened.</div>
      <code class="mono" style="font-size:15px;" data-passphrase-words>${esc(passphrase)}</code>
      <div class="mut" data-encrypting>Encrypting…</div>`;
    void encryptBackup(accountCode, passphrase, account.id).then((block) => {
      state.emailBlock = block;
      passBox.querySelector('[data-encrypting]')!.textContent = 'The encrypted copy will be in the email’s body.';
      update();
    });
  });
  return wrap;
}
