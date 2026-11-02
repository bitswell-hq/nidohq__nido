/**
 * The `account_code` backups enrollment offers (`docs/email-recovery/spec.md`
 * §5.6): the recovery kit (26 characters to save in a password manager or
 * on paper, with the Nido it recovers and where recovery starts) and,
 * optionally, a passphrase-encrypted copy in the enrollment email's body,
 * so it sits in the user's Sent folder (the account rides inside its
 * ciphertext, never in clear). Which of these a wallet offers is an open
 * question (§13 question 4); this component is the only place that
 * decides, so the choice can change here alone.
 *
 * Saving is not taken on trust: the user types two groups of the code back
 * before enrollment continues.
 */

import { encryptBackup, generatePassphrase, recoveryKitCode } from '@nidohq/email-recovery';
import { esc } from '../html.js';
import { toast } from '../toast.js';
import { KIT_STORAGE_ADVICE, kitCheckGroups, kitCheckMatches, recoveryKitText } from './emailModel.js';
import { el } from './ui.js';

export interface BackupState {
  /** The user typed back part of the saved recovery code correctly. */
  saved: boolean;
  /** The block to put in the enrollment email's body, when the user chose the encrypted copy. */
  emailBlock?: string;
}

const ORDINAL = ['first', 'second', 'third', 'fourth', 'fifth', 'sixth', 'seventh'];

export function backupPanel(
  accountCode: Uint8Array,
  account: { address: string; id: Uint8Array; recoverUrl: string },
  onChange: (s: BackupState) => void,
): HTMLElement {
  const kit = recoveryKitCode(accountCode);
  const groups = kitCheckGroups();
  const state: BackupState = { saved: false };
  const wrap = el(
    'div',
    { class: 'pol-fieldset', 'data-backup': '' },
    `<div style="font-size:13.5px;"><strong>Save your recovery code.</strong> Recovering by email needs it, and Nido never has it. Anyone with this code and access to your inbox could approve a recovery, so keep it as safe as a password.</div>
     <code class="mono" style="font-size:17px;letter-spacing:.04em;" data-kit-code>${esc(kit)}</code>
     <div class="mut" style="font-size:12.5px;word-break:break-all;">It recovers the Nido <code class="mono" data-kit-account>${esc(account.address)}</code>. The kit file holds both, and the address of the recovery page.</div>
     <div style="display:flex;gap:8px;flex-wrap:wrap;">
       <button class="btn ghost sm" type="button" data-copy-kit>Copy</button>
       <a class="btn ghost sm" data-download-kit download="nido-recovery-kit.txt">Download the kit</a>
     </div>
     <div class="mut" style="font-size:12.5px;" data-kit-advice>${esc(KIT_STORAGE_ADVICE)}</div>
     <div style="display:grid;gap:6px;font-size:13px;" data-kit-check>
       <div>To show it is saved, type the <strong>${ORDINAL[groups[0]]}</strong> and <strong>${ORDINAL[groups[1]]}</strong> groups of your code, from where you saved it:</div>
       <div style="display:flex;gap:8px;">
         <input class="input mono" name="kit-group-a" data-kit-group="${groups[0]}" autocomplete="off" spellcheck="false" maxlength="5" style="width:7em;" aria-label="The ${ORDINAL[groups[0]]} group">
         <input class="input mono" name="kit-group-b" data-kit-group="${groups[1]}" autocomplete="off" spellcheck="false" maxlength="5" style="width:7em;" aria-label="The ${ORDINAL[groups[1]]} group">
       </div>
       <div class="mut" data-kit-check-status role="status"></div>
     </div>
     <label class="pol-check"><input type="checkbox" name="email-copy"> Also put an encrypted copy in the enrollment email, so it stays in my Sent folder</label>
     <div data-passphrase hidden style="display:grid;gap:6px;font-size:13px;"></div>`,
  );
  const text = recoveryKitText({ kit, account: account.address, recoverUrl: account.recoverUrl });
  wrap.querySelector<HTMLAnchorElement>('[data-download-kit]')!.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  wrap.querySelector('[data-copy-kit]')!.addEventListener('click', () => {
    void navigator.clipboard.writeText(kit.replace(/ /g, '')).then(() => toast({ msg: 'Recovery code copied', icon: 'check' }));
  });
  const groupA = wrap.querySelector<HTMLInputElement>('[name="kit-group-a"]')!;
  const groupB = wrap.querySelector<HTMLInputElement>('[name="kit-group-b"]')!;
  const checkStatus = wrap.querySelector<HTMLElement>('[data-kit-check-status]')!;
  const update = () => {
    const typed = [groupA.value, groupB.value];
    state.saved = kitCheckMatches(kit, groups, typed);
    const complete = groups.every((g, i) => typed[i]!.replace(/\s+/g, '').length >= kit.split(' ')[g]!.length);
    checkStatus.textContent = state.saved ? 'That matches.' : complete ? 'That does not match the code above. Check the copy you saved.' : '';
    onChange({ ...state });
  };
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
