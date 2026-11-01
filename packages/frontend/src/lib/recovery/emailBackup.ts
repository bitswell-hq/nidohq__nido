/**
 * The `account_code` backups enrollment offers (`docs/email-recovery/spec.md`
 * §5.6): the recovery kit (26 characters to save in a password manager or
 * on paper) and, optionally, a passphrase-encrypted copy in the enrollment
 * email's body, so it sits in the user's Sent folder. Which of these a
 * wallet offers is an open question (§13 question 4); this component is the
 * only place that decides, so the choice can change here alone.
 */

import { encryptBackup, generatePassphrase, recoveryKitCode } from '@nidohq/email-recovery';
import { esc } from '../html.js';
import { toast } from '../toast.js';
import { el } from './ui.js';

export interface BackupState {
  /** The user confirmed they saved at least one backup. */
  saved: boolean;
  /** The block to put in the enrollment email's body, when the user chose the encrypted copy. */
  emailBlock?: string;
}

export function backupPanel(accountCode: Uint8Array, accountId: Uint8Array, onChange: (s: BackupState) => void): HTMLElement {
  const kit = recoveryKitCode(accountCode);
  const state: BackupState = { saved: false };
  const wrap = el(
    'div',
    { class: 'pol-fieldset', 'data-backup': '' },
    `<div style="font-size:13.5px;"><strong>Save your recovery code.</strong> Recovering by email needs it, and Nido never has it. Anyone with this code and access to your inbox could approve a recovery, so keep it as safe as a password.</div>
     <code class="mono" style="font-size:17px;letter-spacing:.04em;" data-kit-code>${esc(kit)}</code>
     <div style="display:flex;gap:8px;flex-wrap:wrap;">
       <button class="btn ghost sm" type="button" data-copy-kit>Copy</button>
       <a class="btn ghost sm" data-download-kit download="nido-recovery-code.txt">Download as a file</a>
     </div>
     <label class="pol-check"><input type="checkbox" name="kit-saved"> I saved my recovery code in a password manager or on paper</label>
     <label class="pol-check"><input type="checkbox" name="email-copy"> Also put an encrypted copy in the enrollment email, so it stays in my Sent folder</label>
     <div data-passphrase hidden style="display:grid;gap:6px;font-size:13px;"></div>`,
  );
  const blob = new Blob([`Nido recovery code\n\n${kit}\n\nKeep this safe. Nido never stores it.\n`], { type: 'text/plain' });
  wrap.querySelector<HTMLAnchorElement>('[data-download-kit]')!.href = URL.createObjectURL(blob);
  wrap.querySelector('[data-copy-kit]')!.addEventListener('click', () => {
    void navigator.clipboard.writeText(kit.replace(/ /g, '')).then(() => toast({ msg: 'Recovery code copied', icon: 'check' }));
  });
  const update = () => {
    const kitSaved = wrap.querySelector<HTMLInputElement>('[name="kit-saved"]')!.checked;
    const passSaved = wrap.querySelector<HTMLInputElement>('[name="passphrase-saved"]')?.checked ?? false;
    state.saved = kitSaved || (Boolean(state.emailBlock) && passSaved);
    onChange({ ...state });
  };
  wrap.querySelector('[name="kit-saved"]')!.addEventListener('change', update);
  const passBox = wrap.querySelector<HTMLElement>('[data-passphrase]')!;
  wrap.querySelector<HTMLInputElement>('[name="email-copy"]')!.addEventListener('change', (e) => {
    const on = (e.target as HTMLInputElement).checked;
    passBox.hidden = !on;
    state.emailBlock = undefined;
    if (!on) return update();
    const passphrase = generatePassphrase();
    passBox.innerHTML = `<div>Your passphrase for the encrypted copy. Write it down: without it the copy cannot be opened.</div>
      <code class="mono" style="font-size:15px;" data-passphrase-words>${esc(passphrase)}</code>
      <div class="mut" data-encrypting>Encrypting…</div>
      <label class="pol-check"><input type="checkbox" name="passphrase-saved"> I wrote the passphrase down</label>`;
    passBox.querySelector('[name="passphrase-saved"]')!.addEventListener('change', update);
    void encryptBackup(accountCode, passphrase, accountId).then((block) => {
      state.emailBlock = block;
      passBox.querySelector('[data-encrypting]')!.textContent = 'The encrypted copy will be in the email’s body.';
      update();
    });
  });
  return wrap;
}
