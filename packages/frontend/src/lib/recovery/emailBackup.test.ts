// The recovery kit step of enrollment (docs/email-recovery/spec.md §5.6): the
// code leaves the screen before two groups of it are typed back, so the
// check cannot be passed by reading the page; on an iPhone, printing comes
// first and the page says where a download goes.
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../toast.js', () => ({ toast: vi.fn() }));

import { backupPanel, type BackupState } from './emailBackup';

const ACCOUNT = 'C'.padEnd(56, 'A');
const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
const DESKTOP = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36';

function panel(ua = DESKTOP) {
  const states: BackupState[] = [];
  const el = backupPanel(new Uint8Array(16).fill(7), { address: ACCOUNT, id: new Uint8Array(32), apex: { scheme: 'https:', host: 'nido.fyi' } }, (s) => states.push(s), ua);
  document.body.replaceChildren(el);
  return { el, states };
}

beforeEach(() => {
  URL.createObjectURL = vi.fn(() => 'blob:kit');
});

describe('the recovery kit step', () => {
  it('hides the code while two groups of it are typed back from where it was saved', () => {
    const { el, states } = panel();
    const code = el.querySelector('[data-kit-code]')!.textContent!;
    expect(code.replace(/ /g, '')).toMatch(/^[A-Z2-7]{26}$/);
    expect(el.querySelector<HTMLElement>('[data-kit-check]')!.hidden).toBe(true);

    el.querySelector<HTMLButtonElement>('[data-kit-saved-now]')!.click();
    expect(el.querySelector<HTMLElement>('[data-kit-save]')!.hidden).toBe(true);
    expect(el.textContent).not.toContain(code);
    for (const name of ['kit-group-a', 'kit-group-b']) {
      const input = el.querySelector<HTMLInputElement>(`[name="${name}"]`)!;
      input.value = code.split(' ')[Number(input.dataset.kitGroup)]!;
      input.dispatchEvent(new Event('input'));
    }
    expect(states.at(-1)!.saved).toBe(true);

    el.querySelector<HTMLButtonElement>('[data-kit-show-again]')!.click();
    expect(el.querySelector('[data-kit-code]')!.textContent).toBe(code);
    expect(states.at(-1)!.saved).toBe(false);
  });

  it('prints first on an iPhone, and says a download goes to iCloud Drive', () => {
    const phone = panel(IPHONE).el;
    const buttons = [...phone.querySelectorAll('[data-print-kit], [data-download-kit]')];
    expect(buttons[0]!.matches('[data-print-kit]')).toBe(true);
    expect(buttons[0]!.classList.contains('primary')).toBe(true);
    expect(phone.querySelector('[data-kit-device-note]')!.textContent).toMatch(/iCloud Drive/);
    const desktop = panel(DESKTOP).el;
    expect(desktop.querySelector('[data-download-kit]')!.classList.contains('primary')).toBe(true);
    expect(desktop.querySelector('[data-kit-device-note]')).toBeNull();
  });
});
