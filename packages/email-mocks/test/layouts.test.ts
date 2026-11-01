/**
 * Each provider's signature layout against signatures observed in public
 * mailing-list archives (test/observed-signature-layouts.json: the h=
 * list, tag order and physical line lengths of each, with its source).
 * Replaying the observed tag values through the layout must give the same
 * line breaks; generated signatures must use the observed tag order.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseTags } from '../src/dkim.js';
import { generateEmail } from '../src/generate.js';
import { PROVIDERS } from '../src/providers/index.js';
import type { ProviderId } from '../src/providers/types.js';

interface Observed {
  provider: ProviderId;
  field: string;
  tagOrder: string[];
  d: string;
  s: string;
  h: string;
  darnLength: number | null;
  iLength: number | null;
  lineLengths: number[];
  source: string;
  messageId: string;
}

const observed: Observed[] = JSON.parse(readFileSync(new URL('./observed-signature-layouts.json', import.meta.url), 'utf8'));

function signerFor(o: Observed) {
  const signer = PROVIDERS[o.provider].signers.find((s) => s.fieldName.toLowerCase() === o.field.toLowerCase());
  if (!signer) throw new Error(`no ${o.field} signer for ${o.provider}`);
  return signer;
}

describe('layouts reproduce observed line breaks', () => {
  for (const o of observed) {
    it(`${o.provider} ${o.field} d=${o.d} (${o.messageId})`, () => {
      const values: Record<string, string> = {
        v: '1', a: 'rsa-sha256', c: 'relaxed/relaxed', d: o.d, s: o.s, t: '1234567890', x: '1234567890', h: o.h,
        darn: 'r'.repeat(o.darnLength ?? 0), i: 'f'.repeat(o.iLength ?? 0),
      };
      // Tags in the order the signer emits them (bh and b last); the layout places them.
      const signed = generateEmail({ provider: o.provider, from: `a@${PROVIDERS[o.provider].domains[0]}`, subject: 's', body: 'b' });
      const sig = signed.signatures.find((s) => s.fieldName.toLowerCase() === o.field.toLowerCase())!;
      const emitted = [...parseTags(sig.field.slice(sig.field.indexOf(':') + 1)).keys()].filter((n) => n !== 'bh' && n !== 'b');
      const tags: Array<[string, string]> = emitted
        .filter((n) => o.tagOrder.includes(n))
        .map((n) => [n, values[n]!]);
      const signer = signerFor(o);
      const text = `${o.field}:${signer.layout([...tags, ['bh', 'x'.repeat(44)], ['b', 'x'.repeat(344)]])}`;
      expect(text.split('\r\n').map((l) => l.length)).toEqual(o.lineLengths);
    });
  }
});

describe('generated signatures use the observed tag order', () => {
  for (const id of Object.keys(PROVIDERS) as ProviderId[]) {
    for (const signer of PROVIDERS[id].signers) {
      const o = observed.find((x) => x.provider === id && x.field.toLowerCase() === signer.fieldName.toLowerCase());
      if (!o) continue;
      it(`${id} ${signer.fieldName}`, () => {
        const email = generateEmail({ provider: id, from: `a@${PROVIDERS[id].domains[0]}`, subject: 's', body: 'b' });
        const sig = email.signatures.find((s) => s.fieldName === signer.fieldName)!;
        expect(sig.field.startsWith(`${o.field}:`)).toBe(true);
        expect([...parseTags(sig.field.slice(sig.field.indexOf(':') + 1)).keys()]).toEqual(o.tagOrder);
      });
    }
  }
});
