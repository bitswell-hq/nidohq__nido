import { describe, expect, it } from 'vitest';
import { canonBody, canonHeader } from '../src/canon.js';
import { selectSignedHeaders } from '../src/dkim.js';
import { parseMessage } from '../src/message.js';

// RFC 6376 section 3.4.6, the canonicalization example.
const EXAMPLE = 'A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n';

describe('canonicalization (RFC 6376 section 3.4.6 example)', () => {
  const message = parseMessage(EXAMPLE);

  it('relaxed header', () => {
    expect(message.headers.map((h) => canonHeader(h, 'relaxed')).join('')).toBe('a:X\r\nb:Y Z\r\n');
  });

  it('relaxed body', () => {
    expect(canonBody(message.body, 'relaxed')).toBe(' C\r\nD E\r\n');
  });

  it('simple header', () => {
    expect(message.headers.map((h) => canonHeader(h, 'simple')).join('')).toBe('A: X\r\nB : Y\t\r\n\tZ  \r\n');
  });

  it('simple body', () => {
    expect(canonBody(message.body, 'simple')).toBe(' C \r\nD \t E\r\n');
  });

  it('empty bodies (sections 3.4.3, 3.4.4)', () => {
    expect(canonBody('', 'simple')).toBe('\r\n');
    expect(canonBody('', 'relaxed')).toBe('');
    expect(canonBody('\r\n\r\n', 'relaxed')).toBe('');
    expect(canonBody('x', 'relaxed')).toBe('x\r\n');
  });
});

describe('h= header selection (RFC 6376 section 5.4.2)', () => {
  const message = parseMessage('Subject: first\r\nFrom: a@x.test\r\nSubject: second\r\n\r\n');

  it('takes repeated names bottom-up', () => {
    expect(selectSignedHeaders(message.headers, ['subject', 'subject']).map((h) => h.raw)).toEqual([
      'Subject: second',
      'Subject: first',
    ]);
  });

  it('signs nothing for a name with no instance left', () => {
    expect(selectSignedHeaders(message.headers, ['from', 'from', 'to']).map((h) => h.raw)).toEqual(['From: a@x.test']);
  });
});
