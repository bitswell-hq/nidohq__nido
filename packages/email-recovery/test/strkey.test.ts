import { StrKey } from '@stellar/stellar-sdk';
import { describe, expect, it } from 'vitest';
import { contractIdFromStrkey, strkeyFromContractId } from '../src/strkey.js';

describe('contract StrKeys', () => {
  it('agree with the Stellar SDK both ways', () => {
    for (let i = 0; i < 20; i++) {
      const id = Buffer.from(Array.from({ length: 32 }, (_, j) => (i * 37 + j * 11) & 0xff));
      const s = StrKey.encodeContract(id);
      expect(strkeyFromContractId(id)).toBe(s);
      expect(Buffer.from(contractIdFromStrkey(s))).toEqual(id);
    }
  });

  it('refuses account addresses, bad checksums and wrong lengths', () => {
    const s = StrKey.encodeContract(Buffer.alloc(32, 7));
    expect(() => contractIdFromStrkey(StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 7)))).toThrow();
    const last = s[s.length - 2] === 'A' ? 'B' : 'A';
    expect(() => contractIdFromStrkey(s.slice(0, -2) + last + s.slice(-1))).toThrow();
    expect(() => contractIdFromStrkey(s.slice(0, -1))).toThrow();
  });
});
