/**
 * Contract addresses as Stellar StrKeys (SEP-23): version byte `2 << 3`
 * (`C...`), the 32-byte contract id, and a CRC16-XModem checksum,
 * little-endian, all in RFC 4648 base32 without padding.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const CONTRACT_VERSION = 2 << 3;

function crc16xmodem(bytes: Uint8Array): number {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc;
}

function base32Decode(s: string): Uint8Array {
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const c of s) {
    const v = ALPHABET.indexOf(c);
    if (v < 0) throw new Error('not base32');
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (bits >= 5 || (value & ((1 << bits) - 1)) !== 0) throw new Error('non-canonical base32');
  return Uint8Array.from(out);
}

function base32Encode(b: Uint8Array): string {
  let s = '';
  let bits = 0;
  let value = 0;
  for (const x of b) {
    value = (value << 8) | x;
    bits += 8;
    while (bits >= 5) {
      s += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) s += ALPHABET[(value << (5 - bits)) & 31];
  return s;
}

/** The 32-byte contract id of a `C...` address; throws on anything else. */
export function contractIdFromStrkey(address: string): Uint8Array {
  if (address.length !== 56) throw new Error('not a contract address');
  const raw = base32Decode(address);
  if (raw.length !== 35 || raw[0] !== CONTRACT_VERSION) throw new Error('not a contract address');
  const crc = crc16xmodem(raw.subarray(0, 33));
  if (raw[33] !== (crc & 0xff) || raw[34] !== crc >> 8) throw new Error('bad StrKey checksum');
  return raw.slice(1, 33);
}

export function strkeyFromContractId(id: Uint8Array): string {
  if (id.length !== 32) throw new Error('contract id is 32 bytes');
  const body = new Uint8Array(33);
  body[0] = CONTRACT_VERSION;
  body.set(id, 1);
  const crc = crc16xmodem(body);
  const raw = new Uint8Array(35);
  raw.set(body);
  raw[33] = crc & 0xff;
  raw[34] = crc >> 8;
  return base32Encode(raw);
}
