// A seeded generator of DKIM-signed header blocks around the boundaries of
// the grammars the circuit parses: the From value (spec section 4.5) and the
// DKIM-Signature tag list and h= (spec section 4.3, RFC 6376 section 3.2 and
// 3.5).
//
// Case `i` under seed `s` depends only on (s, i), so any case can be
// regenerated alone. A case starts from an ordinary message and applies one
// family of mutations (sometimes a second one); `FAMILIES` lists them.

import { createHash } from 'node:crypto';

/** A small deterministic generator (xorshift128+ over 64-bit words), seeded from SHA-256 of `seed:index`. */
export function rng(seed, index) {
  const h = createHash('sha256').update(`${seed}:${index}`).digest();
  let s0 = h.readBigUInt64LE(0) | 1n;
  let s1 = h.readBigUInt64LE(8) | 2n;
  const M = (1n << 64n) - 1n;
  const next = () => {
    let x = s0;
    const y = s1;
    s0 = y;
    x = (x ^ (x << 23n)) & M;
    s1 = x ^ y ^ (x >> 17n) ^ (y >> 26n);
    return (s1 + y) & M;
  };
  const r = {
    int: (n) => Number(next() % BigInt(n)),
    chance: (p) => Number(next() % 1000000n) < p * 1000000,
    pick: (a) => a[r.int(a.length)],
    range: (lo, hi) => lo + r.int(hi - lo + 1),
    shuffle: (a) => {
      const out = [...a];
      for (let i = out.length - 1; i > 0; i--) {
        const j = r.int(i + 1);
        [out[i], out[j]] = [out[j], out[i]];
      }
      return out;
    },
  };
  return r;
}

const LAUNCH = ['gmail.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'yahoo.com', 'proton.me', 'protonmail.com', 'fastmail.com', 'gmx.net', 'gmx.de', 'web.de'];
const ATEXT = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~";
const ALNUM = 'abcdefghijklmnopqrstuvwxyz0123456789';
const SPECIALS = ['(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '.', '"'];

const word = (r, n, alphabet = ALNUM) => Array.from({ length: n }, () => r.pick([...alphabet])).join('');

function label(r) {
  return r.pick([
    () => word(r, r.range(1, 10)),
    () => `${word(r, 1)}${word(r, r.range(0, 6), `${ALNUM}-`)}${word(r, 1)}`,
    () => word(r, 63),
    () => word(r, 64),
    () => `-${word(r, 4)}`,
    () => `${word(r, 4)}-`,
    () => `${r.range(0, 999)}`,
    () => `xn--${word(r, 6)}`,
    () => `${word(r, 3)}_${word(r, 3)}`,
    () => '',
    () => word(r, 3).toUpperCase(),
  ])();
}

/** A domain: mostly launch domains, otherwise around RFC 1123's label rules and the 62-octet leaf bound. */
export function domain(r) {
  return r.pick([
    () => r.pick(LAUNCH),
    () => r.pick(LAUNCH),
    () => r.pick(LAUNCH).toUpperCase(),
    () => `${r.pick(LAUNCH)}.`,
    () => `${word(r, r.range(1, 8))}.${r.pick(LAUNCH)}`,
    () => Array.from({ length: r.range(1, 4) }, () => label(r)).join('.'),
    () => `${word(r, 61)}.com`,
    () => `${word(r, 58)}.com`,
    () => `[${r.range(0, 255)}.${r.range(0, 255)}.${r.range(0, 255)}.${r.range(0, 255)}]`,
    () => word(r, 6),
    () => `${word(r, 5)}..com`,
  ])();
}

/** A local part: dot-atoms and their edges, quoted strings, specials, 8-bit octets. */
export function localPart(r) {
  return r.pick([
    () => word(r, r.range(1, 12)),
    () => `${word(r, r.range(1, 6))}.${word(r, r.range(1, 6))}`,
    () => `${word(r, 4)}+${word(r, 4)}`,
    () => word(r, r.range(1, 20), ATEXT),
    () => `.${word(r, 4)}`,
    () => `${word(r, 4)}.`,
    () => `${word(r, 3)}..${word(r, 3)}`,
    () => `"${word(r, 3)} ${word(r, 3)}"`,
    () => `"${word(r, 3)}@${word(r, 3)}"`,
    () => `"${word(r, 3)}\\"${word(r, 2)}"`,
    () => `${word(r, 3)}${r.pick(SPECIALS)}${word(r, 3)}`,
    () => `${word(r, 3)}é${word(r, 2)}`,
    () => word(r, r.range(100, 130)),
    () => '',
    () => word(r, 4).toUpperCase(),
  ])();
}

export const addrSpec = (r, d = domain(r)) => `${localPart(r)}@${d}`;
const plainAddr = (r, d = r.pick(LAUNCH)) => `${word(r, r.range(3, 8))}.${word(r, r.range(3, 8))}@${d}`;

/** RFC 2047 encoded-words, well formed or not, sometimes carrying address-like or angle-bracket text. */
function encodedWord(r, text) {
  const b64 = Buffer.from(text, 'utf8').toString('base64');
  const q = [...Buffer.from(text, 'utf8')].map((c) => (/[A-Za-z0-9]/.test(String.fromCharCode(c)) ? String.fromCharCode(c) : `=${c.toString(16).toUpperCase().padStart(2, '0')}`)).join('');
  return r.pick([
    () => `=?utf-8?B?${b64}?=`,
    () => `=?UTF-8?Q?${q}?=`,
    () => `=?iso-8859-1?q?${q}?=`,
    () => `=?utf-8?B?${b64}`,
    () => `=?utf-8?X?${b64}?=`,
    () => `=?utf-8?Q?${text.replace(/ /g, '_')}?=`,
  ])();
}

/** A display name around the section 4.5 rule (printable ASCII but "<" and ">") and RFC 5322's phrase. */
export function displayName(r, victim) {
  return r.pick([
    () => '',
    () => `${word(r, 5)} ${word(r, 7)}`,
    () => `${word(r, 4)} Q. ${word(r, 6)}`,
    () => `"${word(r, 5)} ${word(r, 5)}"`,
    () => `"${word(r, 3)}, ${word(r, 4)}"`,
    () => `${word(r, 3)}, ${word(r, 4)}`,
    () => `"${word(r, 3)}<${word(r, 3)}"`,
    () => `"${word(r, 3)}>${word(r, 3)}"`,
    () => `"${victim}"`,
    () => victim,
    () => `${victim} via ${word(r, 4)}`,
    () => `"${word(r, 3)}" ${victim}`,
    () => `"${word(r, 3)}\\" <${victim}>"`,
    () => `"${word(r, 3)}\\"" ${word(r, 3)}`,
    () => `(${word(r, 4)}) ${word(r, 4)}`,
    () => `${word(r, 4)} (<${victim}>)`,
    () => `${word(r, 4)} (${word(r, 2)} (${word(r, 2)}) ${word(r, 2)})`,
    () => `${word(r, 4)}: ${word(r, 4)}`,
    () => `${word(r, 4)}; ${word(r, 4)}`,
    () => `${word(r, 4)} @ ${word(r, 4)}`,
    () => encodedWord(r, `${word(r, 4)} ${word(r, 5)}`),
    () => encodedWord(r, victim),
    () => encodedWord(r, `${word(r, 3)} <${victim}>`),
    () => `${encodedWord(r, word(r, 3))} ${encodedWord(r, word(r, 3))}`,
    () => `${word(r, 4)}ü${word(r, 3)}`,
    () => `${word(r, 4)}\t${word(r, 4)}`,
    () => `  ${word(r, 4)}  `,
    () => `${word(r, 3)}\\${word(r, 3)}`,
    () => word(r, r.range(200, 900), `${ALNUM} `),
    () => `${word(r, 3)}"${word(r, 3)}`,
    () => `"${word(r, 3)}`,
  ])();
}

/** A From value: the two section 4.5 forms and everything around them. */
export function fromValue(r, addr, victim) {
  const name = () => displayName(r, victim);
  return r.pick([
    () => addr,
    () => `${name()} <${addr}>`,
    () => `${name()} <${addr}>`,
    () => `${name()}<${addr}>`,
    () => `<${addr}>`,
    () => `${addr} (${word(r, 5)})`,
    () => `${name()} <${addr}> (${word(r, 4)})`,
    () => `${name()} <${addr}>${r.pick(['>', ' x', ',', ';', ' ', '\t', '.'])}`,
    () => `<${addr}>, <${victim}>`,
    () => `${addr}, ${victim}`,
    () => `${victim}, ${addr}`,
    () => `${word(r, 4)}: ${addr};`,
    () => `${word(r, 4)}: ${addr}, ${victim};`,
    () => `${word(r, 4)}:;`,
    () => `<@${word(r, 4)}.example:${addr}>`,
    () => `${name()} < ${addr} >`,
    () => `${name()} <${addr} >`,
    () => `${name()} <<${addr}>>`,
    () => `${name()} <${victim}> <${addr}>`,
    () => `${victim} <${addr}>`,
    () => `"${victim}" <${addr}>`,
    () => `${addr.replace('@', ' @ ')}`,
    () => `${name()} <${addr.replace('@', '@ ')}>`,
    () => `${addr}\u0000`,
    () => `${name()} <${addr}`,
    () => `${name()} ${addr}>`,
    () => `${name()} <${addr}>\r\n <${victim}>`,
    () => `${name()}\r\n <${addr}>`,
    () => `${name()} <${addr}>\r\n\t(${word(r, 3)})`,
    () => `${name()} <${addr.replace('@', '\r\n @')}>`,
    () => '',
  ])();
}

/** One DKIM tag as written: name, value, and the whitespace around them. */
const tag = (name, value, pre = ' ', mid = '') => ({ name, value, pre, mid });

const ORDINARY_H = ['from', 'to', 'subject', 'date', 'message-id'];

/** The family list, each with its weight. */
export const FAMILIES = [
  ['baseline', 2],
  ['from-display', 10],
  ['from-address', 8],
  ['from-structure', 10],
  ['encoded-words', 5],
  ['folding', 6],
  ['duplicated-fields', 8],
  ['field-names', 4],
  ['h-list', 8],
  ['tag-list', 10],
  ['tag-values', 8],
  ['lengths', 6],
  ['octets', 4],
  ['mixed', 11],
];
const WEIGHTED = FAMILIES.flatMap(([f, w]) => Array(w).fill(f));

/**
 * Case `index` under `seed`: `{ family, fields, signature, signatureAt, keyName }`
 * where `fields` are `[name, rawValue]` header fields (folds written as CRLF
 * WSP) and `signature` is the DKIM-Signature tag list with an empty b=.
 */
export function generateCase(seed, index) {
  const r = rng(seed, index);
  const family = r.pick(WEIGHTED);
  const d = r.pick(LAUNCH);
  const victim = plainAddr(r, d);
  const addr = plainAddr(r, d);
  const c = {
    seed,
    index,
    family,
    keyName: 'gmail',
    signatureAt: 0,
    fields: [
      ['From', ` ${word(r, 5)} ${word(r, 6)} <${addr}>`],
      ['To', ` recover@recovery.test`],
      ['Subject', ` ${word(r, 6)} ${word(r, 8)}`],
      ['Date', ' Mon, 2 Nov 2026 10:00:00 +0000'],
      ['Message-ID', ` <${word(r, 20)}@mail.example>`],
      ['MIME-Version', ' 1.0'],
      ['Content-Type', ' text/plain; charset="UTF-8"'],
    ],
    signature: [
      tag('v', '1', ''),
      tag('a', 'rsa-sha256'),
      tag('c', 'relaxed/relaxed'),
      tag('d', d),
      tag('s', 'fuzz'),
      tag('t', '1793613600'),
      tag('h', ORDINARY_H.join(':')),
      tag('bh', 'BH'),
      tag('b', ''),
    ],
  };
  // The original From and Subject fields, held by reference so a renaming
  // mutation does not lose them.
  const [fromField, , subjectField] = c.fields;
  const setFrom = (v) => (fromField[1] = ` ${v}`);
  // A tag an earlier mutation removed or renamed reads as a detached empty
  // tag, so later mutations of it have no effect.
  const tagOf = (n) => c.signature.find((t) => t.name === n) ?? tag(n, '');

  const apply = (fam) => {
    switch (fam) {
      case 'baseline':
        if (r.chance(0.5)) setFrom(addr);
        break;
      case 'from-display':
        setFrom(`${displayName(r, victim)} <${addr}>`);
        break;
      case 'from-address': {
        const a = r.chance(0.3) ? `${localPart(r)}@${d}` : addrSpec(r);
        setFrom(r.chance(0.5) ? a : `${word(r, 4)} <${a}>`);
        if (r.chance(0.7)) tagOf('d').value = a.slice(a.lastIndexOf('@') + 1);
        break;
      }
      case 'from-structure':
        setFrom(fromValue(r, addr, victim));
        break;
      case 'encoded-words':
        setFrom(r.chance(0.5) ? `${encodedWord(r, r.pick([victim, `<${victim}>`, `${word(r, 4)} ${word(r, 4)}`, `"${victim}"`]))} <${addr}>` : `${encodedWord(r, `${word(r, 3)} <${victim}>`)}`);
        if (r.chance(0.3)) subjectField[1] = ` ${encodedWord(r, word(r, 10))}`;
        break;
      case 'folding': {
        const f = r.pick(c.fields);
        const spaces = [...f[1].matchAll(/[ \t]/g)].map((m) => m.index);
        if (spaces.length) {
          const at = r.pick(spaces);
          f[1] = `${f[1].slice(0, at)}\r\n${r.pick([' ', '\t', '  '])}${f[1].slice(at + 1)}`;
        }
        if (r.chance(0.5)) setFrom(`${displayName(r, victim)}\r\n <${addr}>`);
        if (r.chance(0.3)) {
          const t = r.pick(c.signature);
          t.pre = r.pick([' ', '\r\n ', '\r\n\t', '\r\n  ']);
        }
        if (r.chance(0.3)) tagOf('h').value = ORDINARY_H.join(r.pick([':\r\n ', '\r\n :', ':']));
        break;
      }
      case 'duplicated-fields': {
        const name = r.pick(['From', 'Subject', 'From', 'move-signature']);
        const value = name === 'From' ? ` ${r.pick([victim, `<${victim}>`, `${word(r, 3)} <${victim}>`])}` : ` ${word(r, 7)}`;
        if (name === 'move-signature') c.signatureAt = r.pick([c.fields.length, r.int(c.fields.length + 1)]);
        else {
          const at = r.pick([0, c.fields.length, r.int(c.fields.length + 1)]);
          c.fields.splice(at, 0, [name, value]);
          if (r.chance(0.5)) tagOf('h').value += `:${name.toLowerCase()}`;
          if (r.chance(0.2)) tagOf('h').value = tagOf('h').value.replace(`${name.toLowerCase()}:`, '');
        }
        break;
      }
      case 'field-names': {
        const f = r.pick([fromField, subjectField]);
        f[0] = r.pick([f[0].toUpperCase(), f[0].toLowerCase(), `${f[0]} `, `${f[0]}\t`, `X-${f[0]}`, `${f[0]}x`, `Resent-${f[0]}`]);
        if (r.chance(0.5)) c.fields.push([r.pick(['Sender', 'Reply-To', 'X-Original-From', 'Resent-From']), ` <${victim}>`]);
        if (r.chance(0.3)) c.signatureName = r.pick(['dkim-signature', 'DKIM-SIGNATURE', 'Dkim-Signature', 'DKIM-Signature ', 'X-DKIM-Signature']);
        break;
      }
      case 'h-list': {
        const h = tagOf('h');
        h.value = r.pick([
          () => 'From:Subject',
          () => 'FROM:SUBJECT:To',
          () => 'from : subject : to',
          () => 'from:from:subject:subject:to:to',
          () => 'subject:to:date',
          () => 'from:to:date',
          () => 'xfrom:subject',
          () => 'from-x:subject:from',
          () => 'from::subject',
          () => ':from:subject:',
          () => 'subjectx:from:subject',
          () => 'reply-to:from:sender:subject',
          () => `${ORDINARY_H.join(':')}:${Array.from({ length: r.range(1, 40) }, () => word(r, 6)).join(':')}`,
          () => 'from;subject',
          () => 'from subject',
          () => 'From:Subject:DKIM-Signature',
          () => '',
        ])();
        break;
      }
      case 'tag-list': {
        const sig = c.signature;
        r.pick([
          () => (c.signature = [...r.shuffle(sig.filter((t) => t.name !== 'b')), tagOf('b')]),
          () => (c.signature = r.shuffle(sig)),
          () => sig.splice(r.int(sig.length), 0, { ...r.pick(sig.filter((t) => t.name !== 'b' && t.name !== 'bh')) }),
          () => sig.splice(r.int(sig.length), 0, tag(r.pick(['z', 'x-foo', 'q', 'i', 'l', 'g']), r.pick(['dns/txt', `@${d}`, '1', `From:${victim}|Subject:x`, `d=${r.pick(LAUNCH)}`, 'from:subject']))),
          () => sig.splice(r.int(sig.length), 1),
          () => (r.pick(sig).name = r.pick(['V', 'A', 'C', 'D', 'H', 'B', 'S'])),
          () => (r.pick(sig).mid = r.pick([' ', '\t', ' \r\n '])),
          () => (r.pick(sig).pre = r.pick(['', '  ', '\t', ';', ' ; '])),
          () => (c.trailing = r.pick([';', '; ', ';;', ' ;'])),
          () => sig.splice(r.int(sig.length), 0, tag('', '')),
          () => sig.splice(r.int(sig.length), 0, tag(word(r, 2), null)),
        ])();
        break;
      }
      case 'tag-values': {
        const t = r.pick(['v', 'a', 'c', 'd', 'i', 'q', 'l']);
        const values = {
          v: ['1', ' 1', '1 ', '2', '01', 'DKIM1', ''],
          a: ['rsa-sha256', 'RSA-SHA256', 'rsa-sha1', 'ed25519-sha256', 'rsa-sha256 ', 'rsa-sha512', ''],
          c: ['relaxed/relaxed', 'relaxed/simple', 'relaxed', 'simple/relaxed', 'simple', 'RELAXED/relaxed', 'relaxed / relaxed', 'relaxed/relaxed/x', '/relaxed'],
          d: [d.toUpperCase(), ` ${d}`, `${d} `, `${d}.`, `x.${d}`, d.split('.').slice(-1)[0], r.pick(LAUNCH), `${d};`],
          i: [`@${d}`, `${word(r, 4)}@${d}`, `@x.${d}`, `@${r.pick(LAUNCH)}`, victim],
          q: ['dns/txt', 'dns', 'http'],
          l: ['0', '5', '100000', 'x'],
        }[t];
        const existing = c.signature.find((x) => x.name === t);
        if (existing) existing.value = r.pick(values);
        else c.signature.splice(r.int(c.signature.length - 1), 0, tag(t, r.pick(values)));
        break;
      }
      case 'lengths': {
        r.pick([
          () => setFrom(`${word(r, r.range(1000, 1300), `${ALNUM} `)} <${addr}>`),
          () => {
            const localLen = r.range(119 - d.length, 126 - d.length);
            setFrom(`<${word(r, Math.max(1, localLen))}@${d}>`);
          },
          () => {
            c.fields.push(['X-Pad', ` ${word(r, r.range(600, 900))}`]);
            tagOf('h').value += ':x-pad';
          },
          () => c.signature.splice(c.signature.length - 1, 0, tag('z', word(r, r.range(150, 320)))),
          () => {
            for (let k = r.range(5, 9); k > 0; k--) c.signature.splice(c.signature.length - 1, 0, tag(`x${k}`, word(r, 2)));
          },
          () => (tagOf('h').value = `${ORDINARY_H.join(':')}:${Array.from({ length: r.range(20, 60) }, () => 'from').join(':')}`),
        ])();
        break;
      }
      case 'octets': {
        const f = r.pick(c.fields);
        const bad = r.pick(['é', '\u0000', '\u007f', '\u0001', 'ÿ', 'Ã©']);
        const at = r.int(f[1].length + 1);
        f[1] = f[1].slice(0, at) + bad + f[1].slice(at);
        break;
      }
      default:
        break;
    }
  };

  if (family === 'mixed') {
    for (let k = r.range(2, 4); k > 0; k--) apply(r.pick(FAMILIES.map((f) => f[0]).filter((f) => f !== 'mixed' && f !== 'baseline')));
  } else apply(family);
  if (r.chance(0.02)) c.keyName = 'weak';
  return c;
}

/** The DKIM-Signature field's value for a case, with the given b= value. */
export function signatureValue(c, b, bh) {
  const parts = c.signature.map((t) => {
    if (t.name === '' && t.value === '') return t.pre;
    const value = t.name === 'b' ? b : t.name === 'bh' && t.value === 'BH' ? bh : t.value;
    return value === null ? `${t.pre}${t.name}` : `${t.pre}${t.name}${t.mid}=${t.mid}${value}`;
  });
  return parts.join(';') + (c.trailing ?? '');
}
