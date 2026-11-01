#!/usr/bin/env node
// Generates tests/src/vectors.nr, the circuit's test vectors: DKIM-signed
// header blocks (RFC 6376) for honest and malformed emails, signed with
// test-only RSA keys.
//
// The keys are derived deterministically from fixed seeds, so the output is
// reproducible and no private key is stored. They are test keys only and
// must never be registered for a real domain. Signatures are computed with
// BigInt arithmetic (RFC 8017 RSASSA-PKCS1-v1_5) and every honest signature
// is checked with node:crypto's independent verifier before it is written.
//
// The headers follow the published DKIM format: relaxed header
// canonicalization (RFC 6376 section 3.4.2), the DKIM-Signature field
// appended last with an empty b= and no trailing CRLF (section 3.7). Full
// provider fixtures live in packages/email-mocks; these vectors are the
// minimum the circuit tests need.
//
// The recovery Subject carries hex(T), T = P2(DOM_BLIND, digest_hi,
// digest_lo, rho) (docs/email-recovery/spec.md section 4.2). T is computed by
// the circuit's own P2 through tools/blinded_value, so the generator needs
// the pinned nargo: set NARGO, or install it with
// vendor/perch/scripts/zk-toolchain.sh into target/zk-toolchain.
//
// It also writes the Prover.toml inputs of the bench packages.
//
// Usage: node scripts/gen-test-vectors.mjs [--check]
//   --check  regenerate in memory and fail if any generated file differs.

import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, constants, verify } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "tests/src/vectors.nr");
const HEADER_MAX = 1024;
const NARGO =
  process.env.NARGO ?? join(ROOT, "../../target/zk-toolchain/nargo-1.0.0-beta.9/nargo");

// ---------------------------------------------------------------- bigint ---

const hex = (x) => "0x" + x.toString(16);
const bytesToBig = (b) => BigInt("0x" + (Buffer.from(b).toString("hex") || "0"));
const bigToBytes = (x, len) => Buffer.from(x.toString(16).padStart(len * 2, "0"), "hex");

function modpow(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

function modinv(a, m) {
  let [r0, r1, s0, s1] = [a % m, m, 1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1, s0, s1] = [r1, r0 - q * r1, s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("not invertible");
  return ((s0 % m) + m) % m;
}

const bitLength = (x) => x.toString(2).length;

// A counter-mode SHA-256 stream: the deterministic randomness for key
// generation.
function stream(seed) {
  let counter = 0;
  return (nbytes) => {
    const chunks = [];
    let have = 0;
    while (have < nbytes) {
      const c = Buffer.alloc(4);
      c.writeUInt32BE(counter++);
      const block = createHash("sha256").update(seed).update(c).digest();
      chunks.push(block);
      have += block.length;
    }
    return Buffer.concat(chunks).subarray(0, nbytes);
  };
}

const SMALL_PRIMES = (() => {
  const out = [];
  for (let n = 3; n < 2000; n += 2) if (out.every((p) => n % p !== 0)) out.push(n);
  return out.map(BigInt);
})();

function isProbablePrime(n, rand) {
  for (const p of SMALL_PRIMES) if (n % p === 0n) return n === p;
  let d = n - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s++;
  }
  for (let round = 0; round < 40; round++) {
    const a = 2n + (bytesToBig(rand(Math.ceil(bitLength(n) / 8) + 8)) % (n - 3n));
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let i = 1; i < s; i++) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

// The first prime at or above `start` that is below `limit` and coprime to
// 65537 minus one.
function primeFrom(start, limit, rand) {
  let p = start | 1n;
  for (; p < limit; p += 2n) {
    if ((p - 1n) % 65537n !== 0n && isProbablePrime(p, rand)) return p;
  }
  return null;
}

const E = 65537n;

// A test key whose modulus lies in [lo, hi).
function deriveKey(seed, bits, lo, hi) {
  const rand = stream(seed);
  const half = BigInt(bits / 2);
  for (;;) {
    const pStart = (1n << (half - 1n)) | bytesToBig(rand(bits / 16)) | (1n << (half - 2n));
    const p = primeFrom(pStart, 1n << half, rand);
    if (!p) continue;
    const qLo = (lo + p - 1n) / p;
    const qHi = hi / p;
    if (qHi <= qLo) continue;
    const q = primeFrom(qLo + (bytesToBig(rand(bits / 8)) % (qHi - qLo)), qHi, rand);
    if (!q || q === p) continue;
    const n = p * q;
    if (n < lo || n >= hi) continue;
    const d = modinv(E, (p - 1n) * (q - 1n));
    return { n, d, bits };
  }
}

// --------------------------------------------------------------- PKCS#1 ---

const DIGEST_INFO_SHA256 = Buffer.from("3031300d060960864801650304020105000420", "hex");

function emsaPkcs1v15(digest, k) {
  const t = Buffer.concat([DIGEST_INFO_SHA256, digest]);
  const ps = Buffer.alloc(k - t.length - 3, 0xff);
  return Buffer.concat([Buffer.from([0x00, 0x01]), ps, Buffer.from([0x00]), t]);
}

const rawSign = (key, em) => modpow(bytesToBig(em), key.d, key.n);

function signBlock(key, block) {
  const k = key.bits / 8;
  const digest = createHash("sha256").update(block).digest();
  const sig = rawSign(key, emsaPkcs1v15(digest, k));
  const pub = createPublicKey({
    key: {
      kty: "RSA",
      n: bigToBytes(key.n, k).toString("base64url"),
      e: bigToBytes(E, 3).toString("base64url"),
    },
    format: "jwk",
  });
  const ok = verify(
    "sha256",
    block,
    { key: pub, padding: constants.RSA_PKCS1_PADDING },
    bigToBytes(sig, k),
  );
  if (!ok) throw new Error("node:crypto rejected a generated signature");
  return { sig, digest };
}

// 18 little-endian limbs of 120 bits.
function limbs(x) {
  const out = [];
  for (let i = 0; i < 18; i++) {
    out.push(x & ((1n << 120n) - 1n));
    x >>= 120n;
  }
  if (x !== 0n) throw new Error("value does not fit in 18 limbs");
  return out;
}

// noir-bignum v0.7.5's Barrett parameter: floor(2^(2 * 2048 + 4) / N).
const redc = (n) => (1n << 4100n) / n;

// ----------------------------------------------------------------- DKIM ---

// RFC 6376 section 3.4.2: lowercase the name, unfold, collapse whitespace,
// trim, no whitespace around the colon.
function relaxedField(name, value) {
  const v = value
    .replace(/\r\n(?=[ \t])/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/^ /, "")
    .replace(/ $/, "");
  return `${name.toLowerCase().trim()}:${v}`;
}

// RFC 6376 section 3.4.4.
function relaxedBody(body) {
  let lines = body.split("\r\n").map((l) => l.replace(/[ \t]+/g, " ").replace(/ $/, ""));
  while (lines.length && lines[lines.length - 1] === "") lines.pop();
  return lines.length ? lines.join("\r\n") + "\r\n" : "";
}

const bodyHash = (body) =>
  createHash("sha256").update(relaxedBody(body), "latin1").digest("base64");

// A signed header block. `fields` are [name, raw value] in the order the
// signer hashes them; `tags` is the raw DKIM-Signature value with `{bh}` in
// place of the body hash and `b=` empty. `canon` "simple" signs each field
// verbatim apart from a lowercased name, so that a test isolates the check it
// targets rather than the From-field count.
function buildBlock({ fields, tags, canon = "relaxed", body = "Recovery request.\r\n" }) {
  const tagValue = tags.replace("{bh}", bodyHash(body));
  const simple = (n, v) => `${n.toLowerCase()}:${v}`;
  const lines = fields.map(([n, v]) => (canon === "relaxed" ? relaxedField(n, v) : simple(n, v)));
  const dkim = canon === "relaxed" ? relaxedField("DKIM-Signature", tagValue) : simple("DKIM-Signature", tagValue);
  return lines.map((l) => l + "\r\n").join("") + dkim;
}

// ------------------------------------------------------------- vectors ---

const PHRASE = "APPROVE NIDO ACCOUNT RECOVERY ";
const BODY = "Recovery request.\r\n";

// A test statement digest, split as Perch's split_hi_lo, and a test rho.
const DIGEST = createHash("sha256").update("nido email recovery test statement").digest();
const DIGEST_HI = bytesToBig(DIGEST.subarray(0, 16));
const DIGEST_LO = bytesToBig(DIGEST.subarray(16, 32));
const RHO = bytesToBig(createHash("sha256").update("nido email recovery test rho").digest().subarray(0, 31));

const files = {};

// T from the circuit's P2, via `nargo execute` on tools/blinded_value.
function blindedValue(hi, lo, rho) {
  const toml = `digest_hi = "${hex(hi)}"\ndigest_lo = "${hex(lo)}"\nrho = "${hex(rho)}"\n`;
  const path = join(ROOT, "tools/blinded_value/Prover.toml");
  files[path] = toml;
  writeFileSync(path, toml);
  if (!existsSync(NARGO)) throw new Error(`nargo not found at ${NARGO}; set NARGO`);
  const out = execFileSync(NARGO, ["execute", "--package", "blinded_value"], { cwd: ROOT, encoding: "utf8" });
  // nargo prints the output as a signed integer, `Field(-x)` for r - x.
  const m = out.match(/Circuit output: Field\((-?[0-9]+)\)/);
  if (!m) throw new Error(`no circuit output from nargo:\n${out}`);
  const R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001n;
  return ((BigInt(m[1]) % R) + R) % R;
}
const VALUE = blindedValue(DIGEST_HI, DIGEST_LO, RHO).toString(16).padStart(64, "0");

const KEY_A = deriveKey("nido-email-recovery/test-key/a", 2048, 1n << 2047n, (1n << 2047n) + (1n << 2044n));
const KEY_B = deriveKey("nido-email-recovery/test-key/b", 2048, 1n << 2047n, 1n << 2048n);
const KEY_1024 = deriveKey("nido-email-recovery/test-key/1024", 1024, 1n << 1023n, 1n << 1024n);

const GMAIL_TAGS =
  "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=gmail.com; s=20260707; t=1793448000; x=1794052800; darn=nido.example;\r\n" +
  "        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject\r\n" +
  "         :date:message-id:reply-to;\r\n        bh={bh};\r\n        b=";

// The same tags on one line, for vectors signed with simple canonicalization.
const GMAIL_TAGS_FLAT = GMAIL_TAGS.replace(/\r\n +/g, " ").replace(" :date", ":date");
const FLAT_SUBJECT = ` ${PHRASE}${VALUE}`;

const gmailFields = (from, subject = ` ${PHRASE.trim()}\r\n ${VALUE}`) => [
  ["To", " recover@nido.example"],
  ["Subject", subject],
  ["Message-ID", " <CAF1test0001x@mail.gmail.com>"],
  ["Date", " Sat, 31 Oct 2026 12:00:00 +0000"],
  ["From", from],
  ["MIME-Version", " 1.0"],
];
const ALICE = ' "Alice Example" <alice.example@gmail.com>';
// A 124-byte address (ADDR_MAX) with a 62-byte domain, and one byte longer.
const DOMAIN_62 = "y".repeat(58) + ".com";
const ADDR_124 = "z".repeat(61) + "@" + DOMAIN_62;
const ADDR_125 = "z".repeat(62) + "@" + DOMAIN_62;

const OUTLOOK_TAGS =
  "v=1; a=rsa-sha256; c=relaxed/relaxed; d=outlook.com;\r\n s=selector1;\r\n" +
  " h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;\r\n" +
  " bh={bh};\r\n b=";

const gmail = (overrides = {}) => ({
  fields: gmailFields(ALICE),
  tags: GMAIL_TAGS,
  ...overrides,
});
const withTags = (from, to) => GMAIL_TAGS.replace(from, to);

// Each vector: a header block signed by `key` (KEY_A unless stated).
const VECTORS = {
  // Honest shapes.
  GMAIL: gmail(),
  OUTLOOK: {
    fields: [
      ["From", " bob-smith_99@outlook.com"],
      ["Date", " Sat, 31 Oct 2026 12:00:00 +0000"],
      ["Subject", ` ${PHRASE}${VALUE}`],
      ["Message-ID", " <AM0PR01MB0001.eurprd01.prod.outlook.com>"],
      ["Content-Type", " text/plain; charset=\"us-ascii\""],
      ["MIME-Version", " 1.0"],
    ],
    tags: OUTLOOK_TAGS,
  },
  UPPERCASE_FROM_DOMAIN: gmail({ fields: gmailFields(" Alice <alice.example@GMAIL.com>") }),
  ATEXT_LOCAL_PART: gmail({
    fields: gmailFields(" Dana <o'brien!#$%&*+-/=?^_`{|}~x@yahoo.com>"),
    tags: withTags("d=gmail.com", "d=yahoo.com"),
  }),
  DIGIT_LEADING_LABEL: gmail({ fields: gmailFields(" Erin <erin@123mail.org>"), tags: withTags("d=gmail.com", "d=123mail.org") }),
  ADDR_MAX_LENGTH: gmail({ fields: gmailFields(` <${ADDR_124}>`), tags: withTags("d=gmail.com", `d=${DOMAIN_62}`) }),
  PLUS_TAG: gmail({ fields: gmailFields(" Carol <carol.o-neil+nido_1@fastmail.com>"), tags: withTags("d=gmail.com", "d=fastmail.com") }),
  LONG_DISPLAY_NAME: gmail({ fields: gmailFields(` "${"A".repeat(300)}" <alice.example@gmail.com>`) }),
  ADDRESS_LIKE_DISPLAY_NAME: gmail({ fields: gmailFields(" victim@gmail.com <attacker@gmail.com>") }),
  SEMICOLON_FREE_END: gmail({ tags: GMAIL_TAGS.replace("b=", "b=;") }),
  REGEX_RESET: gmail({
    fields: [...gmailFields(ALICE), ["Cc", " ÿfrom:<victim@gmail.com>"]],
  }),

  // From spoofing.
  DECOY_IN_DISPLAY_NAME: gmail({ fields: gmailFields(` "x <victim@gmail.com> ${"A".repeat(300)}" <attacker@gmail.com>`) }),
  QUOTED_LOCAL_PART: gmail({ fields: gmailFields(' "victim@gmail.com"@gmail.com') }),
  FROM_THEN_TO_ANGLE: gmail({
    fields: [
      ["From", " attacker@gmail.com"],
      ["To", " <victim@gmail.com>"],
      ...gmailFields(ALICE).filter(([n]) => n !== "From" && n !== "To"),
    ],
  }),
  TWO_FROM: gmail({ fields: [...gmailFields(ALICE), ["From", " victim@gmail.com"]] }),
  TWO_SUBJECT: gmail({ fields: [...gmailFields(ALICE), ["Subject", ` ${PHRASE}${"0".repeat(64)}`]] }),
  NO_FROM: gmail({ fields: gmailFields(ALICE).filter(([n]) => n !== "From") }),
  FOLDED_FROM_SIMPLE: gmail({
    canon: "simple",
    fields: gmailFields(' ":attacker@gmail.com>"\r\n <alice.example@gmail.com>', FLAT_SUBJECT),
    tags: GMAIL_TAGS_FLAT.replace("c=relaxed/relaxed", "c=simple/simple"),
  }),
  SIMPLE_CANON: gmail({
    canon: "simple",
    fields: gmailFields(ALICE, FLAT_SUBJECT),
    tags: GMAIL_TAGS_FLAT.replace("c=relaxed/relaxed", "c=simple/simple"),
  }),
  RELAXED_SIMPLE: gmail({ tags: withTags("c=relaxed/relaxed", "c=relaxed/simple") }),
  RELAXED_BARE: gmail({ tags: withTags("c=relaxed/relaxed", "c=relaxed") }),
  BARE_LF: gmail({ fields: [...gmailFields(ALICE), ["X-Note", " a\nfrom:victim@gmail.com"]] }),
  BAD_LOCAL_CHAR: gmail({ fields: gmailFields(" Alice <alice,x@gmail.com>") }),
  DOUBLE_DOT: gmail({ fields: gmailFields(" Alice <alice..x@gmail.com>") }),
  HYPHEN_LABEL: gmail({ fields: gmailFields(" Alice <alice@-gmail.com>"), tags: withTags("d=gmail.com", "d=-gmail.com") }),
  HYPHEN_END_LABEL: gmail({ fields: gmailFields(" Alice <alice@gmail-.com>"), tags: withTags("d=gmail.com", "d=gmail-.com") }),
  LONG_LABEL: gmail({ fields: gmailFields(` <a@${"x".repeat(64)}.com>`), tags: withTags("d=gmail.com", `d=${"x".repeat(64)}.com`) }),
  DOMAIN_TOO_LONG: gmail({ fields: gmailFields(` <a@${"x".repeat(59)}.com>`), tags: withTags("d=gmail.com", `d=${"x".repeat(59)}.com`) }),
  ADDR_TOO_LONG: gmail({ fields: gmailFields(` <${ADDR_125}>`), tags: withTags("d=gmail.com", `d=${DOMAIN_62}`) }),
  NON_ASCII_DISPLAY_NAME: gmail({ fields: gmailFields(" Zo\u00c3\u00ab <alice.example@gmail.com>") }),

  // DKIM-Signature tags.
  L_TAG: gmail({ tags: withTags("c=relaxed/relaxed;", "c=relaxed/relaxed; l=20;") }),
  L_TAG_SPACED: gmail({ tags: withTags("c=relaxed/relaxed;", "c=relaxed/relaxed; l =20;") }),
  THIRD_PARTY_D: gmail({ tags: withTags("d=gmail.com", "d=gmail-com.20230601.gappssmtp.com") }),
  SUBDOMAIN_D: gmail({ tags: withTags("d=gmail.com", "d=mail.gmail.com") }),
  UPPERCASE_D: gmail({ tags: withTags("d=gmail.com", "d=Gmail.com") }),
  BH_IN_Z: gmail({ tags: withTags("darn=nido.example;", "darn=nido.example; z=Subject:bh=" + "A".repeat(43) + "=;") }),
  DUPLICATE_BH: gmail({ tags: withTags("        b=", "        bh=" + "A".repeat(43) + "=;\r\n        b=") }),
  BH_ILLEGAL_CHAR: gmail({ tags: GMAIL_TAGS.replace("bh={bh}", "bh=" + "A".repeat(20) + "#" + "A".repeat(22) + "=") }),
  SHA1: gmail({ tags: withTags("a=rsa-sha256", "a=rsa-sha1") }),
  V2: gmail({ tags: withTags("v=1", "v=2") }),
  B_NOT_EMPTY: gmail({ tags: GMAIL_TAGS.replace(/b=$/, "b=AAAA") }),
  H_WITHOUT_FROM: gmail({ tags: withTags(":from:mime-version:from:", ":mime-version:") }),
  H_WITHOUT_SUBJECT: gmail({ tags: withTags("h=to:subject:", "h=to:").replace(":cc:subject\r\n", ":cc\r\n") }),
  NO_T: gmail({ tags: withTags(" t=1793448000;", "") }),
  LAST_NOT_DKIM: null, // built below: a field after the DKIM-Signature

  // Subject.
  SUBJECT_UPPER_HEX: gmail({ fields: gmailFields(ALICE, ` ${PHRASE}${VALUE.toUpperCase()}`) }),
  SUBJECT_ENCODED_WORD: gmail({ fields: gmailFields(ALICE, ` =?UTF-8?Q?APPROVE_NIDO_RECOVERY_?= ${VALUE}`) }),
  SUBJECT_TRAILING: gmail({ fields: gmailFields(ALICE, ` ${PHRASE}${VALUE} please`) }),
  SUBJECT_REPLY: gmail({ fields: gmailFields(ALICE, ` Re: ${PHRASE}${VALUE}`) }),
};

const blocks = {};
for (const [name, spec] of Object.entries(VECTORS)) {
  if (spec) blocks[name] = buildBlock(spec);
}
// A block whose last line is not the DKIM-Signature field.
blocks.LAST_NOT_DKIM = blocks.GMAIL + "\r\nx-trailer:1";
// The block ends with CRLF.
blocks.TRAILING_CRLF = blocks.GMAIL + "\r\n";

const signed = {};
for (const [name, block] of Object.entries(blocks)) {
  const bytes = Buffer.from(block, "latin1");
  if (bytes.length > HEADER_MAX) throw new Error(`${name}: ${bytes.length} bytes exceeds ${HEADER_MAX}`);
  signed[name] = { bytes, ...signBlock(KEY_A, bytes) };
}

// GMAIL signed by another key, and by a 1024-bit key. Key B's modulus is
// larger than key A's, so key A's signatures are below it and a check under
// key B reaches the encoding comparison.
if (KEY_B.n <= KEY_A.n) throw new Error("key B's modulus must exceed key A's; choose another seed");
const gmailBytes = signed.GMAIL.bytes;
const byB = signBlock(KEY_B, gmailBytes);
const by1024 = signBlock(KEY_1024, gmailBytes);

// sig + N, which must stay below 2^2048 for the test to isolate the check.
const sigPlusN = signed.GMAIL.sig + KEY_A.n;
if (sigPlusN >= 1n << 2048n) throw new Error("sig + N does not fit in 2048 bits; choose another seed");

// An unsigned field prepended to the GMAIL block, with GMAIL's signature.
const UNSIGNED_PREPENDED = Buffer.concat([Buffer.from("reply-to:victim@gmail.com\r\n"), gmailBytes]);

// Raw RSA signatures over non-conforming encodings of GMAIL's digest.
const k = 256;
const goodEm = emsaPkcs1v15(signed.GMAIL.digest, k);
const badEm = {
  PS_BYTE: Buffer.from(goodEm).fill(0xfe, 100, 101),
  BLOCK_TYPE_2: Buffer.concat([Buffer.from([0x00, 0x02]), goodEm.subarray(2)]),
  SHA1_PREFIX: Buffer.concat([
    goodEm.subarray(0, 205),
    Buffer.from("3021300906052b0e03021a05000414", "hex"),
    Buffer.alloc(4, 0xff),
    goodEm.subarray(224),
  ]),
  NO_SEPARATOR: Buffer.from(goodEm).fill(0xff, 204, 205),
};
for (const [n, em] of Object.entries(badEm)) {
  if (em.length !== k) throw new Error(`${n}: encoding is ${em.length} bytes`);
}

// The DKIM key registry's fixture moduli, whose key hashes, leaves and roots
// contracts/dkim-registry/src/test.rs pins from the host's Poseidon2.
const REGISTRY_INPUTS = join(ROOT, "../../contracts/dkim-registry/vectors/src/inputs.nr");
const registryModulus = (name) => {
  const src = readFileSync(REGISTRY_INPUTS, "utf8");
  const m = src.match(new RegExp(`pub global ${name}: \\[u8; 256\\] = \\[([^\\]]*)\\]`));
  if (!m) throw new Error(`${name} not found in ${REGISTRY_INPUTS}`);
  const bytes = m[1].split(",").map((x) => x.trim()).filter(Boolean).map((x) => Number(x));
  if (bytes.length !== 256) throw new Error(`${name} has ${bytes.length} bytes`);
  return bytesToBig(Buffer.from(bytes));
};

// The body for the body-hash component.
const bodyCanonical = relaxedBody(BODY);

// ---------------------------------------------------------------- output ---

const limbArray = (x) => `[${limbs(x).map(hex).join(", ")}]`;
const byteArray = (b) => `[${[...b].join(", ")}]`;

function noirString(bytes) {
  let s = "";
  for (const c of bytes) {
    if (c === 0x0d) s += "\\r";
    else if (c === 0x0a) s += "\\n";
    else if (c === 0x09) s += "\\t";
    else if (c === 0x22) s += '\\"';
    else if (c === 0x5c) s += "\\\\";
    else if (c >= 0x20 && c < 0x7f) s += String.fromCharCode(c);
    else return null;
  }
  return `"${s}"`;
}

function bytesGlobal(name, bytes) {
  const str = noirString(bytes);
  return str
    ? `pub global ${name}: str<${bytes.length}> = ${str};`
    : `pub global ${name}: [u8; ${bytes.length}] = ${byteArray(bytes)};`;
}

const out = [];
out.push("// Generated by scripts/gen-test-vectors.mjs. Do not edit.");
out.push("//");
out.push("// Test-only keys and DKIM-signed header blocks. The keys are derived from");
out.push("// fixed seeds by the generator and must never be registered for a domain.");
out.push("");
out.push(`pub global PHRASE: str<${PHRASE.length}> = "${PHRASE}";`);
out.push(`pub global VALUE: str<${VALUE.length}> = "${VALUE}";`);
out.push(`pub global DIGEST_HI: Field = ${hex(DIGEST_HI)};`);
out.push(`pub global DIGEST_LO: Field = ${hex(DIGEST_LO)};`);
out.push(`pub global RHO: Field = ${hex(RHO)};`);
out.push("");
for (const [name, key] of [["KEY_A", KEY_A], ["KEY_B", KEY_B], ["KEY_1024", KEY_1024]]) {
  out.push(`pub global ${name}_MODULUS: [u128; 18] = ${limbArray(key.n)};`);
  // The Barrett parameter exists only for 2048-bit moduli.
  if (key.bits === 2048) out.push(`pub global ${name}_REDC: [u128; 18] = ${limbArray(redc(key.n))};`);
}
out.push("");
for (const [name, v] of Object.entries(signed)) {
  out.push(bytesGlobal(`${name}_HEADER`, v.bytes));
  out.push(`pub global ${name}_SIG: [u128; 18] = ${limbArray(v.sig)};`);
}
out.push("");
for (const x of ["A", "B", "C"]) {
  out.push(`pub global REGISTRY_MODULUS_${x}: [u128; 18] = ${limbArray(registryModulus(`MODULUS_${x}`))};`);
}
out.push(`pub global GMAIL_SIG_BY_KEY_B: [u128; 18] = ${limbArray(byB.sig)};`);
out.push(`pub global GMAIL_SIG_BY_KEY_1024: [u128; 18] = ${limbArray(by1024.sig)};`);
out.push(`pub global GMAIL_SIG_PLUS_N: [u128; 18] = ${limbArray(sigPlusN)};`);
out.push(`pub global GMAIL_DIGEST: [u8; 32] = ${byteArray(signed.GMAIL.digest)};`);
out.push(`pub global GMAIL_ENCODING: [u128; 18] = ${limbArray(bytesToBig(goodEm))};`);
out.push(bytesGlobal("UNSIGNED_PREPENDED_HEADER", UNSIGNED_PREPENDED));
for (const [n, em] of Object.entries(badEm)) {
  out.push(`pub global BAD_ENCODING_${n}_SIG: [u128; 18] = ${limbArray(rawSign(KEY_A, em))};`);
}
out.push("");
out.push(bytesGlobal("BODY", Buffer.from(bodyCanonical, "latin1")));
out.push(`pub global BODY_HASH_B64: str<44> = "${bodyHash(BODY)}";`);
out.push("");

files[OUT] = out.join("\n");

// Bench inputs: the GMAIL vector, its body, and the spec hashes' inputs.
const tomlBytes = (b) => `[${[...b].join(", ")}]`;
const tomlLimbs = (x) => `[${limbs(x).map((l) => `"${hex(l)}"`).join(", ")}]`;
const boundedVec = (name, b, max) =>
  `[${name}]\nstorage = ${tomlBytes(Buffer.concat([b, Buffer.alloc(max - b.length)]))}\nlen = ${b.length}\n`;
const keyToml = `modulus = ${tomlLimbs(KEY_A.n)}\nredc = ${tomlLimbs(redc(KEY_A.n))}\nsignature = ${tomlLimbs(signed.GMAIL.sig)}\n`;
const bench = (name) => join(ROOT, `bench/${name}/Prover.toml`);
const headerToml = boundedVec("header", gmailBytes, HEADER_MAX);
for (const name of ["header_sha_1024", "header_scan_1024", "header_from_1024", "header_tags_1024", "header_parse_1024"]) {
  files[bench(name)] = headerToml;
}
files[bench("dkim_header_1024")] = keyToml + headerToml;
files[bench("rsa_2048")] = keyToml + `digest = ${tomlBytes(signed.GMAIL.digest)}\n`;
for (const max of [1024, 4096]) {
  files[bench(`body_hash_${max}`)] =
    `body_hash_b64 = ${tomlBytes(Buffer.from(bodyHash(BODY)))}\n` + boundedVec("body", Buffer.from(bodyCanonical, "latin1"), max);
}
files[bench("spec_hashes")] =
  `account_code = "${hex(0x0123456789abcdef0123456789abcdefn)}"\n` +
  `modulus = ${tomlLimbs(KEY_A.n)}\n` +
  `index = "0x5"\n` +
  `siblings = [${Array.from({ length: 16 }, (_, i) => `"${hex(BigInt(i + 1))}"`).join(", ")}]\n` +
  `digest_hi = "${hex(DIGEST_HI)}"\ndigest_lo = "${hex(DIGEST_LO)}"\nrho = "${hex(RHO)}"\n` +
  `value = ${tomlBytes(Buffer.from(VALUE))}\n` +
  boundedVec("address", Buffer.from("alice.example@gmail.com"), 124) +
  boundedVec("domain", Buffer.from("gmail.com"), 62);

if (process.argv.includes("--check")) {
  const stale = Object.entries(files).filter(([path, text]) => !existsSync(path) || readFileSync(path, "utf8") !== text);
  if (stale.length) {
    console.error(`stale generated files (run node scripts/gen-test-vectors.mjs):\n${stale.map(([p]) => p).join("\n")}`);
    process.exit(1);
  }
  console.log("generated files are up to date");
} else {
  for (const [path, text] of Object.entries(files)) writeFileSync(path, text);
  console.log(`wrote ${Object.keys(signed).length} signed headers and ${Object.keys(files).length - 1} input files`);
}
