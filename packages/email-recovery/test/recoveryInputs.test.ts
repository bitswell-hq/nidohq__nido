import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { PROVIDERS, buildAttacks, defaultAttackInput, generateEmail, testKey } from '@nidohq/email-mocks';
import { Noir } from '@noir-lang/noir_js';
import { beforeAll, describe, expect, test } from 'vitest';
import {
  DkimHeaderError,
  HEADER_MAX,
  LAUNCH_DOMAINS,
  RECOVERY_PHRASE,
  addressCommitment,
  alignedSignatures,
  dkimSignatures,
  emptySubtrees,
  encodeRecoveryEmail,
  initHashes,
  keyHash,
  limbs,
  merkleRoot,
  noirInputs,
  parseMessage,
  pinSalt,
  proverToml,
  publicInputBytes,
  recoverySubject,
  registryLeaf,
  signedHeaderBlock,
  treePath,
} from '../src/index.js';

const repo = (path: string) => new URL(`../../../${path}`, import.meta.url);
const circuit = JSON.parse(readFileSync(repo('circuits/email-recovery/artifacts/recovery.json'), 'utf8'));
const vectors = readFileSync(repo('circuits/email-recovery/tests/src/vectors.nr'), 'utf8');

/** A `[u128; 18]` limb global of the circuit's test vectors, as an integer. */
function vectorLimbs(name: string): bigint {
  const m = new RegExp(`pub global ${name}: \\[u128; 18\\] = \\[([^\\]]+)\\]`).exec(vectors);
  if (!m) throw new Error(`no ${name} in vectors.nr`);
  return m[1]!
    .split(',')
    .map((x) => BigInt(x.trim()))
    .reduce((acc, limb, i) => acc + (limb << (120n * BigInt(i))), 0n);
}

const sha256 = (data: Uint8Array) => new Uint8Array(createHash('sha256').update(data).digest());
const text = (s: string) => new TextEncoder().encode(s);

const ACCOUNT_CODE = 0x0102030405060708090a0b0c0d0e0f10n;
const RHO = 0x36364934bfecde233a74c7671765676f7e2e23f6ff3dc3505b5a294a5d6en;
const STATEMENT = text('TEST-ONLY recovery statement');
const DIGEST = sha256(STATEMENT);

/** The provider's honest recovery email from `from`, and its aligned signer's key. */
function honestEmail(provider: keyof typeof PROVIDERS, from: string, displayName?: string) {
  const email = generateEmail({ provider, from, displayName, subject: recoverySubject(DIGEST, RHO), body: 'Recovery.\r\n' });
  const domain = from.slice(from.indexOf('@') + 1);
  const aligned = email.signatures.find((s) => s.standard && s.domain === domain)!;
  return { email, modulus: testKey(aligned.keyName).modulus };
}

/** A key tree whose only leaf is the key for `domain`. */
function loneKeyPath(domain: string, modulus: bigint) {
  const leaf = registryLeaf(domain, keyHash(modulus));
  const siblings = treePath([leaf], 0);
  return { root: merkleRoot(leaf, 0, siblings), index: 0, siblings };
}

beforeAll(async () => {
  await initHashes();
});

describe('P2 hashes', () => {
  test('the blinded digest is the Subject value the circuit vectors open', () => {
    const digest = new Uint8Array(32);
    digest.set(Buffer.from('222abbecd128052121e4ad2bf3c42381', 'hex'), 0);
    digest.set(Buffer.from('f98abfc18f24903c49681a7f60ba4d42', 'hex'), 16);
    expect(recoverySubject(digest, RHO)).toBe(
      `${RECOVERY_PHRASE}1a62d6a2ed28ca196c93ad7a4c12b40381fe22216859ea4ac6fe4626d1f1e773`,
    );
  });

  test('key hashes, leaves, roots and the pin root are the DKIM key registry vectors', () => {
    const [a, b, c] = ['A', 'B', 'C'].map((x) => keyHash(vectorLimbs(`REGISTRY_MODULUS_${x}`)));
    expect(a).toBe(0x25a7dd9c7d1722237f60c18f7e981754bacb873259d63ffc9114caacdb4bcdaen);
    expect(b).toBe(0x0612361cdce4d414bbcb22c64e24fe37a2e1e546d506d19176c5a0237d0aaa00n);
    expect(c).toBe(0x12abba657357fe88dfc265e30573e1924ba02888c9338454f097b739c9519115n);
    const la = registryLeaf('gmail.com', a!);
    const lb = registryLeaf('outlook.com', b!);
    const lc = registryLeaf('fastmail.com', c!);
    expect(la).toBe(0x27f86eaf8edb3e0731742dcb5d4224053934a67a158915aef1cceaaf0d769169n);
    expect(lb).toBe(0x13507fa59f3214cee8a827a2b87eaab25f32ac2b62e14586173376a423b953b9n);
    expect(lc).toBe(0x212a001de51855c45d590f4c72f7d7575c841fcc1cc515553e2faedcf956c9b8n);
    expect(merkleRoot(la, 0, treePath([la], 0))).toBe(0x22da6e7490012cd3daa3edab29388c9ab80ffeea19aa956f35ad9da0600d8319n);
    expect(merkleRoot(lc, 2, treePath([la, lb, lc], 2))).toBe(0x08fd83d83b64b3be8f9af81baeca40cbd5ea0ce9960e877254df996a1d4c927cn);
    expect(merkleRoot(lc, 2, treePath([la, 0n, lc], 2))).toBe(0x23cce8ab300369c2220682360665ee0218df244953b2753de7e011d716181a3cn);
    const salt = pinSalt(ACCOUNT_CODE);
    expect(merkleRoot(la, 1, treePath([salt, la], 1))).toBe(0x06809f5b34b6b7e95400ba494bbf58b9e2e7e5c9457bbc537560af4b3cb36a1fn);
    expect(emptySubtrees()[16]).toBe(0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3n);
  });

  test('the commitment is the one the circuit and the Soroban host compute', () => {
    // Pinned in circuits/email-recovery/tests/src/recovery_tests.nr and
    // crates/integration-tests/tests/it/email_proofs.rs.
    expect(addressCommitment('alice.example@gmail.com', ACCOUNT_CODE)).toBe(
      0x2c0e895ffe502297a6cf6881711fd974dec6e17f396b4c56977781fd07d5b73cn,
    );
  });

  test('limbs are 18 little-endian 120-bit words', () => {
    const n = (1n << 2047n) + 5n;
    const l = limbs(n);
    expect(l).toHaveLength(18);
    expect(l[0]).toBe(5n);
    expect(l[17]).toBe(1n << 7n);
    expect(() => limbs(1n << 2160n)).toThrow(RangeError);
  });
});

describe('signed header block', () => {
  // Every provider's every signature, honest, with and without a display name:
  // the encoder's octets are the octets the mock's RSA key signed.
  const cases = Object.values(PROVIDERS).flatMap((p) =>
    p.domains.flatMap((d) => [undefined, 'Test User'].map((name) => [p.id, d, name] as const)),
  );
  test.each(cases)('%s %s %s', (provider, domain, name) => {
    const email = generateEmail({ provider, from: `test.user@${domain}`, displayName: name, subject: `${RECOVERY_PHRASE}${'0'.repeat(64)}`, body: 'x\r\n' });
    const message = parseMessage(email.eml);
    const fields = dkimSignatures(message);
    const standard = email.signatures.filter((s) => s.standard);
    expect(fields).toHaveLength(standard.length);
    standard.forEach((info, i) => {
      expect(Buffer.from(signedHeaderBlock(message, fields[i]!)).toString('latin1')).toBe(info.signedHeaderData);
    });
    expect(alignedSignatures(message).map((s) => s.tags.get('d'))).toEqual([domain]);
  });
});

describe('encodeRecoveryEmail', () => {
  // One honest recovery email per domain the mocks sign for; noir_js runs the
  // committed circuit on the encoder's witness.
  const domains = Object.values(PROVIDERS).flatMap((p) => p.domains.map((d) => [p.id, d] as const));
  test.each(domains)('the circuit accepts an honest %s email from %s', async (provider, domain) => {
    const from = `first.last+nido@${domain}`;
    const { email, modulus } = honestEmail(provider, from, 'First Last');
    const keyPath = loneKeyPath(domain, modulus);
    const out = await encodeRecoveryEmail({ eml: email.eml, accountCode: ACCOUNT_CODE, rho: RHO, statement: STATEMENT, modulus, keyPath });
    expect(out.address).toBe(from);
    expect(out.domain).toBe(domain);
    expect(out.witness.commitment).toBe(addressCommitment(from, ACCOUNT_CODE));
    expect(out.witness.keyRoot).toBe(keyPath.root);
    expect(out.witness.header.length).toBeLessThanOrEqual(HEADER_MAX);
    await new Noir(circuit).execute(noirInputs(out.witness) as never);
  }, 60_000);

  // The longest address the spec allows (124 bytes) with a 500-byte display
  // name: every launch domain's signed block fits HEADER_MAX.
  test.each(LAUNCH_DOMAINS.map((d) => [d]))('the circuit accepts the longest address with a long display name at %s', async (domain) => {
    const provider = Object.values(PROVIDERS).find((p) => p.domains.includes(domain))!.id;
    const local = Array.from({ length: 124 - 1 - domain.length }, (_, i) => (i % 10 === 9 ? '.' : 'a')).join('');
    const from = `${local.replace(/\.$/, 'a')}@${domain}`;
    expect(from).toHaveLength(124);
    const { email, modulus } = honestEmail(provider, from, 'Long Display Name '.repeat(28).slice(0, 500));
    const out = await encodeRecoveryEmail({
      eml: email.eml, accountCode: ACCOUNT_CODE, rho: RHO, statement: STATEMENT, modulus, keyPath: loneKeyPath(domain, modulus),
    });
    expect(out.address).toBe(from);
    expect(out.witness.header.length).toBeGreaterThan(1024);
    await new Noir(circuit).execute(noirInputs(out.witness) as never);
  }, 60_000);

  test('the Prover.toml carries exactly the circuit ABI, public inputs first', async () => {
    const { email, modulus } = honestEmail('gmail', 'test.user@gmail.com');
    const out = await encodeRecoveryEmail({
      eml: email.eml, accountCode: ACCOUNT_CODE, rho: RHO, statement: STATEMENT, modulus, keyPath: loneKeyPath('gmail.com', modulus),
    });
    const params: Array<{ name: string; visibility: string }> = circuit.abi.parameters;
    expect(params.filter((p) => p.visibility === 'public').map((p) => p.name)).toEqual(['commitment', 'digest_hi', 'digest_lo', 'key_root']);
    expect(Object.keys(noirInputs(out.witness)).sort()).toEqual(params.map((p) => p.name).sort());
    const toml = proverToml(out.witness);
    for (const p of params) expect(toml).toMatch(new RegExp(`^(${p.name} = |\\[${p.name}\\])`, 'm'));
    const pub = publicInputBytes(out.witness);
    expect(pub).toHaveLength(128);
    expect(Buffer.from(pub.subarray(0, 32)).toString('hex')).toBe(out.witness.commitment.toString(16).padStart(64, '0'));
    expect(Buffer.from(pub.subarray(32, 64)).toString('hex')).toBe(`${'0'.repeat(32)}${Buffer.from(DIGEST.subarray(0, 16)).toString('hex')}`);
  });

  describe('refuses', () => {
    const gmail = () => honestEmail('gmail', 'test.user@gmail.com');
    const encode = (over: Partial<Parameters<typeof encodeRecoveryEmail>[0]>) => {
      const { email, modulus } = gmail();
      return encodeRecoveryEmail({
        eml: email.eml, accountCode: ACCOUNT_CODE, rho: RHO, statement: STATEMENT, modulus, keyPath: loneKeyPath('gmail.com', modulus), ...over,
      });
    };

    test('another statement', async () => {
      await expect(encode({ statement: text('another statement') })).rejects.toThrow(/recovery Subject/);
    });

    test('another rho', async () => {
      await expect(encode({ rho: RHO + 1n })).rejects.toThrow(/recovery Subject/);
    });

    test('a key that did not sign the email', async () => {
      await expect(encode({ modulus: testKey('outlook').modulus })).rejects.toThrow(/verifies under this key/);
    });

    test('a root the key is not under', async () => {
      const { modulus } = gmail();
      await expect(encode({ keyPath: { ...loneKeyPath('outlook.com', modulus) } })).rejects.toThrow(/does not reach the given root/);
    });

    test('a message signed only by a domain other than the From domain', async () => {
      const misaligned = buildAttacks(defaultAttackInput()).find((c) => c.id === 'misaligned-d-gappssmtp')!;
      await expect(encode({ eml: misaligned.email.eml })).rejects.toThrow(DkimHeaderError);
      await expect(encode({ eml: misaligned.email.eml })).rejects.toThrow(/d= equal to the From domain/);
    });

    test('a signed header block over the circuit bound', async () => {
      const long = generateEmail({
        provider: 'gmx', from: `${'x'.repeat(116)}@gmx.net`, displayName: 'N'.repeat(600), subject: recoverySubject(DIGEST, RHO), body: 'x\r\n',
      });
      const modulus = testKey('gmx').modulus;
      await expect(
        encodeRecoveryEmail({ eml: long.eml, accountCode: ACCOUNT_CODE, rho: RHO, statement: STATEMENT, modulus, keyPath: loneKeyPath('gmx.net', modulus) }),
      ).rejects.toThrow(/at most 1536/);
    });
  });
});
