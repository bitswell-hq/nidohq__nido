/**
 * The attack suite's prover: for each adversarial email of
 * `@nidohq/email-mocks`, the witness that would prove the case's claim, and
 * the committed recovery circuit's verdict on it (noir_js).
 *
 * Keys come from the mock DNS (every launch provider's published keys, plus
 * the records the case itself publishes, such as an attacker's own domain),
 * as a DKIM verifier and the registry's attesters read them. The attacker
 * takes the most favourable inputs available:
 *
 * - the signature: one a standard verifier (node:crypto) accepts under its
 *   `d=`/`s=` key, preferring the claimed sender's domain; when none does,
 *   the claimed domain's signature anyway, so the circuit's RSA check is
 *   what refuses it;
 * - `H`: the octets that signature covers, built as a verifier builds them;
 * - the key tree: the launch registry's tree (one leaf per launch domain
 *   under its provider's published key) when the key is in it; otherwise a
 *   tree planted with that key under the lowercase `d=`, as if the registry
 *   had admitted it, so the email's own checks are what refuse it;
 * - the public inputs the claimed account's guardian would build: the
 *   claimed sender committed under that account's code, and that account's
 *   statement digest (account B's attempt has its own statement).
 */
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { type AttackCase, type AttackInput, MockDns, PROVIDERS, launchDns, parseTags } from '@nidohq/email-mocks';
import { Noir } from '@noir-lang/noir_js';
import {
  HEADER_MAX,
  LAUNCH_DOMAINS,
  addressCommitment,
  blindedDigest,
  dkimSignatures,
  fieldHex,
  keyHash,
  merkleRoot,
  noirInputs,
  parseMessage,
  registryLeaf,
  signatureValue,
  signedHeaderBlock,
  splitDigest,
  treePath,
} from '../src/index.js';

const circuit = JSON.parse(
  readFileSync(new URL('../../../circuits/email-recovery/artifacts/recovery.json', import.meta.url), 'utf8'),
);

export const PHRASE = 'APPROVE NIDO ACCOUNT RECOVERY';


const sha256 = (s: string) => new Uint8Array(createHash('sha256').update(s).digest());

interface Statement {
  digest: Uint8Array;
  rho: bigint;
}

/**
 * Account A's attempt (`a`), another statement of account A (`b`), and
 * account B's attempt (`accountB`), each with the `rho` an email for it
 * would carry; and the two accounts' codes.
 */
export const STATEMENTS: Record<'a' | 'b' | 'accountB', Statement> = {
  a: { digest: sha256('TEST-ONLY statement A'), rho: 0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0an },
  b: { digest: sha256('TEST-ONLY statement B'), rho: 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0bn },
  accountB: { digest: sha256('TEST-ONLY account B statement'), rho: 0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0cn },
};
export const ACCOUNT_CODES: Record<string, bigint> = {
  'account-a': 0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0n,
  'account-b': 0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0n,
};

const valueOf = (s: Statement) => fieldHex(blindedDigest(s.digest, s.rho));

/** The attack input with the spec's Subject: statement A's blinded digest; B's is the other value. */
export function specAttackInput(): AttackInput {
  const recoveryValue = valueOf(STATEMENTS.a);
  return {
    victim: 'victim@gmail.com',
    attacker: 'attacker@gmail.com',
    phrase: PHRASE,
    subject: `${PHRASE} ${recoveryValue}`,
    recoveryValue,
    otherRecoveryValue: valueOf(STATEMENTS.b),
    account: 'account-a',
    otherAccount: 'account-b',
    body: 'This message is a test fixture.\r\n',
  };
}

function rsaKey(dns: MockDns, d: string, s: string): { modulus: bigint; key: ReturnType<typeof createPublicKey> } | undefined {
  const record = dns.lookup(`${s}._domainkey.${d}`)?.join('');
  const p = record ? parseTags(record).get('p') : undefined;
  if (!p) return undefined;
  const key = createPublicKey({ key: Buffer.from(p, 'base64'), format: 'der', type: 'spki' });
  const n = key.export({ format: 'jwk' }).n!;
  return { modulus: BigInt(`0x${Buffer.from(n, 'base64url').toString('hex')}`), key };
}

/** The launch registry: each launch domain's aligned key, in allowlist order. */
function registryLeaves(dns: MockDns): bigint[] {
  return LAUNCH_DOMAINS.map((domain) => {
    const provider = Object.values(PROVIDERS).find((p) => p.domains.includes(domain))!;
    const signer = provider.signers.find((x) => x.fieldName.toLowerCase() === 'dkim-signature' && x.domain(domain) === domain)!;
    return registryLeaf(domain, keyHash(rsaKey(dns, domain, signer.selector(domain))!.modulus));
  });
}

export type Outcome =
  | { accepted: true; tree: 'registry' | 'planted' }
  | { accepted: false; tree: 'registry' | 'planted'; reason: string };

/** The circuit's verdict on the strongest witness for `c.claim`. */
export async function prove(c: AttackCase): Promise<Outcome> {
  const dns = launchDns();
  for (const [name, value] of c.email.dnsRecords) if (!dns.lookup(name)) dns.publish(name, value);

  const message = parseMessage(c.email.eml);
  const claimDomain = c.claim.from.slice(c.claim.from.lastIndexOf('@') + 1).toLowerCase();
  const candidates = dkimSignatures(message).map((field) => {
    const d = (field.tags.get('d') ?? '').toLowerCase();
    const key = rsaKey(dns, d, field.tags.get('s') ?? '');
    const block = signedHeaderBlock(message, field);
    const ok = !!key && verify('sha256', block, key.key, Buffer.from(field.tags.get('b') ?? '', 'base64'));
    return { field, d, key, block, ok };
  });
  const rank = (x: (typeof candidates)[number]) => 2 * Number(x.ok) + Number(x.d === claimDomain);
  const chosen = candidates.filter((x) => x.key).sort((x, y) => rank(y) - rank(x))[0];
  if (!chosen) throw new Error(`${c.id}: no signature has a published key`);
  const modulus = chosen.key!.modulus;

  const leaves = registryLeaves(dns);
  const leaf = registryLeaf(chosen.d.slice(0, 62), keyHash(modulus));
  const at = leaves.indexOf(leaf);
  const tree = at === -1 ? 'planted' : 'registry';
  const index = at === -1 ? 0 : at;
  const siblings = treePath(at === -1 ? [leaf] : leaves, index);
  if (chosen.block.length > HEADER_MAX) {
    return { accepted: false, tree, reason: `the signed header block exceeds ${HEADER_MAX} octets` };
  }

  const account = c.claim.account ?? 'account-a';
  const statement =
    account === 'account-b' ? STATEMENTS.accountB : c.claim.recoveryValue === valueOf(STATEMENTS.b) ? STATEMENTS.b : STATEMENTS.a;
  const [digestHi, digestLo] = splitDigest(statement.digest);
  const accountCode = ACCOUNT_CODES[account]!;
  const witness = {
    commitment: addressCommitment(c.claim.from, accountCode),
    digestHi,
    digestLo,
    keyRoot: merkleRoot(leaf, index, siblings),
    header: chosen.block,
    modulus,
    signature: signatureValue(chosen.field),
    rho: statement.rho,
    accountCode,
    keyIndex: index,
    keySiblings: siblings,
    // The Barrett hint is a prover hint; a key that is not 2048 bits has none that fits.
    redc: modulus >> 2047n === 1n ? undefined : 0n,
  };
  try {
    await new Noir(circuit).execute(noirInputs(witness) as never);
    return { accepted: true, tree };
  } catch (e) {
    return { accepted: false, tree, reason: (e as Error).message.replace(/^Circuit execution failed: /, '') };
  }
}
