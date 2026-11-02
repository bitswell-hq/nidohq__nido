// The attacker's strongest witness for an email's claim, against a live
// attempt on the network: the same choices as the circuit attack suite
// (`packages/email-recovery/test/attackHarness.ts`), with the claimed
// account's real statement, commitment and accepted key tree.
//
// - The signature: one a standard verifier (node:crypto) accepts under its
//   `d=`/`s=` key in DNS, preferring the claimed sender's domain; when none
//   verifies, the claimed domain's signature anyway, so the circuit's RSA
//   check is what refuses it.
// - `H`: the octets that signature covers, built as a verifier builds them.
// - The key tree: the claimed account's pin when the key is in it (the
//   root its guardian accepts); otherwise a tree planted with the key under
//   the lowercase `d=`, so the email's own checks are what refuse it.
// - The public inputs the claimed account's guardian builds: its
//   commitment, its attempt's statement digest. The attacker is granted the
//   account's `account_code` unless the scenario says otherwise.
import { createPublicKey, verify } from 'node:crypto';
import { launchDns, parseTags } from '@nidohq/email-mocks';
import {
  HEADER_MAX,
  addressCommitment,
  dkimSignatures,
  keyHash,
  merkleRoot,
  parseMessage,
  registryLeaf,
  signatureValue,
  signedHeaderBlock,
  splitDigest,
  treePath,
} from '@nidohq/email-recovery';
import { solve } from './email.mjs';

function rsaKey(dns, d, s) {
  const record = dns.lookup(`${s}._domainkey.${d}`)?.join('');
  const p = record ? parseTags(record).get('p') : undefined;
  if (!p) return undefined;
  const key = createPublicKey({ key: Buffer.from(p, 'base64'), format: 'der', type: 'spki' });
  const n = key.export({ format: 'jwk' }).n;
  return { modulus: BigInt(`0x${Buffer.from(n, 'base64url').toString('hex')}`), key };
}

/**
 * @param {object} o
 * @param {Uint8Array} o.eml the email as received
 * @param {string} o.claimFrom the address the attacker claims sent it
 * @param {{ accountCode: bigint, digest: Uint8Array, rho: bigint, pinLeaves: bigint[], commitment?: bigint }} o.target the claimed
 *   account and attempt: the code the attacker uses, and the commitment the guardian builds (by default the
 *   claimed address under that code)
 * @param {Array<[string, string]>} [o.dnsRecords] records the case publishes (an attacker's own domain)
 */
export function strongestWitness({ eml, claimFrom, target, dnsRecords = [] }) {
  const dns = launchDns();
  for (const [name, value] of dnsRecords) if (!dns.lookup(name)) dns.publish(name, value);
  const message = parseMessage(eml);
  const claimDomain = claimFrom.slice(claimFrom.lastIndexOf('@') + 1).toLowerCase();
  const candidates = dkimSignatures(message).map((field) => {
    const d = (field.tags.get('d') ?? '').toLowerCase();
    const key = rsaKey(dns, d, field.tags.get('s') ?? '');
    const block = signedHeaderBlock(message, field);
    const ok = !!key && verify('sha256', block, key.key, Buffer.from(field.tags.get('b') ?? '', 'base64'));
    return { field, d, key, block, ok };
  });
  const rank = (x) => 2 * Number(x.ok) + Number(x.d === claimDomain);
  const chosen = candidates.filter((x) => x.key).sort((x, y) => rank(y) - rank(x))[0];
  if (!chosen) return { error: 'no signature has a published key' };
  const modulus = chosen.key.modulus;
  const leaf = registryLeaf(chosen.d.slice(0, 62), keyHash(modulus));
  const at = target.pinLeaves.indexOf(leaf);
  const tree = at === -1 ? 'planted' : 'pin';
  const leaves = at === -1 ? [leaf] : target.pinLeaves;
  const index = at === -1 ? 0 : at;
  const siblings = treePath(leaves, index);
  if (chosen.block.length > HEADER_MAX) return { tree, error: `the signed header block exceeds ${HEADER_MAX} octets` };
  const [digestHi, digestLo] = splitDigest(target.digest);
  const witness = {
    commitment: target.commitment ?? addressCommitment(claimFrom, target.accountCode),
    digestHi,
    digestLo,
    keyRoot: merkleRoot(leaf, index, siblings),
    header: chosen.block,
    modulus,
    signature: signatureValue(chosen.field),
    rho: target.rho,
    accountCode: target.accountCode,
    keyIndex: index,
    keySiblings: siblings,
    // The Barrett hint is a prover hint; a key that is not 2048 bits has none that fits.
    redc: modulus >> 2047n === 1n ? undefined : 0n,
  };
  return { tree, witness, verifies: chosen.ok, d: chosen.d };
}

/** The circuit's verdict on the strongest witness: `{ tree, accepted, reason?, witness? }`. */
export async function circuitVerdict(o) {
  const w = strongestWitness(o);
  if (w.error) return { tree: w.tree, accepted: false, reason: w.error };
  const solved = await solve(w.witness);
  return solved.ok ? { tree: w.tree, accepted: true, solved: solved.witness, witness: w.witness } : { tree: w.tree, accepted: false, reason: solved.reason };
}
