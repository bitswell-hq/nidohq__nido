import { describe, expect, it } from 'vitest';
import { StrKey } from '@stellar/stellar-sdk';
import { accountReader, readSnapshot } from '@stellar-registry/perch';

// `readAccountSnapshot` reads an account through perch-js's `accountReader`
// over its generated client, then `readSnapshot` checks its capabilities.
// The account Nido's factory deploys (Perch's `perch-account`, sha256
// d99d56fc..., `vendor/perch/deployments/testnet.json`) reports the
// account-address-bound authorization digest; a perch-js that refuses it
// leaves the account's recovery pages unable to read it.

const contract = (n: number) => StrKey.encodeContract(Buffer.alloc(32, n));
const COMPILER = contract(9);
const sim = <T>(result: T, latestLedger = 100) => ({ result, simulation: { latestLedger } });

/** The views as the generated bindings answer them, with `capabilities()` as the account wasm returns it. */
function bindings(authDigest: string) {
  const client = {
    configuration: async () =>
      sim({
        revision: 3n,
        doc_hash: null,
        rules: [],
        recovery_controller: null,
        recovery_rule: null,
        gate: [],
        recovery_generation: 0n,
        infra: { doc_compiler: COMPILER, interpreter: contract(10), spending_limit: contract(11) },
      }),
    revision: async () => sim(3n),
    document: async () => sim([3n, null]),
    capabilities: async () =>
      sim({ interface_version: 1, doc_identity: 'canon_v1', auth_digest: authDigest, apply_modes: ['one_tx'], snapshot_version: 1 }),
  };
  const compiler = {
    options: { contractId: COMPILER },
    limits: async () => sim({ tag: 'V1', values: [{ max_signers: 16, max_rules: 16, max_canonical_bytes: 8192, max_rule_name_bytes: 32 }] }),
  };
  return accountReader(contract(1), client as never, compiler as never);
}

describe('reading a Perch account', () => {
  it('reads an account that reports the addr_oz_v1 authorization digest', async () => {
    const snap = await readSnapshot(bindings('addr_oz_v1'), { document: true });
    expect(snap.capabilities.authDigest).toBe('addr_oz_v1');
    expect(snap.configuration.revision).toBe(3n);
    expect(snap.document).toBeNull();
  });
});
