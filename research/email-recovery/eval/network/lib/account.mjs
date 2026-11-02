// Nido accounts on a network: minted by Nido's factory around a Perch
// account, administered by an owner passkey (a TEST-ONLY P-256 key behind
// `AuthenticatorMock`, the authenticator format of W3C WebAuthn Level 3),
// whose assertions sign Soroban authorization entries exactly as the
// wallet's do: the WebAuthn challenge is the account's auth digest over the
// host's signature payload and the selected context rule
// (`computeAuthDigest`, `addr_oz_v1`).
import { createHash } from 'node:crypto';
import { AuthenticatorMock } from '@nidohq/email-mocks';
import { buildAuthPayloadScVal, computeAuthDigest, derToCompact } from '@nidohq/passkey-sdk';
import { Keypair, Operation, StrKey, hash, xdr } from '@stellar/stellar-sdk';
import { sc } from './chain.mjs';

const sha256 = (b) => createHash('sha256').update(b).digest();

/** The wallet's origin for an account: its own subdomain of the apex. */
export const accountOrigin = (account, apex) => ({
  rpId: `${account.toLowerCase()}.${apex.host}`,
  origin: `${apex.scheme}//${account.toLowerCase()}.${apex.host}${apex.port ? `:${apex.port}` : ''}`,
});

/** A passkey: a P-256 key derived from `label` (TEST-ONLY). */
export class Passkey {
  constructor(label) {
    this.label = label;
    this.privateKey = sha256(`nido-eval/email-attacks/passkey/${label}`);
    this.mock = new AuthenticatorMock('unset.invalid', 'https://unset.invalid', this.privateKey);
    this.publicKey = this.mock.publicKey;
  }

  /** An assertion over `challenge` for `account`'s relying party. */
  assert(challenge, rp) {
    return this.mock.assert(challenge, rp);
  }
}

export class NidoAccount {
  constructor({ chain, address, owner, verifier, apex }) {
    this.chain = chain;
    this.address = address;
    this.owner = owner;
    this.verifier = verifier;
    this.rp = accountOrigin(address, apex);
  }

  /**
   * Mint through `factory.create_account(setup, owner key, binding)`, paid by
   * `payer`: a one-time setup key fixes the address and binds the owner's
   * passkey to it with its signature over
   * `sha256("nido/bind/v1" || network_id || factory_id || key)`.
   */
  static async mint({ chain, factory, payer, owner, verifier, apex, label }) {
    const setup = Keypair.random();
    const key = Buffer.from(owner.publicKey);
    const binding = hash(Buffer.concat([Buffer.from('nido/bind/v1'), hash(Buffer.from(chain.passphrase)), StrKey.decodeContract(factory), key]));
    const r = await chain.invoke(payer, factory, 'create_account', [sc.bytes(setup.rawPublicKey()), sc.bytes(key), sc.bytes(setup.sign(binding))], { label: `mint ${label}` });
    return new NidoAccount({ chain, address: r.value, owner, verifier, apex });
  }

  /** The live rule named `name`, or the recovery rule, as `configuration()` reports it. */
  async ruleId(name) {
    const config = await this.chain.read(this.address, 'configuration');
    if (name === 'recovery') return config.recovery_rule;
    const rule = config.rules.find((r) => !r.recovery && r.name === name);
    if (!rule) throw new Error(`${this.address} has no rule ${name}`);
    return rule.id;
  }

  /** `entry` (the account's recorded entry) signed by the owner through rule `ruleId`. */
  async sign(entry, ruleId, lastLedger) {
    const creds = entry.credentials().address();
    const expiration = lastLedger + 1_000;
    creds.signatureExpirationLedger(expiration);
    const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
      new xdr.HashIdPreimageSorobanAuthorization({
        networkId: hash(Buffer.from(this.chain.passphrase)),
        nonce: creds.nonce(),
        signatureExpirationLedger: expiration,
        invocation: entry.rootInvocation(),
      }),
    );
    const payload = hash(preimage.toXDR());
    const digest = computeAuthDigest(this.address, payload, [ruleId]);
    const a = this.owner.assert(digest, this.rp);
    creds.signature(
      buildAuthPayloadScVal({
        contextRuleIds: [ruleId],
        signers: [
          {
            kind: 'external',
            verifierAddress: this.verifier,
            publicKey: this.owner.publicKey,
            passkeySignature: { authenticatorData: a.authenticatorData, clientDataJson: a.clientDataJSON, signature: derToCompact(a.signature) },
          },
        ],
      }),
    );
    return entry;
  }

  /**
   * `contract.fn(args)` authorized by the owner through the admin rule:
   * recorded, the account's entry signed, then sent with that entry
   * enforced.
   */
  async ownerCall(payer, contract, fn, args, label) {
    const bare = Operation.invokeContractFunction({ contract, function: fn, args });
    const { sim } = await this.chain.simulate(payer, bare, 'record');
    const ruleId = await this.ruleId('admin');
    const last = await this.chain.ledger();
    const entries = [];
    for (const e of sim.result.auth) {
      const addr = e.credentials().switch().name === 'sorobanCredentialsAddress' ? e.credentials().address().address() : undefined;
      const isAccount = addr && addr.switch().name === 'scAddressTypeContract' && Buffer.from(addr.contractId()).equals(Buffer.from(contractIdOf(this.address)));
      entries.push(isAccount ? await this.sign(e, ruleId, last) : e);
    }
    const op = Operation.invokeHostFunction({ func: bare.body().invokeHostFunctionOp().hostFunction(), auth: entries });
    return this.chain.send(payer, op, { authMode: 'enforce', label });
  }

  /** `apply_doc(canonical, 0, None)`: the owner's whole-document write. */
  applyDoc(payer, canonical, label = 'apply_doc') {
    return this.ownerCall(payer, this.address, 'apply_doc', [sc.bytes(Buffer.from(canonical, 'utf8')), sc.u32(0), xdr.ScVal.scvVoid()], label);
  }

  /** A `Loss` owner's veto of an attempt. */
  cancelRecovery(payer, attemptId, label = 'cancel_recovery') {
    return this.ownerCall(payer, this.address, 'cancel_recovery', [sc.u64(attemptId)], label);
  }
}

export const contractIdOf = (c) => StrKey.decodeContract(c);
