import { describe, expect, it } from 'vitest';
import { Address, StrKey, xdr } from '@stellar/stellar-sdk';
import { initHashes, recoverySubject } from '@nidohq/email-recovery';
import {
  PRIVACY_CLAIM,
  chooseKeyPath,
  clock,
  delayCountdown,
  mailtoLink,
  newPendingApproval,
  nextEnrollStep,
  pendingApprovalProblem,
  recoveryEmail,
  remainingFactors,
  spacedCode,
  stageText,
  subjectValue,
} from './emailModel';
import {
  emailApprovalEntry,
  emailApprovalScVal,
  deployedAddress,
  guardianConfigFromNative,
  guardianConfigScVal,
  submitGuardianOperation,
} from './emailGuardian';
import { parseEmailRecoveryDeployment } from './emailConfig';
import { EMAIL_CIRCUIT_ID } from './emailProver';

const contract = (n: number) => StrKey.encodeContract(Buffer.alloc(32, n));

describe('the email to send', () => {
  it('is a mailto: link with the exact Subject, which routes by its value', async () => {
    await initHashes();
    const digest = new Uint8Array(32).fill(3);
    const email = recoveryEmail('recover@recovery.test', digest, 9n);
    expect(email.subject).toBe(recoverySubject(digest, 9n));
    const link = mailtoLink(email);
    expect(link.startsWith('mailto:recover@recovery.test?subject=APPROVE%20NIDO%20ACCOUNT%20RECOVERY%20')).toBe(true);
    expect(decodeURIComponent(new URL(link).searchParams.get('subject')!)).toBe(email.subject);
    expect(subjectValue(email.subject)).toBe(email.subject.slice(-64));
    expect(() => subjectValue(`Re: ${email.subject} x`)).toThrow();
    expect(mailtoLink({ to: 'a@b.c', subject: 'S', body: 'one\ntwo' })).toBe('mailto:a@b.c?subject=S&body=one%0D%0Atwo');
  });

  it('a saved approval fits only the attempt and statement it was built for', () => {
    const digest = new Uint8Array(32).fill(1);
    const p = newPendingApproval(4n, digest, 77n);
    expect(pendingApprovalProblem(p, 4n, digest)).toBeUndefined();
    expect(pendingApprovalProblem(p, 5n, digest)).toMatch(/earlier recovery attempt/);
    expect(pendingApprovalProblem(p, 4n, new Uint8Array(32).fill(2))).toMatch(/changed/);
    expect(JSON.stringify(p)).not.toMatch(/account_?code/i);
  });

  it('the privacy claim is the scoped one', () => {
    expect(PRIVACY_CLAIM).toBe('Nido’s servers and staff can’t read your address.');
  });
});

describe('the key path', () => {
  const path = (root: bigint) => ({ index: 1, siblings: [], root });
  it('prefers a live pin that holds the key, else an accepted registry root', () => {
    expect(chooseKeyPath({ ledger: 10, pin: { root: 5n, validUntilLedger: 10, path: path(5n) } })).toMatchObject({ kind: 'pin', root: 5n });
    expect(
      chooseKeyPath({ ledger: 11, pin: { root: 5n, validUntilLedger: 10, path: path(5n) }, registry: { root: 6n, accepted: true, path: path(6n) } }),
    ).toMatchObject({ kind: 'registry', root: 6n });
    expect(chooseKeyPath({ ledger: 11, pin: { root: 5n, validUntilLedger: 10, path: path(5n) } })).toMatchObject({ kind: 'none', why: /pin has expired/ });
    expect(chooseKeyPath({ ledger: 1, registry: { root: 6n, accepted: false, path: path(6n) } })).toMatchObject({ kind: 'none' });
    // A pin path that does not open to the guardian's pin root is no path.
    expect(chooseKeyPath({ ledger: 1, pin: { root: 5n, validUntilLedger: 10, path: path(7n) } })).toMatchObject({ kind: 'none' });
  });
});

describe('progress and what remains', () => {
  it('stage copy, clock, and the code as alerts print it', () => {
    expect(stageText('download', { loaded: 2e6, total: 18.8e6, cached: false })).toBe('Downloading the prover (2.0 of 18.8 MB)…');
    expect(stageText('download', { loaded: 1, total: 1, cached: true })).toMatch(/from this browser/);
    expect(stageText('proving', {})).toMatch(/two minutes on a phone/);
    expect(clock(65_400)).toBe('1:05');
    expect(spacedCode('169328')).toBe('169 328');
  });

  it('remaining factors after the email vote', () => {
    const base = { guardians: ['E', 'F', 'G'], emailGuardian: 'E', zkNeeded: false, zkRecorded: false };
    expect(remainingFactors({ ...base, quorum: 2, approvals: [] })).toMatchObject({ emailApproved: false, othersNeeded: 1 });
    expect(remainingFactors({ ...base, quorum: 2, approvals: ['E'] })).toMatchObject({ emailApproved: true, othersNeeded: 1 });
    expect(remainingFactors({ ...base, quorum: 2, approvals: ['E', 'F'] }).text).toMatch(/Nothing else is needed/);
    expect(remainingFactors({ ...base, quorum: 1, approvals: ['E'], zkNeeded: true }).text).toMatch(/recovery kit still needs/);
  });

  it('the delay counts down from the ledger read', () => {
    expect(delayCountdown(130, 100, 0, 0).remainingMs).toBe(150_000);
    expect(delayCountdown(130, 100, 0, 60_000).remainingMs).toBe(90_000);
    expect(delayCountdown(130, 100, 0, 200_000)).toEqual({ remainingMs: 0, text: 'The waiting period is over.' });
  });

  it('enrollment steps run in order', () => {
    expect(nextEnrollStep({})).toBe('code');
    expect(nextEnrollStep({ code: true, email: true })).toBe('check');
    expect(nextEnrollStep({ code: true, email: true, check: true, alerts: true, deploy: true, apply: true })).toBe('done');
  });
});

describe('the email guardian on chain', () => {
  const cfg = {
    account: contract(1),
    controller: contract(2),
    commitment: new Uint8Array(32).fill(3),
    registry: contract(4),
    keyPin: [{ root: new Uint8Array(32).fill(5), validUntilLedger: 777 }],
    allowedActions: 31,
    verifier: contract(6),
    circuitId: new Uint8Array(32).fill(7),
  };

  it('GuardianConfig is the contract type: a map of its fields in sorted order', () => {
    const v = guardianConfigScVal(cfg);
    const keys = v.map()!.map((e) => e.key().sym().toString());
    expect(keys).toEqual(['account', 'allowed_actions', 'circuit_id', 'commitment', 'controller', 'key_pin', 'registry', 'verifier']);
    const pin = v.map()![5]!.val().vec()![0]!;
    expect(pin.map()!.map((e) => e.key().sym().toString())).toEqual(['root', 'valid_until_ledger']);
    // Round trip through the XDR and the native form `config()` returns.
    const back = xdr.ScVal.fromXDR(v.toXDR());
    expect(back.toXDR('base64')).toBe(v.toXDR('base64'));
  });

  it('the approval entry authorizes exactly (digest,) on the controller’s submit_guardian', () => {
    const approval = { statement: new Uint8Array([1, 2, 3]), keyRoot: new Uint8Array(32).fill(9), proof: new Uint8Array(16_224) };
    const sig = emailApprovalScVal(approval);
    expect(sig.map()!.map((e) => e.key().sym().toString())).toEqual(['key_root', 'proof', 'statement']);
    const entry = emailApprovalEntry({
      guardian: contract(8),
      controller: contract(2),
      fnName: 'submit_guardian',
      digest: new Uint8Array(32).fill(4),
      approval,
      nonce: 42n,
      expirationLedger: 1_000,
    });
    const creds = entry.credentials().address();
    expect(Address.fromScAddress(creds.address()).toString()).toBe(contract(8));
    expect(creds.nonce().toString()).toBe('42');
    const fn = entry.rootInvocation().function().contractFn();
    expect(Address.fromScAddress(fn.contractAddress()).toString()).toBe(contract(2));
    expect(fn.functionName().toString()).toBe('submit_guardian');
    expect(fn.args().map((a) => Buffer.from(a.bytes()).toString('hex'))).toEqual(['04'.repeat(32)]);
    expect(entry.rootInvocation().subInvocations()).toEqual([]);
    const op = submitGuardianOperation({ controller: contract(2), account: contract(1), attemptId: 3n, domain: 0, guardian: contract(8), entry });
    const args = op.body().invokeHostFunctionOp().hostFunction().invokeContract().args();
    expect(args.map((a) => a.switch().name)).toEqual(['scvAddress', 'scvU64', 'scvU32', 'scvAddress']);
    expect(op.body().invokeHostFunctionOp().auth()).toHaveLength(1);
  });

  it('config() reads back into the same configuration', () => {
    const native = {
      account: cfg.account,
      controller: cfg.controller,
      commitment: cfg.commitment,
      registry: cfg.registry,
      key_pin: [{ root: cfg.keyPin[0]!.root, valid_until_ledger: 777 }],
      allowed_actions: 31,
      verifier: cfg.verifier,
      circuit_id: cfg.circuitId,
    };
    expect(guardianConfigFromNative(native)).toEqual(cfg);
  });

  it('the deployed address is the CAP-46 derivation of deployer and salt', () => {
    const deployer = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 9));
    const salt = new Uint8Array(32).fill(1);
    const a = deployedAddress(deployer, salt, 'Test SDF Network ; September 2015');
    expect(a).toMatch(/^C[A-Z2-7]{55}$/);
    expect(deployedAddress(deployer, salt, 'Standalone Network ; February 2017')).not.toBe(a);
    expect(deployedAddress(deployer, new Uint8Array(32).fill(2), 'Test SDF Network ; September 2015')).not.toBe(a);
  });
});

describe('the email recovery deployment', () => {
  const ok = {
    guardianWasmHash: 'ab'.repeat(32),
    registry: contract(1),
    verifier: contract(2),
    circuitId: EMAIL_CIRCUIT_ID,
    recoveryInbox: 'recover@recovery.test',
    alertService: 'https://alerts.test',
    keyList: '/dkim-keys.json',
    enclaveImageRegistry: contract(3),
    attestationRoots: ['AAAA'],
  };
  it('is checked before use', () => {
    expect(parseEmailRecoveryDeployment(ok)).toEqual(ok);
    expect(() => parseEmailRecoveryDeployment({ ...ok, circuitId: 'cd'.repeat(32) })).toThrow(/another circuit/);
    expect(() => parseEmailRecoveryDeployment({ ...ok, registry: 'G' })).toThrow(/registry/);
    expect(() => parseEmailRecoveryDeployment({ ...ok, attestationRoots: [] })).toThrow(/attestationRoots/);
  });
});
