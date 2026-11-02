// A Stellar network as the evaluation drives it: Stellar RPC reads,
// simulation in an explicit authorization mode, submission, refusals decoded
// to the contract and error that refused, and each transaction's resources
// and fee read back from the network's own result.
//
// Simulation in `enforce` mode runs every authorization entry the operation
// carries, custom accounts' `__check_auth` included; `record` mode records
// entries instead and does not run them (vendor/perch/AGENTS.md). Every
// transaction that carries an email approval is therefore simulated with
// `enforce`, so its footprint and resources include the guardian's checks
// and the proof verification.
import { performance } from 'node:perf_hooks';
import { Account, Address, Keypair, Operation, SorobanDataBuilder, StrKey, TransactionBuilder, rpc, scValToNative, xdr } from '@stellar/stellar-sdk';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A refusal: which contract refused, with which error, at which stage. */
export class Refused extends Error {
  constructor(stage, detail) {
    super(`${stage}: ${detail.kind}${detail.code !== undefined ? ` #${detail.code}` : ''}${detail.contract ? ` from ${detail.contract}` : ''}`);
    this.stage = stage;
    Object.assign(this, detail);
  }
}

/**
 * The first contract error in a host error and its diagnostic events, and
 * the contract that raised it: the innermost frame that reported one.
 */
export function decodeHostError(text, events = []) {
  const contractErr = /Error\(Contract, #(\d+)\)/.exec(text);
  const authErr = /Error\(Auth, (\w+)\)/.exec(text);
  const budgetErr = /Error\(Budget, (\w+)\)/.exec(text);
  let contract;
  for (const e of events) {
    try {
      const ev = e.event();
      const id = ev.contractId();
      const body = ev.body().v0();
      const topics = body.topics().map((t) => t.switch().name === 'scvError' ? 'error' : scValToNative(t));
      if (topics[0] === 'error' && id && contractErr) {
        const err = body.topics()[1];
        if (err?.switch().name === 'scvError' && err.error().switch().name === 'sceContract' && err.error().contractCode() === Number(contractErr[1])) {
          contract = Address.contract(id).toString();
          break;
        }
      }
    } catch {
      // Events of other shapes carry no error.
    }
  }
  if (!contract && contractErr) {
    // RPC's text form: "contract:C…, topics:[error, Error(Contract, #N)]".
    const m = new RegExp(`contract:(C[A-Z2-7]{55}), topics:\\[error, Error\\(Contract, #${contractErr[1]}\\)`).exec(text);
    if (m) contract = m[1];
  }
  if (contractErr) return { kind: 'contract', code: Number(contractErr[1]), contract, raw: text };
  if (authErr) return { kind: `auth:${authErr[1]}`, raw: text };
  if (budgetErr) return { kind: `budget:${budgetErr[1]}`, raw: text };
  return { kind: 'other', raw: text };
}

export class Chain {
  /**
   * @param {{ rpcUrl: string, passphrase: string, friendbot?: string, allowHttp?: boolean, baseFee?: string }} o
   */
  constructor(o) {
    this.rpcUrl = o.rpcUrl;
    this.passphrase = o.passphrase;
    this.friendbotUrl = o.friendbot;
    this.server = new rpc.Server(o.rpcUrl, { allowHttp: o.allowHttp ?? o.rpcUrl.startsWith('http://') });
    this.baseFee = o.baseFee ?? '1000000';
    /** A pause after each confirmation, for RPCs whose nodes trail each other (not counted in the measurement). */
    this.settleMs = o.settleMs ?? 0;
    /** Every transaction sent, with its measurement. */
    this.log = [];
  }

  async call(method, params = {}) {
    for (let attempt = 1; ; attempt++) {
      try {
        const r = await fetch(this.rpcUrl, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        });
        const body = await r.json();
        if (body.error) throw new Error(`${method}: ${body.error.message}`);
        return body.result;
      } catch (e) {
        if (attempt >= 5 || !/fetch failed|ECONNRESET|socket/i.test(String(e.message))) throw e;
        await sleep(500 * attempt);
      }
    }
  }

  /** The latest ledger sequence, from the raw RPC answer (no close-meta decoding). */
  async ledger() {
    return (await this.call('getLatestLedger')).sequence;
  }

  /** Wait until the network has closed ledger `n`. */
  async untilLedger(n, { pollMs = 500 } = {}) {
    for (;;) {
      const at = await this.ledger();
      if (at >= n) return at;
      await sleep(pollMs);
    }
  }

  /** The latest ledger's close time, Unix seconds. */
  async closeTime() {
    return Number((await this.call('getLatestLedger')).closeTime);
  }

  /** Wait until the network has closed a ledger at close time `t` or later. */
  async untilCloseTime(t, { pollMs = 500 } = {}) {
    for (;;) {
      const at = await this.closeTime();
      if (at >= t) return at;
      await sleep(pollMs);
    }
  }

  /** The network's target ledger close time, `scp_timing.ledger_target_close_time_milliseconds`. */
  async targetCloseMs() {
    const key = xdr.LedgerKey.configSetting(new xdr.LedgerKeyConfigSetting({ configSettingId: xdr.ConfigSettingId.configSettingScpTiming() }));
    const { entries } = await this.call('getLedgerEntries', { keys: [key.toXDR('base64')] });
    return xdr.LedgerEntryData.fromXDR(entries[0].xdr, 'base64').configSetting().contractScpTiming().ledgerTargetCloseTimeMilliseconds();
  }

  async fund(kp) {
    for (let attempt = 1; ; attempt++) {
      const r = await fetch(`${this.friendbotUrl}?addr=${kp.publicKey()}`);
      const text = await r.text();
      if (r.ok || text.includes('createAccountAlreadyExist') || text.includes('op_already_exists')) return;
      if (r.status < 500 || attempt === 20) throw new Error(`friendbot ${r.status}: ${text.slice(0, 200)}`);
      await sleep(3_000);
    }
  }

  async funded(label) {
    const kp = typeof label === 'string' ? Keypair.random() : label;
    await this.fund(kp);
    return kp;
  }

  async build(source, op) {
    return new TransactionBuilder(await this.server.getAccount(source.publicKey()), {
      fee: this.baseFee,
      networkPassphrase: this.passphrase,
    })
      .addOperation(op)
      .setTimeout(180)
      .build();
  }

  /**
   * Simulate `op` from `source`; throws `Refused('simulation', …)` on a host
   * error. A public RPC behind a load balancer can answer from a node a
   * ledger behind the one that confirmed the previous transaction, so a
   * just-written entry it reports missing is retried a few times.
   */
  async simulate(source, op, authMode = 'record') {
    for (let attempt = 1; ; attempt++) {
      const tx = await this.build(source, op);
      const sim = await this.server.simulateTransaction(tx, undefined, authMode);
      if (!rpc.Api.isSimulationError(sim)) return { tx, sim };
      const refused = decodeHostError(sim.error, sim.events ?? []);
      if (refused.kind === 'other' && /Storage, MissingValue/.test(refused.raw) && attempt < 6) {
        await sleep(2_500);
        continue;
      }
      throw new Refused('simulation', refused);
    }
  }

  /** The return value of `contract.fn(args)`, simulated (a read). */
  async read(contract, fn, args = [], source = this.reader) {
    source ??= this.reader = Keypair.random();
    const op = Operation.invokeContractFunction({ contract, function: fn, args });
    // A read needs an existing source account only for its sequence number.
    const tx = new TransactionBuilder(new Account(source.publicKey(), '0'), {
      fee: '100',
      networkPassphrase: this.passphrase,
    })
      .addOperation(op)
      .setTimeout(60)
      .build();
    for (let attempt = 1; ; attempt++) {
      const sim = await this.server.simulateTransaction(tx);
      if (!rpc.Api.isSimulationError(sim)) return sim.result?.retval ? scValToNative(sim.result.retval) : undefined;
      const refused = decodeHostError(sim.error, sim.events ?? []);
      if (refused.kind === 'other' && /Storage, MissingValue/.test(refused.raw) && attempt < 6) {
        await sleep(2_500);
        continue;
      }
      throw new Refused('simulation', refused);
    }
  }

  /**
   * Simulate, assemble, sign and send `op` from `source`, and wait for its
   * result. Returns the return value and the transaction's measurement.
   * Throws `Refused` at the stage that refused it.
   */
  async send(source, op, opts = {}) {
    const { authMode = 'record', label = '' } = opts;
    const t0 = performance.now();
    const { tx, sim } = await this.simulate(source, op, authMode);
    const tSim = performance.now();
    const prepared = rpc.assembleTransaction(tx, sim).build();
    prepared.sign(source);
    let sent = await this.server.sendTransaction(prepared);
    for (let attempt = 1; sent.status === 'TRY_AGAIN_LATER' && attempt < 6; attempt++) {
      await sleep(2_500);
      sent = await this.server.sendTransaction(prepared);
    }
    if (sent.status === 'ERROR' && /txBadSeq/.test(JSON.stringify(sent.errorResult?.result().switch().name ?? '')) && !opts.retried) {
      // The account was read from a node a ledger behind: rebuild once.
      await sleep(2_500);
      return this.send(source, op, { ...opts, retried: true });
    }
    if (sent.status === 'ERROR' || sent.status === 'TRY_AGAIN_LATER') {
      const code = sent.errorResult?.result().switch().name ?? sent.status;
      throw new Refused('submission', { kind: code, label, fee: prepared.fee, raw: sent.errorResult?.toXDR('base64') ?? '', ...measure(prepared, undefined, sim) });
    }
    const tSent = performance.now();
    let got;
    for (let i = 0; i < 240; i++) {
      got = await this.server.getTransaction(sent.hash);
      if (got.status !== 'NOT_FOUND') break;
      await sleep(250);
    }
    const tDone = performance.now();
    const m = measure(prepared, got, sim);
    const entry = {
      label,
      hash: sent.hash,
      status: got.status,
      ledger: got.ledger,
      ms: { simulate: Math.round(tSim - t0), submit: Math.round(tSent - tSim), confirm: Math.round(tDone - tSent), total: Math.round(tDone - t0) },
      ...m,
    };
    this.log.push(entry);
    if (this.settleMs) await sleep(this.settleMs);
    if (got.status !== 'SUCCESS') {
      const diag = got.diagnosticEventsXdr ?? [];
      throw new Refused('execution', { ...decodeHostError(JSON.stringify(got.resultXdr?.result().switch().name ?? ''), diag), hash: sent.hash });
    }
    return { value: got.returnValue ? scValToNative(got.returnValue) : undefined, scVal: got.returnValue, ...entry };
  }

  /**
   * Restore archived ledger entries (`keys`, LedgerKey XDR) with one
   * RestoreFootprint transaction from `source`; returns its measurement.
   */
  async restore(source, keys, { label = 'restore' } = {}) {
    const t0 = performance.now();
    const tx = new TransactionBuilder(await this.server.getAccount(source.publicKey()), { fee: this.baseFee, networkPassphrase: this.passphrase })
      .addOperation(Operation.restoreFootprint({}))
      .setSorobanData(new SorobanDataBuilder().setReadWrite(keys).build())
      .setTimeout(180)
      .build();
    const sim = await this.server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) throw new Refused('simulation', decodeHostError(sim.error, sim.events ?? []));
    const prepared = rpc.assembleTransaction(tx, sim).build();
    prepared.sign(source);
    const sent = await this.server.sendTransaction(prepared);
    if (sent.status !== 'PENDING' && sent.status !== 'DUPLICATE') throw new Refused('submission', { kind: sent.errorResult?.result().switch().name ?? sent.status, label });
    let got;
    for (let i = 0; i < 240; i++) {
      got = await this.server.getTransaction(sent.hash);
      if (got.status !== 'NOT_FOUND') break;
      await sleep(250);
    }
    const entry = { label, hash: sent.hash, status: got.status, ledger: got.ledger, ms: { total: Math.round(performance.now() - t0) }, ...measure(prepared, got, sim) };
    this.log.push(entry);
    if (this.settleMs) await sleep(this.settleMs);
    if (got.status !== 'SUCCESS') throw new Refused('execution', { kind: got.status, label, hash: sent.hash });
    return entry;
  }

  /** The keys among `keys` whose entries are archived (live until a past ledger, or reported at 0). */
  async archived(keys) {
    const latest = await this.ledger();
    const r = await this.server.getLedgerEntries(...keys);
    return keys.filter((k) => {
      const e = r.entries.find((x) => x.key.toXDR('base64') === k.toXDR('base64'));
      return !e || !e.liveUntilLedgerSeq || e.liveUntilLedgerSeq < latest;
    });
  }

  /** `send`, but a refusal is returned rather than thrown. */
  async attempt(source, op, opts) {
    try {
      return { ok: true, ...(await this.send(source, op, opts)) };
    } catch (e) {
      if (e instanceof Refused) return { ok: false, refused: e };
      throw e;
    }
  }

  invoke(source, contract, fn, args, opts) {
    return this.send(source, Operation.invokeContractFunction({ contract, function: fn, args }), opts);
  }
}

/**
 * A sent transaction's resources and fee, from the envelope and the
 * network's result: the declared Soroban resources (what the transaction
 * paid for), the metered figures the host reported (`core_metrics`
 * diagnostic events, when the network emits them), the envelope's size, and
 * the fee the network charged.
 */
export function measure(envelope, got, sim) {
  const out = {};
  const env = envelope.toEnvelope();
  out.envelopeBytes = env.toXDR().length;
  const data = envelope.toEnvelope().v1().tx().ext().value();
  if (data) {
    const r = data.resources();
    out.declared = {
      instructions: r.instructions(),
      diskReadBytes: r.diskReadBytes(),
      writeBytes: r.writeBytes(),
      readOnly: r.footprint().readOnly().length,
      readWrite: r.footprint().readWrite().length,
      resourceFee: Number(data.resourceFee().toBigInt()),
    };
    out.footprint = { readOnly: r.footprint().readOnly().map(describeKey), readWrite: r.footprint().readWrite().map(describeKey) };
  }
  out.simulated = { instructions: Number(sim?.cost?.cpuInsns ?? 0), memBytes: Number(sim?.cost?.memBytes ?? 0), minResourceFee: Number(sim?.minResourceFee ?? 0) };
  out.authEntryBytes = env.v1().tx().operations().reduce(
    (n, op) => n + (op.body().switch().name === 'invokeHostFunction' ? op.body().invokeHostFunctionOp().auth().reduce((m, a) => m + a.toXDR().length, 0) : 0),
    0,
  );
  if (got?.resultXdr) out.feeCharged = Number(got.resultXdr.feeCharged().toBigInt());
  try {
    const meta = got?.resultMetaXdr;
    const v = meta?.switch?.();
    const soroban = v === 4 ? meta.v4().sorobanMeta() : v === 3 ? meta.v3().sorobanMeta() : undefined;
    const ext = soroban?.ext?.();
    if (ext && ext.switch() === 1) {
      const v1 = ext.v1();
      out.feeSplit = {
        nonRefundableResource: Number(v1.totalNonRefundableResourceFeeCharged().toBigInt()),
        refundableResource: Number(v1.totalRefundableResourceFeeCharged().toBigInt()),
        rent: Number(v1.rentFeeCharged().toBigInt()),
      };
    }
  } catch {
    // Older meta versions have no fee split.
  }
  const metrics = {};
  for (const d of got?.diagnosticEventsXdr ?? []) {
    try {
      const body = d.event().body().v0();
      const topics = body.topics().map((t) => (t.switch().name === 'scvSymbol' ? t.sym().toString() : null));
      if (topics[0] === 'core_metrics' && topics[1]) metrics[topics[1]] = Number(scValToNative(body.data()));
    } catch {
      // Not a metrics event.
    }
  }
  if (Object.keys(metrics).length) out.metered = metrics;
  return out;
}

/** A ledger key in a few words: its type, its owner, and for contract data its durability and key. */
export function describeKey(k) {
  const t = k.switch().name;
  try {
    if (t === 'contractData') {
      const d = k.contractData();
      const key = d.key().switch().name === 'scvLedgerKeyContractInstance' ? 'instance' : (() => {
        try {
          const v = scValToNative(d.key());
          return Array.isArray(v) ? String(v[0]) : typeof v === 'object' ? Object.keys(v)[0] : String(v);
        } catch {
          return d.key().switch().name;
        }
      })();
      return `data ${Address.fromScAddress(d.contract()).toString().slice(0, 6)} ${d.durability().name} ${key}`;
    }
    if (t === 'contractCode') return `code ${Buffer.from(k.contractCode().hash()).toString('hex').slice(0, 8)}`;
    if (t === 'account') return `account ${StrKey.encodeEd25519PublicKey(k.account().accountId().ed25519()).slice(0, 6)}`;
  } catch {
    // Fall through to the type alone.
  }
  return t;
}

export const sc = {
  address: (a) => Address.fromString(a).toScVal(),
  bytes: (b) => xdr.ScVal.scvBytes(Buffer.from(b)),
  u32: (n) => xdr.ScVal.scvU32(n),
  u64: (n) => xdr.ScVal.scvU64(xdr.Uint64.fromString(BigInt(n).toString())),
  sym: (s) => xdr.ScVal.scvSymbol(s),
  vec: (v) => xdr.ScVal.scvVec(v),
  /** A `#[contracttype]` struct: a map from field symbols, in sorted order. */
  struct: (fields) =>
    xdr.ScVal.scvMap(
      Object.keys(fields)
        .sort()
        .map((k) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: fields[k] })),
    ),
};
