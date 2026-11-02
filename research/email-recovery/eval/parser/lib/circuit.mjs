// The circuit side of the comparison: the signed header block, key and
// signature go through @nidohq/email-recovery's encoder functions (the
// block from `signedHeaderBlock`, the limbs and Barrett hint from `limbs` and
// `barrettHint`) and are executed with noir_js, without proving, in a pool of
// worker threads.
//
// Each input runs through the parser harness (harness/, the recovery
// circuit's header checks without the recovery Subject's value; it returns
// the From address, the lowercase d= and the key hash, and the hints the
// checks ran on). `run` lets the harness find the hints as the honest prover
// does; `runWithHints` runs the checks on hints the caller chooses. With `crossCheck`,
// the same input also runs through the committed recovery artifact
// (circuits/email-recovery/artifacts/recovery.json) with placeholder public
// inputs: a message the harness refuses must be refused there with the same
// assertion, and one it accepts must be refused there first by a Subject
// assertion, since a real message carries no recovery Subject.

import { existsSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { HEADER_MAX, REGISTRY_DEPTH, barrettHint, limbs } from '@nidohq/email-recovery';

/** `DKIM_TAGS_MAX` of circuits/email-recovery/lib/src/spec.nr. */
export const DKIM_TAGS_MAX = 16;

const here = fileURLToPath(new URL('.', import.meta.url));
export const HARNESS = join(here, '../harness/target/parser_harness.json');
/** The recovery artifact the cross-check runs; PARSER_CHECK_ARTIFACT selects another build. */
export const RECOVERY = process.env.PARSER_CHECK_ARTIFACT ?? join(here, '../../../../../circuits/email-recovery/artifacts/recovery.json');

const hex = (x) => `0x${x.toString(16)}`;

/** The harness's hint inputs: `hints` (numbers) when given, zeros (unused) otherwise. */
function hintInputs(hints) {
  const h = hints ?? { from: { addr_start: 0, addr_len: 0, at_index: 0 }, tags: { tag_starts: new Array(DKIM_TAGS_MAX).fill(0), tag_count: 0, h_from: 0, h_subject: 0, t_len: 0 } };
  return {
    hint_override: hints !== undefined,
    given_hints: {
      from: { addr_start: hex(h.from.addr_start), addr_len: hex(h.from.addr_len), at_index: hex(h.from.at_index) },
      tags: { tag_starts: h.tags.tag_starts.map(hex), tag_count: hex(h.tags.tag_count), h_from: hex(h.tags.h_from), h_subject: hex(h.tags.h_subject), t_len: hex(h.tags.t_len) },
    },
  };
}

/** The hints the harness returns, as numbers. */
export function hintsOf(returned) {
  const n = (x) => Number(BigInt(x));
  return {
    from: { addr_start: n(returned.from.addr_start), addr_len: n(returned.from.addr_len), at_index: n(returned.from.at_index) },
    tags: { tag_starts: returned.tags.tag_starts.map(n), tag_count: n(returned.tags.tag_count), h_from: n(returned.tags.h_from), h_subject: n(returned.tags.h_subject), t_len: n(returned.tags.t_len) },
  };
}

/** The harness's inputs, or the reason the circuit cannot take them at all. */
export function harnessInputs(header, modulus, signature, hints) {
  if (header.length > HEADER_MAX) return { error: `encoder: the signed header block is ${header.length} octets; the circuit takes at most ${HEADER_MAX}` };
  let sig;
  let mod;
  let redc;
  try {
    mod = limbs(modulus).map(hex);
    sig = limbs(signature).map(hex);
  } catch (err) {
    return { error: `encoder: ${err.message}` };
  }
  try {
    redc = limbs(barrettHint(modulus)).map(hex);
  } catch {
    // The hint of a modulus below 2^2048 does not fit; the hint is read only
    // by unconstrained code, so any value lets the circuit judge the modulus.
    redc = new Array(mod.length).fill('0x0');
  }
  const storage = new Array(HEADER_MAX).fill(0);
  header.forEach((b, i) => (storage[i] = b));
  return { inputs: { header: { storage, len: header.length }, modulus: mod, redc, signature: sig, ...hintInputs(hints) } };
}

/** The recovery circuit's inputs for the same header, key and signature, with placeholder public inputs and openings. */
function artifactInputs({ header, modulus, redc, signature }) {
  return {
    commitment: '0x1',
    digest_hi: '0x2',
    digest_lo: '0x3',
    key_root: '0x4',
    header,
    modulus,
    redc,
    signature,
    rho: '0x5',
    account_code: '0x6',
    key_index: '0x0',
    key_siblings: new Array(REGISTRY_DEPTH).fill('0x0'),
  };
}

/** Whether a recovery-artifact refusal is one of the Subject module's assertions. */
export const isSubjectRefusal = (refusal) => /^Subject: /.test(refusal ?? '');

export class CircuitPool {
  constructor({ jobs = Math.max(1, availableParallelism() - 1), crossCheck = false } = {}) {
    if (!existsSync(HARNESS)) {
      throw new Error(`${HARNESS} is missing: compile it with the pinned nargo (research/email-recovery/eval/parser/check.sh does)`);
    }
    this.crossCheck = crossCheck;
    this.queue = [];
    this.waiting = new Map();
    this.nextId = 0;
    this.executions = 0;
    this.idle = [];
    this.workers = Array.from({ length: jobs }, () => {
      const w = new Worker(join(here, 'worker.mjs'), { workerData: { harness: HARNESS, recovery: RECOVERY } });
      w.on('message', (res) => {
        this.waiting.get(res.id)(res);
        this.waiting.delete(res.id);
        this.dispatch(w);
      });
      w.on('error', (err) => {
        throw err;
      });
      return w;
    });
    this.idle.push(...this.workers);
  }

  dispatch(worker) {
    const job = this.queue.shift();
    if (job) worker.postMessage(job);
    else this.idle.push(worker);
  }

  /**
   * Executes the circuit on `header` (octets) under `modulus` with
   * `signature`. Resolves to `{ harness: { accepted, address, domain, keyHash }
   * | { accepted: false, refusal }, artifact?: { accepted, refusal } }`.
   */
  run(header, modulus, signature) {
    return this.runWithHints(header, modulus, signature, undefined);
  }

  /**
   * `run` with the harness's checks on `hints` (`{ from: { addr_start,
   * addr_len, at_index }, tags: { tag_starts, tag_count, h_from, h_subject,
   * t_len } }`, numbers) instead of the ones it finds; `undefined` finds them.
   */
  runWithHints(header, modulus, signature, hints) {
    const built = harnessInputs(header, modulus, signature, hints);
    if (built.error) return Promise.resolve({ harness: { accepted: false, refusal: built.error }, encoderRefusal: true });
    const id = this.nextId++;
    const job = { id, inputs: built.inputs, artifactInputs: this.crossCheck ? artifactInputs(built.inputs) : undefined };
    this.executions += this.crossCheck ? 2 : 1;
    const done = new Promise((resolve) => this.waiting.set(id, resolve));
    const w = this.idle.pop();
    if (w) w.postMessage(job);
    else this.queue.push(job);
    return done;
  }

  async close() {
    await Promise.all(this.workers.map((w) => w.terminate()));
  }
}

/**
 * Whether the recovery artifact's verdict agrees with the harness's: the same
 * refusal, or a Subject refusal where the harness accepts.
 */
export function crossCheckAgrees(res) {
  if (!res.artifact) return true;
  if (res.artifact.accepted) return false;
  return res.harness.accepted ? isSubjectRefusal(res.artifact.refusal) : res.artifact.refusal === res.harness.refusal;
}
