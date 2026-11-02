/**
 * The host's poll driver (`docs/email-recovery/spec.md` §10.2): what runs
 * [`AlertService.pollOnce`] for as long as the host runs.
 *
 * - **Drains while behind.** A poll that is not caught up (either cursor
 *   short of the latest ledger) is followed by the next at once. In the
 *   recorded hour of mainnet (spec §12) a ledger held 263 transactions on
 *   average and up to 1,011, 1.31 pages of 200, whose reads took 1.44 s of
 *   each 5-second ledger: a scan that waited between pages would fall
 *   behind for good.
 * - **One interval once caught up**, `intervalMs` (default
 *   [`POLL_INTERVAL_MS`], one ledger at the 5-second target close time): an
 *   alert follows its vote by at most one interval plus the reads. A poll
 *   that read nothing at all also waits one interval, so a cursor that
 *   cannot reach the head (short pages below it) is read again at that pace
 *   rather than in a tight loop.
 * - **Backs off on failure.** A failed poll (the RPC unreachable, an HTTP
 *   429 or 5xx, a timeout) waits `backoffMs`, doubling up to
 *   `maxBackoffMs`; once polls have failed for `failingAlarmMs` the driver
 *   raises the host's alarm (the log, `onAlarm`, `GET /v1/health`), which
 *   the next caught-up poll clears.
 * - **Retention exceeded** is the poll's own case: a cursor the RPC refuses
 *   (-32600, the events or transactions after it aged out) raises an alarm,
 *   restarts both cursors at the oldest ledger the RPC keeps, and reconciles
 *   every account from controller state.
 *
 * It stops when `signal` aborts.
 */
import type { AlertService, PollReport } from './service.js';

/** Wait between polls once caught up: one ledger at the 5-second target close time. */
export const POLL_INTERVAL_MS = 5_000;
/** First wait after a failed poll; it doubles up to [`MAX_BACKOFF_MS`]. */
export const BACKOFF_MS = 1_000;
export const MAX_BACKOFF_MS = 60_000;
/** Polls failing for this long raise an alarm. */
export const FAILING_ALARM_MS = 5 * 60_000;

export interface DriverConfig {
  intervalMs?: number;
  backoffMs?: number;
  maxBackoffMs?: number;
  failingAlarmMs?: number;
  signal?: AbortSignal;
  /** Called with each poll's report. */
  onReport?: (r: PollReport) => void;
  /** Called with each failed poll's error. */
  onError?: (e: unknown) => void;
  now?: () => number;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
}

/** Resolves after `ms`, or at once when `signal` aborts. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(done, ms);
    function done() {
      clearTimeout(t);
      signal?.removeEventListener('abort', done);
      resolve();
    }
    signal?.addEventListener('abort', done, { once: true });
  });
}

/** How long to wait before the next poll after `r`. */
export function nextPollIn(r: PollReport, intervalMs = POLL_INTERVAL_MS): number {
  return r.caughtUp || (r.events === 0 && r.transactions === 0) ? intervalMs : 0;
}

/** Poll `service` until `cfg.signal` aborts. */
export async function runWatcher(service: Pick<AlertService, 'pollOnce' | 'raise'>, cfg: DriverConfig = {}): Promise<void> {
  const wait = cfg.sleep ?? sleep;
  const now = cfg.now ?? Date.now;
  const interval = cfg.intervalMs ?? POLL_INTERVAL_MS;
  const base = cfg.backoffMs ?? BACKOFF_MS;
  const max = cfg.maxBackoffMs ?? MAX_BACKOFF_MS;
  const alarmAfter = cfg.failingAlarmMs ?? FAILING_ALARM_MS;
  let failures = 0;
  let failingSince: number | undefined;
  let alarmed = false;
  while (!cfg.signal?.aborted) {
    let ms: number;
    try {
      const r = await service.pollOnce();
      failures = 0;
      failingSince = undefined;
      alarmed = false;
      cfg.onReport?.(r);
      ms = nextPollIn(r, interval);
    } catch (e) {
      failures++;
      failingSince ??= now();
      cfg.onError?.(e);
      if (!alarmed && now() - failingSince >= alarmAfter) {
        service.raise(`polls have failed for ${Math.round((now() - failingSince) / 1000)} s (${(e as Error).message ?? e})`);
        alarmed = true;
      }
      ms = Math.min(base * 2 ** (failures - 1), max);
    }
    if (ms > 0) await wait(ms, cfg.signal);
  }
}
