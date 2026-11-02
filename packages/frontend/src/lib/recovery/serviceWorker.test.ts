// @vitest-environment node
// The wallet's service worker (public/sw.js, docs/email-recovery/spec.md
// §10.6), run against a stand-in for its global scope: the probe asks to be
// tapped and looks unlike an alert; a tap signs the probe id with the device
// key it made, posts it to the alert service, and records when; alerts carry
// their own title prefix and icon.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createPublicKey, verify, webcrypto } from 'node:crypto';
import { probeAckMessage } from '@nidohq/email-recovery';
import { beforeEach, describe, expect, it, vi } from 'vitest';

type Listener = (event: Record<string, unknown>) => void;

/** An in-memory IndexedDB with the one database and object store the worker opens. */
function memoryIndexedDb() {
  const data = new Map<string, unknown>();
  let created = false;
  const request = <T>(result: () => T) => {
    const r: { result?: T; onsuccess?: () => void; onerror?: () => void } = {};
    queueMicrotask(() => {
      r.result = result();
      r.onsuccess?.();
    });
    return r;
  };
  const db = {
    createObjectStore: () => (created = true),
    transaction: () => ({
      objectStore: () => ({
        get: (k: string) => request(() => data.get(k)),
        put: (v: unknown, k: string) => request(() => void data.set(k, v)),
      }),
    }),
  };
  return {
    data,
    open() {
      const r: { result?: typeof db; onupgradeneeded?: () => void; onsuccess?: () => void; onerror?: () => void } = {};
      queueMicrotask(() => {
        r.result = db;
        if (!created) r.onupgradeneeded?.();
        r.onsuccess?.();
      });
      return r;
    },
  };
}

function loadWorker() {
  const listeners = new Map<string, Listener>();
  const shown: { title: string; options: Record<string, unknown> }[] = [];
  const opened: string[] = [];
  const posts: { url: string; body: { probe: string; signature: string } }[] = [];
  const self = {
    addEventListener: (type: string, fn: Listener) => listeners.set(type, fn),
    skipWaiting: () => {},
    clients: { claim: async () => {}, openWindow: async (url: string) => void opened.push(url) },
    registration: { showNotification: async (title: string, options: Record<string, unknown>) => void shown.push({ title, options }) },
  };
  const fetch = vi.fn(async (url: string, init: { body: string }) => {
    posts.push({ url, body: JSON.parse(init.body) });
    return { ok: true };
  });
  const idb = memoryIndexedDb();
  const src = readFileSync(fileURLToPath(new URL('../../../public/sw.js', import.meta.url)), 'utf8');
  new Function('self', 'indexedDB', 'crypto', 'fetch', src)(self, idb, webcrypto, fetch);
  /** Dispatch an event and wait for what it handed to `waitUntil`. */
  const dispatch = async (type: string, event: Record<string, unknown>) => {
    let wait: Promise<unknown> = Promise.resolve();
    listeners.get(type)!({ ...event, waitUntil: (p: Promise<unknown>) => (wait = p) });
    await wait;
  };
  const ask = async (data: Record<string, unknown>) => {
    let answer: Record<string, unknown> | undefined;
    await dispatch('message', { data, ports: [{ postMessage: (m: Record<string, unknown>) => (answer = m) }] });
    return answer!;
  };
  return { shown, opened, posts, idb, dispatch, ask };
}

const push = (payload: unknown) => ({ data: { json: () => payload } });
const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');

let sw: ReturnType<typeof loadWorker>;
beforeEach(() => {
  sw = loadWorker();
});

describe('the service worker', () => {
  it('creates one device key per origin and keeps where acknowledgements go', async () => {
    const a = await sw.ask({ type: 'nido-device-key', alertService: 'https://alerts.nido.test' });
    const b = await sw.ask({ type: 'nido-device-key', alertService: 'https://alerts.nido.test' });
    const key = Buffer.from(String(a.deviceKey), 'base64url');
    expect(key).toHaveLength(65);
    expect(key[0]).toBe(4);
    expect(b.deviceKey).toBe(a.deviceKey);
    expect((sw.idb.data.get('key') as { privateKey: CryptoKey }).privateKey.extractable).toBe(false);
    expect(await sw.ask({ type: 'nido-device-state' })).toEqual({ ackedAt: null });
  });

  it('shows a probe as a request to tap, never as nothing to do, and unlike an alert', async () => {
    await sw.dispatch('push', push({ v: 1, kind: 'probe', probe: b64u(new Uint8Array(16).fill(1)) }));
    const [n] = sw.shown;
    expect(n!.title).toBe('Nido: tap to confirm your alerts');
    expect(n!.options.body).toBe('Tap here to confirm this device still gets your Nido’s recovery alerts. Nido asks about once a month.');
    expect(String(n!.options.body)).not.toMatch(/nothing to do/i);
    expect(n!.options).toMatchObject({ tag: 'nido-probe', icon: '/favicon.svg' });

    await sw.dispatch('push', push({ v: 1, kind: 'attempt_authorized', title: 'Account recovery approved', body: 'Lead.', code: '169328' }));
    const alert = sw.shown[1]!;
    expect(alert.title).toBe('Security alert: Account recovery approved');
    expect(alert.options).toMatchObject({ body: 'Lead. Code 169 328.', icon: '/alert.svg', requireInteraction: true, tag: 'attempt_authorized:169328' });
  });

  it('alerts of one kind for different attempts are separate notifications, and each one sounds', async () => {
    await sw.dispatch('push', push({ v: 1, kind: 'email_vote_recorded', title: 'Your email approved a recovery', body: 'Lead.', code: '111111' }));
    await sw.dispatch('push', push({ v: 1, kind: 'email_vote_recorded', title: 'Your email approved a recovery', body: 'Lead.', code: '222222' }));
    const [a, b] = sw.shown;
    expect(a!.options.tag).not.toBe(b!.options.tag);
    expect([a!.options.renotify, b!.options.renotify]).toEqual([true, true]);
  });

  it('a tap on the probe signs its id with the device key, posts it, and records when', async () => {
    const { deviceKey } = await sw.ask({ type: 'nido-device-key', alertService: 'https://alerts.nido.test' });
    const probe = new Uint8Array(16).fill(0x2a);
    await sw.dispatch('push', push({ v: 1, kind: 'probe', probe: b64u(probe) }));
    const close = vi.fn();
    await sw.dispatch('notificationclick', { notification: { tag: 'nido-probe', data: sw.shown[0]!.options.data, close } });
    expect(close).toHaveBeenCalled();
    const [post] = sw.posts;
    expect(post!.url).toBe('https://alerts.nido.test/v1/ack');
    expect(post!.body.probe).toBe(b64u(probe));
    const raw = Buffer.from(String(deviceKey), 'base64url');
    const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64u(raw.subarray(1, 33)), y: b64u(raw.subarray(33)) }, format: 'jwk' });
    expect(verify('sha256', probeAckMessage(probe), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(post!.body.signature, 'base64url'))).toBe(true);
    expect(typeof (await sw.ask({ type: 'nido-device-state' })).ackedAt).toBe('number');
    expect(sw.opened).toEqual(['/security/recovery/#alerts-confirmed']);
  });

  it('a click on an alert opens the wallet’s recovery page, never a URL from the payload', async () => {
    await sw.dispatch('notificationclick', { notification: { tag: 'attempt_authorized', data: { url: 'https://evil.example' }, close: () => {} } });
    expect(sw.opened).toEqual(['/security/recovery/']);
    expect(sw.posts).toEqual([]);
  });
});
