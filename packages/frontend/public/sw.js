// The wallet's service worker: it receives the recovery alerts the alert
// vault pushes (docs/email-recovery/spec.md §10.6), RFC 8291-encrypted to
// this device's subscription, which the browser decrypts before this runs.
// An alert's payload is {v, kind, title, body, code}. It carries no link to
// act on: a click opens the wallet's own recovery page, never a URL from the
// payload. It handles no fetches.
//
// Real alerts and the liveness probe look different on purpose: an alert's
// title starts "Security alert:", it carries the red alert icon and stays
// until dismissed; the probe ({v, kind: 'probe', probe}, monthly by default)
// carries the wallet's own icon and asks to be tapped. WebKit revokes a
// subscription whose pushes show nothing
// (https://webkit.org/blog/12945/meet-web-push/), so the probe is visible.
//
// The device key. With each subscription the wallet asks this worker for
// its device key ({type: 'nido-device-key', alertService}): an ECDSA P-256
// key pair made once with WebCrypto, its private half not extractable, kept
// in this origin's IndexedDB with the alert service's address. A tap on the
// probe signs `"nido/email-recovery/v1/probe-ack" || probe id` with it and
// posts {probe, signature} to the alert service's /v1/ack; on success it
// records when ({type: 'nido-device-state'} answers it), so the wallet can
// say that alerts reach this device only after a recent confirmation.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

const PROBE_ACK_LABEL = 'nido/email-recovery/v1/probe-ack';

function store(mode, use) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('nido-alerts', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('device');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const req = use(open.result.transaction('device', mode).objectStore('device'));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    };
  });
}
const get = (key) => store('readonly', (s) => s.get(key));
const put = (key, value) => store('readwrite', (s) => s.put(value, key));

const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

/** This origin's device key's public half (uncompressed P-256), made on first use. */
async function deviceKey(alertService) {
  let key = await get('key');
  if (!key) {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    key = { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)) };
    await put('key', key);
  }
  await put('alertService', alertService);
  return key.publicKey;
}

/** Sign and post the acknowledgement of probe `probe` (base64url); record when it was accepted. */
async function acknowledge(probe) {
  const [key, alertService] = await Promise.all([get('key'), get('alertService')]);
  if (!key || !alertService) return false;
  const id = unb64u(probe);
  const label = new TextEncoder().encode(PROBE_ACK_LABEL);
  const message = new Uint8Array(label.length + id.length);
  message.set(label);
  message.set(id, label.length);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, message));
  const r = await fetch(`${alertService}/v1/ack`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ probe, signature: b64u(signature) }),
    credentials: 'omit',
  });
  if (!r.ok) return false;
  await put('ackedAt', Date.now());
  return true;
}

self.addEventListener('message', (event) => {
  const port = event.ports && event.ports[0];
  const m = event.data || {};
  if (!port) return;
  const answer = (p) => p.then((x) => port.postMessage(x), (e) => port.postMessage({ error: String((e && e.message) || e) }));
  if (m.type === 'nido-device-key') event.waitUntil(answer(deviceKey(String(m.alertService)).then((k) => ({ deviceKey: b64u(k) }))));
  else if (m.type === 'nido-device-state') event.waitUntil(answer(get('ackedAt').then((ackedAt) => ({ ackedAt: ackedAt ?? null }))));
});

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = {};
  }
  if (data.kind === 'probe') {
    event.waitUntil(
      self.registration.showNotification('Nido: tap to confirm your alerts', {
        body: 'Tap here to confirm this device still gets your Nido’s recovery alerts. Nido asks about once a month.',
        tag: 'nido-probe',
        icon: '/favicon.svg',
        data: { probe: typeof data.probe === 'string' ? data.probe : '' },
      }),
    );
    return;
  }
  const title = typeof data.title === 'string' ? data.title : 'Something changed in your Nido’s recovery';
  const code = typeof data.code === 'string' && /^\d{6}$/.test(data.code) ? `${data.code.slice(0, 3)} ${data.code.slice(3)}` : '';
  const body = (typeof data.body === 'string' ? data.body : 'Open your wallet to see what changed.') + (code ? ` Code ${code}.` : '');
  event.waitUntil(
    self.registration.showNotification(`Security alert: ${title}`, {
      body,
      tag: typeof data.kind === 'string' ? data.kind : 'nido-alert',
      icon: '/alert.svg',
      requireInteraction: true,
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  if (event.notification.tag === 'nido-probe') {
    const probe = (event.notification.data && event.notification.data.probe) || '';
    event.waitUntil(
      acknowledge(probe)
        .catch(() => false)
        .then((ok) => self.clients.openWindow(ok ? '/security/recovery/#alerts-confirmed' : '/security/recovery/')),
    );
    return;
  }
  event.waitUntil(self.clients.openWindow('/security/recovery/'));
});
