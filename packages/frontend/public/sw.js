// The wallet's service worker: it receives the recovery alerts the alert
// vault pushes (docs/email-recovery/spec.md §10.6), RFC 8291-encrypted to
// this device's subscription, which the browser decrypts before this runs.
// The payload is {v, kind, title, body, code}. An alert carries no link to
// act on: a click opens the wallet's own security page, never a URL from the
// payload. It handles no fetches.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = {};
  }
  const title = typeof data.title === 'string' ? data.title : 'Nido security alert';
  const code = typeof data.code === 'string' && /^\d{6}$/.test(data.code) ? `${data.code.slice(0, 3)} ${data.code.slice(3)}` : '';
  const body = (typeof data.body === 'string' ? data.body : 'Something changed in your Nido’s recovery.') + (code ? ` Code ${code}.` : '');
  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag: typeof data.kind === 'string' ? data.kind : 'nido-alert',
      icon: '/favicon.svg',
      requireInteraction: true,
    }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(self.clients.openWindow('/security/'));
});
