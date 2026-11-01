/**
 * The vault's Web Push encryption against RFC 8291's published example, and
 * its VAPID header against the push-service mock's RFC 8292 checks.
 */
import { PushServiceMock, PushUserAgentMock, decryptWebPush } from '@nidohq/email-mocks';
import { describe, expect, it } from 'vitest';
import { encryptWebPush, pushMessage } from '../src/vault/webpush.js';

const u = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

/** RFC 8291 §5 and Appendix A. */
const RFC8291 = {
  asPrivate: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
  uaPrivate: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94',
  uaPublic: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  auth: 'BTBZMqHH6r4Tts7J_aSIgg',
  salt: 'DGv6ra1nlYgDCS1FRnbzlw',
  header: 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  ciphertext: '8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ',
};

describe('Web Push from the vault', () => {
  it('reproduces the RFC 8291 example byte for byte', () => {
    const body = encryptWebPush(
      { p256dh: u(RFC8291.uaPublic), auth: u(RFC8291.auth) },
      new TextEncoder().encode('When I grow up, I want to be a watermelon'),
      { asPrivate: u(RFC8291.asPrivate), salt: u(RFC8291.salt) },
    );
    expect(Buffer.from(body)).toEqual(Buffer.concat([u(RFC8291.header), u(RFC8291.ciphertext)]));
  });

  it('is accepted by the push service (VAPID) and decrypted by the browser', async () => {
    const service = new PushServiceMock();
    await service.listen();
    try {
      const ecdh = (await import('node:crypto')).createECDH('prime256v1');
      ecdh.generateKeys();
      const vapid = { privateKey: new Uint8Array(ecdh.getPrivateKey()), publicKey: new Uint8Array(ecdh.getPublicKey()) };
      const ua = new PushUserAgentMock(service);
      const sub = ua.subscribe(vapid.publicKey);
      const target = { endpoint: sub.endpoint, p256dh: u(sub.keys.p256dh), auth: u(sub.keys.auth) };
      const msg = new TextEncoder().encode('{"code":"123456"}');
      const r = await pushMessage(target, msg, { vapid, subject: 'mailto:alerts@nido.test', ttl: 60, urgency: 'high', topic: 'abc' });
      expect(r).toEqual({ outcome: 'accepted', status: 201 });
      const [got] = ua.receive();
      expect(Buffer.from(got!.payload).toString()).toBe('{"code":"123456"}');
      expect(got!.message).toMatchObject({ urgency: 'high', topic: 'abc', ttl: 60, sender: 'mailto:alerts@nido.test' });
      // A key the subscription was not created with is refused.
      const other = (await import('node:crypto')).createECDH('prime256v1');
      other.generateKeys();
      const bad = await pushMessage(
        target,
        msg,
        { vapid: { privateKey: new Uint8Array(other.getPrivateKey()), publicKey: new Uint8Array(other.getPublicKey()) }, subject: 'mailto:x@nido.test', ttl: 60, urgency: 'high', topic: 'abc' },
      );
      expect(bad).toEqual({ outcome: 'retry', status: 403 });
      expect(decryptWebPush).toBeTypeOf('function');
    } finally {
      await service.close();
    }
  });
});
