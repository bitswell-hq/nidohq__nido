import { describe, expect, it } from 'vitest';
import { MockDns, keyRecord } from '../src/dns.js';
import { RECOVERY_ADDRESS, generateEmail, launchDns } from '../src/generate.js';
import { InboundMx, SmtpReject, fromSmtpData, toSmtpData } from '../src/inbound.js';
import { verify, verifyTime } from './verify.js';

const email = generateEmail({
  provider: 'gmail',
  from: 'test.user@gmail.com',
  subject: 'Account recovery TEST-ONLY-0123456789abcdef',
  body: '.leading dot\r\nThis message is a test fixture.\r\n',
});
const envelope = { mailFrom: 'test.user@gmail.com', rcptTo: RECOVERY_ADDRESS };

describe('inbound MX mock', () => {
  const mx = new InboundMx({ recipient: RECOVERY_ADDRESS, now: () => new Date('2026-10-15T09:30:05Z') });

  it('hands on the submitted octets unchanged below its trace fields', () => {
    const delivered = mx.receive(email.eml, envelope);
    const bytes = Buffer.from(delivered.bytes);
    expect(bytes.subarray(0, delivered.trace.length).toString('latin1')).toBe(delivered.trace);
    expect(bytes.subarray(delivered.trace.length).equals(Buffer.from(email.eml))).toBe(true);
    expect(delivered.trace).toMatch(/^Return-Path: <test\.user@gmail\.com>\r\nReceived: from /);
  });

  it('round-trips SMTP DATA dot-stuffing', () => {
    const data = toSmtpData(email.eml);
    expect(Buffer.from(data).toString('latin1')).toContain('\r\n..leading dot\r\n');
    expect(Buffer.from(fromSmtpData(data)).equals(Buffer.from(email.eml))).toBe(true);
    const delivered = mx.receiveSmtpData(data, envelope);
    expect(Buffer.from(delivered.bytes).subarray(delivered.trace.length).equals(Buffer.from(email.eml))).toBe(true);
  });

  it('delivered mail still verifies', async () => {
    const delivered = mx.receive(email.eml, envelope);
    const results = await verify(delivered.bytes, launchDns(), verifyTime(email));
    expect(results.map((r) => r.result)).toEqual(['pass']);
  });

  it('accepts only the recovery address (domain case-insensitive, local part exact)', () => {
    expect(() => mx.receive(email.eml, { ...envelope, rcptTo: 'recover@RECOVERY.test' })).not.toThrow();
    expect(() => mx.receive(email.eml, { ...envelope, rcptTo: 'Recover@recovery.test' })).toThrow(SmtpReject);
    expect(() => mx.receive(email.eml, { ...envelope, rcptTo: 'other@recovery.test' })).toThrow(/550 5\.1\.1/);
  });

  it('refuses bare LF, bare CR and over-long lines', () => {
    const raw = Buffer.from(email.eml).toString('latin1');
    for (const bad of [raw.replace('\r\n\r\n', '\r\n\n'), raw.replace('\r\n\r\n', '\r\r\n\r\n'), `X-Long: ${'a'.repeat(1000)}\r\n${raw}`]) {
      expect(() => mx.receive(new Uint8Array(Buffer.from(bad, 'latin1')), envelope)).toThrow(/554 5\.6\.0/);
    }
  });

  it('can hand on the message with no trace fields', () => {
    const bare = new InboundMx({ recipient: RECOVERY_ADDRESS, trace: false }).receive(email.eml, envelope);
    expect(Buffer.from(bare.bytes).equals(Buffer.from(email.eml))).toBe(true);
  });
});

describe('mock DNS', () => {
  it('serves key records as 255-octet character-strings', async () => {
    const dns = launchDns();
    const chunks = await dns.resolver('20260707._domainkey.gmail.com', 'TXT');
    expect(chunks).toHaveLength(1);
    expect(chunks[0]!.every((c) => c.length <= 255)).toBe(true);
    expect(chunks[0]!.join('')).toMatch(/^v=DKIM1; k=rsa; p=MIIBIjAN[A-Za-z0-9+/=]{384}$/);
  });

  it('publishes each provider in its own record format', () => {
    const dns = launchDns();
    expect(dns.lookup('selector1._domainkey.outlook.com')![0]).toMatch(/^v=DKIM1;k=rsa;p=[^;]+;n=2048,\d+,\d+$/);
    expect(dns.lookup('s2048._domainkey.yahoo.com')![0]).toMatch(/^k=rsa; p=[^;]+;$/);
    expect(dns.lookup('s31663417._domainkey.gmx.net')![0]).toMatch(/^v=DKIM1; p=/);
    expect(dns.lookup('fm1._domainkey.fastmail.com')![0]).toBe('v=DKIM1; k=rsa; n=Intentionally_Left_Blank_As_Per_DKIM_Rotation_BCP; p=');
    expect(dns.lookup('20230601._domainkey.gmail.com')![0]).toBe('v=DKIM1; k=rsa; p=');
  });

  it('shares keys where the providers do and not elsewhere', () => {
    const dns = launchDns();
    const p = (name: string) => dns.lookup(name)![0]!.match(/p=([^;]*)/)![1];
    expect(p('20260707._domainkey.googlemail.com')).toBe(p('20260707._domainkey.gmail.com'));
    expect(p('selector1._domainkey.hotmail.com')).toBe(p('selector1._domainkey.outlook.com'));
    expect(p('s31663417._domainkey.gmx.de')).toBe(p('s31663417._domainkey.gmx.net'));
    expect(p('1a1hai._domainkey.me.com')).not.toBe(p('1a1hai._domainkey.icloud.com'));
    expect(p('protonmail3._domainkey.protonmail.com')).not.toBe(p('protonmail2._domainkey.proton.me'));
    expect(p('s29768273._domainkey.web.de')).not.toBe(p('s31663417._domainkey.gmx.net'));
  });

  it('answers NXDOMAIN and NODATA as dns.promises does', async () => {
    const dns = new MockDns();
    dns.publishKey('s', 'x.test', keyRecord({ p: 'AAAA' }));
    await expect(dns.resolver('missing._domainkey.x.test', 'TXT')).rejects.toMatchObject({ code: 'ENOTFOUND' });
    await expect(dns.resolver('s._domainkey.x.test', 'A')).rejects.toMatchObject({ code: 'ENODATA' });
  });

  it('revokes a key by blanking p= in place', () => {
    const dns = new MockDns();
    dns.publishKey('s', 'x.test', 'v=DKIM1; k=rsa; p=AAAA');
    dns.revokeKey('s', 'x.test');
    expect(dns.lookup('s._domainkey.x.test')).toEqual(['v=DKIM1; k=rsa; p=']);
  });
});
