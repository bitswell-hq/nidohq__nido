/**
 * A mock of the receiving MX for the fixed recovery address: a message the
 * user sends from their own inbox arrives here and is handed on as the
 * exact octets that were submitted, with only the trace fields an MX
 * prepends (RFC 5321 section 4.4). Nothing below those fields is re-encoded,
 * re-folded or re-ordered, so every DKIM signature still verifies.
 */
import { createHash } from 'node:crypto';
import { formatRfc5322Date } from './format.js';
import { fromBinary, toBinary } from './message.js';

export interface Envelope {
  /** SMTP MAIL FROM (reverse-path). */
  mailFrom: string;
  /** SMTP RCPT TO (forward-path). */
  rcptTo: string;
  /** The sending MTA's EHLO name. */
  helo?: string;
  clientIp?: string;
}

export interface InboundOptions {
  /** The one address this MX accepts mail for. */
  recipient: string;
  hostname?: string;
  /** Prepend Return-Path and Received (default true). */
  trace?: boolean;
  /** Arrival time written into Received; defaults to now. */
  now?: () => Date;
}

export interface Delivered {
  /** The message as handed to the mailbox: trace fields, then the submitted octets. */
  bytes: Uint8Array;
  /** The prepended trace fields (CRLF-terminated), empty without trace. */
  trace: string;
  envelope: Envelope;
}

export class SmtpReject extends Error {
  constructor(readonly code: number, readonly enhanced: string, text: string) {
    super(`${code} ${enhanced} ${text}`);
  }
}

/** RFC 5321 section 4.5.2: a line starting with "." gets one more ".". */
export function toSmtpData(message: Uint8Array): Uint8Array {
  let s = toBinary(message);
  if (!s.endsWith('\r\n')) s += '\r\n';
  return fromBinary(`${s.replace(/(^|\r\n)\./g, '$1..')}.\r\n`);
}

/** Inverse of `toSmtpData`: strips the terminator and the added dots. */
export function fromSmtpData(data: Uint8Array): Uint8Array {
  const s = toBinary(data);
  if (!s.endsWith('\r\n.\r\n') && s !== '.\r\n') throw new SmtpReject(554, '5.6.0', 'DATA not terminated by CRLF.CRLF');
  return fromBinary(s.slice(0, -3).replace(/(^|\r\n)\.\./g, '$1.'));
}

function sameMailbox(a: string, b: string): boolean {
  const split = (s: string) => {
    const at = s.lastIndexOf('@');
    return [s.slice(0, at), s.slice(at + 1).toLowerCase()] as const;
  };
  const [la, da] = split(a);
  const [lb, db] = split(b);
  return la === lb && da === db;
}

export class InboundMx {
  readonly recipient: string;
  readonly hostname: string;
  private readonly trace: boolean;
  private readonly now: () => Date;

  constructor(options: InboundOptions) {
    this.recipient = options.recipient;
    this.hostname = options.hostname ?? 'mx.recovery.test';
    this.trace = options.trace ?? true;
    this.now = options.now ?? (() => new Date());
  }

  /** Accepts a raw RFC 5322 message, as after SMTP DATA un-stuffing. */
  receive(message: Uint8Array, envelope: Envelope): Delivered {
    if (!sameMailbox(envelope.rcptTo, this.recipient)) {
      throw new SmtpReject(550, '5.1.1', `<${envelope.rcptTo}>: recipient not accepted here`);
    }
    const s = toBinary(message);
    // Bare CR or LF are refused outright (RFC 5322 section 2.3; RFC 5321
    // section 2.3.8), so no second reading of the line structure reaches the mailbox.
    if (/\r(?!\n)|(?<!\r)\n/.test(s)) throw new SmtpReject(554, '5.6.0', 'bare CR or LF in message');
    if (s.split('\r\n').some((line) => line.length > 998)) {
      throw new SmtpReject(554, '5.6.0', 'line longer than 998 octets');
    }
    const trace = this.trace ? this.traceFields(message, envelope) : '';
    return { bytes: fromBinary(trace + s), trace, envelope };
  }

  /** Accepts the DATA stream (dot-stuffed, CRLF.CRLF-terminated). */
  receiveSmtpData(data: Uint8Array, envelope: Envelope): Delivered {
    return this.receive(fromSmtpData(data), envelope);
  }

  private traceFields(message: Uint8Array, envelope: Envelope): string {
    const helo = envelope.helo ?? 'mail-out.sender.test';
    const ip = envelope.clientIp ?? '192.0.2.25';
    const id = createHash('sha256').update(message).digest('hex').slice(0, 16).toUpperCase();
    const date = formatRfc5322Date(this.now(), { offsetMinutes: 0 });
    return (
      `Return-Path: <${envelope.mailFrom}>\r\n` +
      `Received: from ${helo} (${helo} [${ip}])\r\n` +
      `\tby ${this.hostname} with ESMTPS id ${id}\r\n` +
      `\tfor <${envelope.rcptTo}>; ${date}\r\n`
    );
  }
}
