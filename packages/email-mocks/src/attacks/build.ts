/** Helpers the adversarial builders share: compose, edit, sign, edit again. */
import type { HeaderField } from '../canon.js';
import {
  type GenerateOptions,
  type GeneratedEmail,
  type SignOverrides,
  composeInput,
  providerProfile,
  recordsFor,
  signAsProvider,
} from '../generate.js';
import { type Message, fromBinary, serializeMessage } from '../message.js';
import type { SignerProfile } from '../providers/types.js';

export interface BuildSteps {
  /** Edit the provider's unsigned header block or body before signing. */
  beforeSign?: (message: Message) => Message;
  /** Edit the signed message (headers added in transit, tampering). */
  afterSign?: (message: Message) => Message;
  overrides?: SignOverrides;
  signers?: SignerProfile[];
}

export function buildEmail(options: GenerateOptions, steps: BuildSteps = {}): GeneratedEmail {
  const base = providerProfile(options.provider);
  const signers = steps.signers ?? options.signers;
  const profile = signers ? { ...base, signers } : base;
  const input = composeInput(options);
  let message = profile.compose(input);
  if (steps.beforeSign) message = steps.beforeSign(message);
  const signed = signAsProvider(profile, input, message, steps.overrides);
  message = steps.afterSign ? steps.afterSign(signed.message) : signed.message;
  return {
    eml: fromBinary(serializeMessage(message)),
    provider: profile.id,
    input,
    signatures: signed.signatures,
    dnsRecords: recordsFor(profile, signed.signatures),
  };
}

const isNamed = (name: string) => (h: HeaderField) => h.name.toLowerCase() === name.toLowerCase();

/** Replaces the (first) field called `name` with `raw` (`Name: value`, folding allowed). */
export function replaceHeader(message: Message, name: string, raw: string): Message {
  const at = message.headers.findIndex(isNamed(name));
  if (at === -1) throw new Error(`no ${name} header`);
  const headers = [...message.headers];
  headers[at] = { name: raw.slice(0, raw.indexOf(':')), raw };
  return { ...message, headers };
}

export function removeHeader(message: Message, name: string): Message {
  return { ...message, headers: message.headers.filter((h) => !isNamed(name)(h)) };
}

/** Inserts a field at the top of the header block (above every signature). */
export function prependHeader(message: Message, raw: string): Message {
  return { ...message, headers: [{ name: raw.slice(0, raw.indexOf(':')), raw }, ...message.headers] };
}

/** Inserts a field at the bottom of the header block (just above the body). */
export function appendHeader(message: Message, raw: string): Message {
  return { ...message, headers: [...message.headers, { name: raw.slice(0, raw.indexOf(':')), raw }] };
}

export function headerRaw(message: Message, name: string): string {
  const h = message.headers.find(isNamed(name));
  if (!h) throw new Error(`no ${name} header`);
  return h.raw;
}

/**
 * Whether a field called `name` added above (`top`) or below (`bottom`)
 * every existing instance leaves a signature with this `h=` intact
 * (RFC 6376 section 5.4.2: instances are taken bottom-up, and a name
 * listed more often than it occurs signs the absence of the extra ones).
 */
export function survivesInsertion(h: string[], present: number, name: string, where: 'top' | 'bottom'): boolean {
  const listed = h.filter((n) => n.toLowerCase() === name.toLowerCase()).length;
  return where === 'bottom' ? listed === 0 : listed <= present;
}
