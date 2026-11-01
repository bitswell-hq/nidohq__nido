/**
 * The fixtures API: a plain-text message as a launch provider sends it,
 * DKIM-signed with that provider's TEST-ONLY key in its signing format.
 */
import { type SignInput, signMessage } from './dkim.js';
import { MockDns, keyRecordName } from './dns.js';
import { type KeyName, publicKeyBase64, testKey } from './keys.js';
import { type Message, fromBinary, serializeMessage } from './message.js';
import { PROVIDERS } from './providers/index.js';
import {
  type ComposeInput,
  type ProviderId,
  type ProviderProfile,
  type SignerProfile,
  isStandardSignature,
} from './providers/types.js';

/** The default recipient: the fixed address recovery emails are sent to. */
export const RECOVERY_ADDRESS = 'recover@recovery.test';
/** The default send time, so fixtures are reproducible. */
export const DEFAULT_DATE = new Date('2026-10-15T09:30:00Z');

export interface GenerateOptions {
  provider: ProviderId;
  /** `local@domain`; the domain is one of the provider's launch domains. */
  from: string;
  displayName?: string;
  subject: string;
  body: string;
  to?: string;
  date?: Date;
  /** The sender's UTC offset in minutes (default 0), for providers that write local time. */
  utcOffsetMinutes?: number;
  /** Varies Message-ID and opaque headers; defaults to a digest of the other inputs. */
  seed?: string;
  /** Sign with these instead of the provider's current signers. */
  signers?: SignerProfile[];
}

export interface SignatureInfo {
  fieldName: string;
  /** Read by DKIM verifiers (`DKIM-Signature`, any case), as opposed to a provider-internal copy. */
  standard: boolean;
  domain: string;
  selector: string;
  keyName: KeyName;
  /** PEM path relative to the package root. */
  keyFile: string;
  keyBits: number;
  /** The `h=` list as written. */
  signedHeaders: string[];
  /** The whole field as written, folding kept. */
  field: string;
  bh: string;
  b: string;
  /** The octets the RSA signature covers. */
  signedHeaderData: string;
}

export interface GeneratedEmail {
  /** The raw `.eml` octets, CRLF line endings. */
  eml: Uint8Array;
  provider: ProviderId;
  input: ComposeInput;
  /** Top-most first, the order they appear in the message. */
  signatures: SignatureInfo[];
  /** The key records these signatures need, as `[name, TXT value]`. */
  dnsRecords: Array<[string, string]>;
}

export function providerProfile(id: ProviderId): ProviderProfile {
  return PROVIDERS[id];
}

export function composeInput(options: GenerateOptions): ComposeInput {
  const at = options.from.lastIndexOf('@');
  if (at < 1) throw new Error(`not an address: ${options.from}`);
  const domain = options.from.slice(at + 1).toLowerCase();
  const profile = providerProfile(options.provider);
  if (!profile.domains.includes(domain)) {
    throw new Error(`${profile.name} does not send for ${domain} (launch domains: ${profile.domains.join(', ')})`);
  }
  const date = options.date ?? DEFAULT_DATE;
  const to = options.to ?? RECOVERY_ADDRESS;
  const utcOffsetMinutes = options.utcOffsetMinutes ?? 0;
  const seed =
    options.seed ??
    [options.provider, options.from, options.displayName ?? '', to, options.subject, options.body, date.toISOString()].join(
      '\u0000',
    );
  return { from: options.from, displayName: options.displayName, to, subject: options.subject, body: options.body, date, utcOffsetMinutes, seed };
}

export interface SignOverrides {
  /** Replace parts of the sign input for one signer (index in `profile.signers`). */
  signer?: (index: number, input: SignInput, signer: SignerProfile) => SignInput;
  /** Signing time; defaults to the message date. */
  time?: number;
}

export function fromDomainOf(input: ComposeInput): string {
  return input.from.slice(input.from.lastIndexOf('@') + 1).toLowerCase();
}

/** Adds each of the provider's signatures in order, each above the last, then its trace fields. */
export function signAsProvider(
  profile: ProviderProfile,
  input: ComposeInput,
  message: Message,
  overrides: SignOverrides = {},
): { message: Message; signatures: SignatureInfo[] } {
  const time = overrides.time ?? Math.floor(input.date.getTime() / 1000);
  const fromDomain = fromDomainOf(input);
  let current = message;
  const signatures: SignatureInfo[] = [];
  profile.signers.forEach((signer, index) => {
    const d = signer.domain(fromDomain);
    const s = signer.selector(fromDomain);
    const h = signer.signedHeaders(current.headers);
    const key = testKey(signer.key(fromDomain));
    let signInput: SignInput = {
      key: key.privateKey,
      tags: signer.tags({ message: current, input, fromDomain, time }, { d, s, h }),
      signedHeaders: h,
      canon: signer.canon,
      layout: signer.layout,
      fieldName: signer.fieldName,
    };
    if (overrides.signer) signInput = overrides.signer(index, signInput, signer);
    const signed = signMessage(current, signInput);
    current = { headers: [signed.field, ...current.headers], body: current.body };
    signatures.unshift({
      fieldName: signer.fieldName,
      standard: isStandardSignature(signer.fieldName),
      domain: d,
      selector: s,
      keyName: key.name,
      keyFile: key.file,
      keyBits: key.bits,
      signedHeaders: signInput.signedHeaders,
      field: signed.field.raw,
      bh: signed.bh,
      b: signed.b,
      signedHeaderData: signed.signedHeaderData,
    });
  });
  if (profile.trace) current = { headers: [...profile.trace(input), ...current.headers], body: current.body };
  return { message: current, signatures };
}

export function recordsFor(profile: ProviderProfile, signatures: SignatureInfo[]): Array<[string, string]> {
  return signatures.map((s) => [keyRecordName(s.selector, s.domain), profile.keyRecord(publicKeyBase64(testKey(s.keyName)))]);
}

/** A signed plain-text message from `options.from`, as `options.provider` sends it. */
export function generateEmail(options: GenerateOptions): GeneratedEmail {
  const base = providerProfile(options.provider);
  const profile = options.signers ? { ...base, signers: options.signers } : base;
  const input = composeInput(options);
  const { message, signatures } = signAsProvider(profile, input, profile.compose(input));
  return {
    eml: fromBinary(serializeMessage(message)),
    provider: profile.id,
    input,
    signatures,
    dnsRecords: recordsFor(profile, signatures),
  };
}

/**
 * The mock DNS as the launch providers publish it: every live key for
 * every launch domain, plus the rotated-out selectors they leave in place
 * with `p=` blanked.
 */
export function launchDns(): MockDns {
  const dns = new MockDns();
  for (const profile of Object.values(PROVIDERS)) {
    for (const [name, value] of profile.extraRecords ?? []) dns.publish(name, value);
    for (const domain of profile.domains) {
      for (const signer of profile.signers) {
        const record = profile.keyRecord(publicKeyBase64(testKey(signer.key(domain))));
        dns.publishKey(signer.selector(domain), signer.domain(domain), record);
      }
    }
  }
  return dns;
}
