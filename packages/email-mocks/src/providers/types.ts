import type { Canon, HeaderField } from '../canon.js';
import type { SignatureLayout, Tag } from '../dkim.js';
import type { KeyName } from '../keys.js';
import type { Message } from '../message.js';

export type ProviderId = 'gmail' | 'outlook' | 'icloud' | 'yahoo' | 'proton' | 'fastmail' | 'gmx';

/** What the user typed into their mail client. */
export interface ComposeInput {
  /** The sender's address (`local@domain`). */
  from: string;
  displayName?: string;
  to: string;
  subject: string;
  /** Plain text; any line ending. */
  body: string;
  /** When the message was sent. */
  date: Date;
  /** The sender's UTC offset in minutes, for providers that write local time. */
  utcOffsetMinutes: number;
  /** Varies the provider-generated parts (Message-ID, opaque headers) deterministically. */
  seed: string;
}

export interface SignContext {
  message: Message;
  input: ComposeInput;
  fromDomain: string;
  /** Signing time in seconds, the `t=` value where the signer writes one. */
  time: number;
}

/** One DKIM signature a provider adds when it sends. */
export interface SignerProfile {
  /** Header field name; providers' internal signatures use nonstandard names. */
  fieldName: string;
  key: (fromDomain: string) => KeyName;
  /** `d=` for a message from `fromDomain`. */
  domain: (fromDomain: string) => string;
  selector: (fromDomain: string) => string;
  canon: { header: Canon; body: Canon };
  /** Tags before `bh=` and `b=`, in the provider's order, `h=` included. */
  tags: (ctx: SignContext, id: { d: string; s: string; h: string[] }) => Tag[];
  /** The `h=` list for this header block, oversigned names repeated. */
  signedHeaders: (headers: HeaderField[]) => string[];
  layout: SignatureLayout;
}

export interface ProviderProfile {
  id: ProviderId;
  name: string;
  /** Launch domains this provider signs for. */
  domains: readonly string[];
  /** Signatures in the order they are added; each is prepended above the last. */
  signers: SignerProfile[];
  /** The DNS key record for a `p=` value, in the provider's published form. */
  keyRecord: (p: string) => string;
  /** Other published key records, such as rotated-out selectors, as `[name, TXT]`. */
  extraRecords?: Array<[string, string]>;
  /** The header block and body as the provider emits a plain-text message, unsigned. */
  compose: (input: ComposeInput) => Message;
  /** Trace fields the provider's outbound MTA writes above its signatures. */
  trace?: (input: ComposeInput) => HeaderField[];
}

/** Whether a signature field is one a DKIM verifier reads (RFC 6376 section 3.5). */
export function isStandardSignature(fieldName: string): boolean {
  return fieldName.toLowerCase() === 'dkim-signature';
}
