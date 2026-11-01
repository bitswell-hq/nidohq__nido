/**
 * The vault's half of the sealed inbound path (`docs/email-recovery/spec.md`
 * §4.6): registrations from recovering browsers, and the recovery and
 * enrollment emails that reach `RECOVERY_INBOX`, each sealed to the device
 * that registered its Subject value.
 *
 * Registrations live only in enclave memory: a restarted vault has none, and
 * a browser whose registration was lost registers again. The first
 * registration of a value holds it until it expires; a second one for the
 * same value is refused, so whoever learns a value (the mail provider sees
 * the Subject) after the browser registered it cannot have the message
 * sealed to another key.
 */
import { bytes, type InboundRequest, openInboundRegistration, sealInboundMessage, subjectValues } from '@nidohq/email-recovery';

const { toHex } = bytes;

/** How long a registration accepts mail. */
export const INBOUND_TTL_MS = 24 * 3600_000;
/** Messages one registration accepts (a resend, a provider's duplicate). */
export const INBOUND_MAX_MESSAGES = 4;
/** Registrations held at once. */
export const INBOUND_MAX_REGISTRATIONS = 100_000;
/** The largest message accepted, in octets. */
export const INBOUND_MAX_OCTETS = 256 * 1024;

interface Registration {
  req: InboundRequest;
  expires: number;
  delivered: number;
}

export type InboundResult = { ok: true; expiresAt: number } | { ok: false; error: string };

export class InboundBox {
  private readonly byValue = new Map<string, Registration>();

  constructor(
    private readonly hpke: CryptoKeyPair,
    private readonly now: () => number = Date.now,
  ) {}

  private sweep(): void {
    const now = this.now();
    for (const [k, r] of this.byValue) if (r.expires < now) this.byValue.delete(k);
  }

  async register(envelope: Uint8Array): Promise<InboundResult> {
    let req: InboundRequest;
    try {
      req = await openInboundRegistration(this.hpke, envelope);
    } catch (e) {
      return { ok: false, error: (e as Error).message };
    }
    this.sweep();
    const value = toHex(req.value);
    if (this.byValue.has(value)) return { ok: false, error: 'this Subject value is already registered' };
    if (this.byValue.size >= INBOUND_MAX_REGISTRATIONS) return { ok: false, error: 'too many registrations' };
    const expires = this.now() + INBOUND_TTL_MS;
    this.byValue.set(value, { req, expires, delivered: 0 });
    return { ok: true, expiresAt: expires };
  }

  /**
   * A message the MX accepted for `RECOVERY_INBOX`: for each registered
   * value one of its Subject fields ends with, the message sealed to that
   * registration's device, under its inbox id (hex). The message itself is
   * not kept.
   */
  async deliver(raw: Uint8Array): Promise<Record<string, Uint8Array>> {
    if (raw.length > INBOUND_MAX_OCTETS) return {};
    this.sweep();
    const out: Record<string, Uint8Array> = {};
    for (const value of new Set(subjectValues(raw))) {
      const r = this.byValue.get(value);
      if (!r || r.delivered >= INBOUND_MAX_MESSAGES) continue;
      r.delivered++;
      out[toHex(r.req.id)] = await sealInboundMessage(r.req, raw);
    }
    return out;
  }
}
