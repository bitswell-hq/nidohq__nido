/**
 * The enclave-image registry as a custodian reads it: from the registry
 * contract's public events (`measurement_activated`, `measurement_revoked`),
 * through Stellar RPC `getEvents`. A measurement is active once its
 * activation event has been seen and no revocation after it.
 */
import { bytes } from '@nidohq/email-recovery';
import { scValToNative, xdr } from '@stellar/stellar-sdk';
import type { StellarRpc } from './rpc.js';

export class RegistryEventsView {
  private readonly active = new Set<string>();
  private cursor?: string;

  constructor(
    private readonly rpc: StellarRpc,
    private readonly registry: string,
    private readonly startLedger: number,
  ) {}

  /** Read every new registry event. */
  async refresh(): Promise<void> {
    for (;;) {
      const page = await this.rpc.getEvents(
        this.registry,
        this.cursor ? { cursor: this.cursor } : { startLedger: this.startLedger },
      );
      for (const e of page.events) {
        const name = scValToNative(xdr.ScVal.fromXDR(e.topic[0]!, 'base64'));
        const m = bytes.toHex(new Uint8Array(scValToNative(xdr.ScVal.fromXDR(e.topic[1]!, 'base64')) as Uint8Array));
        if (name === 'measurement_activated') this.active.add(m);
        if (name === 'measurement_revoked') this.active.delete(m);
      }
      this.cursor = page.cursor;
      if (page.events.length < 200 && Number(BigInt(page.cursor.slice(0, 19)) >> 32n) >= page.latestLedger) return;
    }
  }

  async isActive(measurementHex: string): Promise<boolean> {
    await this.refresh();
    return this.active.has(measurementHex);
  }
}
