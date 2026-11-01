/**
 * TEST-ONLY mock of a platform authenticator answering
 * `navigator.credentials.get` (W3C WebAuthn Level 3, §6.1 authenticator
 * data, §5.8.1 client data): an ES256 (P-256) credential that returns
 * `authenticatorData = rpIdHash || flags || signCount`, the
 * `clientDataJSON` a browser serializes, and a DER-encoded ECDSA signature
 * over `authenticatorData || SHA-256(clientDataJSON)`.
 */
import { createECDH, createHash, createPrivateKey, randomBytes, sign } from 'node:crypto';

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;

export interface Assertion {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  /** DER ECDSA-Sig-Value, as `AuthenticatorAssertionResponse.signature` carries it. */
  signature: Uint8Array;
}

export interface AssertOptions {
  flags?: number;
  origin?: string;
  rpId?: string;
  type?: string;
}

export class AuthenticatorMock {
  readonly publicKey: Uint8Array;
  private signCount = 0;

  /** `privateKey`: the credential's 32-byte P-256 scalar. */
  constructor(
    readonly rpId: string,
    readonly origin: string,
    private readonly privateKey: Uint8Array = new Uint8Array(randomBytes(32)),
  ) {
    const ecdh = createECDH('prime256v1');
    ecdh.setPrivateKey(privateKey);
    this.publicKey = new Uint8Array(ecdh.getPublicKey());
  }

  assert(challenge: Uint8Array, opts: AssertOptions = {}): Assertion {
    const rpIdHash = createHash('sha256').update(opts.rpId ?? this.rpId).digest();
    const count = Buffer.alloc(4);
    count.writeUInt32BE(++this.signCount);
    const authenticatorData = new Uint8Array(
      Buffer.concat([rpIdHash, Buffer.of(opts.flags ?? FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS), count]),
    );
    const clientDataJSON = new Uint8Array(
      Buffer.from(
        JSON.stringify({
          type: opts.type ?? 'webauthn.get',
          challenge: Buffer.from(challenge).toString('base64url'),
          origin: opts.origin ?? this.origin,
          crossOrigin: false,
        }),
      ),
    );
    const key = createPrivateKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        d: Buffer.from(this.privateKey).toString('base64url'),
        x: Buffer.from(this.publicKey.subarray(1, 33)).toString('base64url'),
        y: Buffer.from(this.publicKey.subarray(33, 65)).toString('base64url'),
      },
      format: 'jwk',
    });
    const signed = Buffer.concat([authenticatorData, createHash('sha256').update(clientDataJSON).digest()]);
    return { authenticatorData, clientDataJSON, signature: new Uint8Array(sign('sha256', signed, key)) };
  }
}
