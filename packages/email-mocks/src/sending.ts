/**
 * TEST-ONLY mocks of the two EU-owned transactional email APIs the alert
 * vault sends through. Each is an HTTP server on 127.0.0.1 that accepts
 * exactly its provider's published request shape, answers with its
 * published response and error shapes, and records what it accepted.
 *
 * - **Lettermint Sending API** (primary), from its OpenAPI document
 *   `https://lettermint.co/docs/api-reference/sending/0.0.1/lettermint-sending-openapi.json`
 *   (version 0.0.1, read 2026-11-01): `POST /v1/send` on
 *   `https://api.lettermint.co`, header `x-lettermint-token`, optional
 *   `Idempotency-Key` (1 to 255 characters; the same key and body within
 *   24 hours returns the original response, a different body is a 409),
 *   body `SendMailRequest` (`from`, `to` (at least one), `subject` (at most
 *   998), optional `text`/`html` (at least 3 characters), `headers`,
 *   `tag`, ...), answer `202 {message_id, status: "pending"}`; errors as
 *   `ErrorMessage {message}`, `ApiError {error: {code, message}}`, or
 *   `ValidationError {message, errors}`.
 * - **Scaleway Transactional Email** (failover), from Scaleway's generated
 *   Go SDK `api/tem/v1alpha1/tem_sdk.go` (scaleway-sdk-go commit
 *   e27899944eebbe6b7c39b19d1a336cf6bcc9d577): `POST
 *   /transactional-email/v1alpha1/regions/fr-par/emails` on
 *   `https://api.scaleway.com`, header `X-Auth-Token`, body
 *   `CreateEmailRequest` (`from {email, name}`, `to [{email, name}]`,
 *   `subject`, `text`, `html`, `project_id`, `additional_headers [{key,
 *   value}]`, ...), answer `CreateEmailResponse {emails: [Email]}`; errors
 *   as `ResponseError {message, type}`. The API has no idempotency key.
 */
import { createHash, randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface SentEmail {
  provider: 'lettermint' | 'scaleway';
  from: string;
  to: string[];
  subject: string;
  text?: string;
  html?: string;
  headers: Record<string, string>;
  messageId: string;
  idempotencyKey?: string;
  receivedAt: number;
  /** The raw request body, as the provider received it. */
  body: string;
}

/** A failure the next request(s) get instead of being accepted. */
export interface InjectedFailure {
  status: number;
  /** How many requests fail; default 1. */
  count?: number;
  retryAfter?: number;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

function json(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
}

abstract class HttpMock {
  readonly sent: SentEmail[] = [];
  /** Every request, accepted or not (method, path, status). */
  readonly requests: { method: string; path: string; status: number }[] = [];
  protected failures: InjectedFailure[] = [];
  private server?: Server;
  url = '';

  constructor(protected readonly token: string) {}

  failNext(f: InjectedFailure): void {
    this.failures.push({ count: 1, ...f });
  }

  /** Pops an injected failure for this request, if any. */
  protected injected(): InjectedFailure | undefined {
    const f = this.failures[0];
    if (!f) return undefined;
    if (--f.count! <= 0) this.failures.shift();
    return f;
  }

  protected abstract handle(req: IncomingMessage, body: string, res: ServerResponse): void;

  async listen(): Promise<string> {
    this.server = createServer(async (req, res) => {
      const body = await readBody(req);
      const end = res.end.bind(res);
      res.end = ((...args: Parameters<ServerResponse['end']>) => {
        this.requests.push({ method: req.method ?? '', path: req.url ?? '', status: res.statusCode });
        return end(...args);
      }) as ServerResponse['end'];
      this.handle(req, body, res);
    });
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
    return this.url;
  }

  async close(): Promise<void> {
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()));
  }
}

const isStr = (v: unknown): v is string => typeof v === 'string';
const isStrArr = (v: unknown): v is string[] => Array.isArray(v) && v.every(isStr);

export class LettermintMock extends HttpMock {
  private readonly idempotent = new Map<string, { bodyHash: string; at: number; response: unknown }>();

  constructor(token = 'lm_test_only_token') {
    super(token);
  }

  protected handle(req: IncomingMessage, raw: string, res: ServerResponse): void {
    if (req.method !== 'POST' || req.url !== '/v1/send') return json(res, 404, { message: 'Not found.' });
    if (req.headers['x-lettermint-token'] !== this.token) {
      return json(res, 401, { message: 'The project API token is missing or invalid.' });
    }
    const failure = this.injected();
    if (failure) {
      if (failure.status === 429) {
        return json(res, 429, { error: { code: 'RATE_LIMITED', message: 'Too many requests.' } }, {
          'retry-after': String(failure.retryAfter ?? 1),
        });
      }
      return json(res, failure.status, { error: { code: 'INTERNAL_ERROR', message: 'Internal error.' } });
    }
    const key = req.headers['idempotency-key'];
    if (key !== undefined && (typeof key !== 'string' || key.length < 1 || key.length > 255)) {
      return json(res, 422, { message: 'The idempotency key must be 1 to 255 characters.' });
    }
    const bodyHash = createHash('sha256').update(raw).digest('hex');
    if (typeof key === 'string') {
      const prior = this.idempotent.get(key);
      if (prior && Date.now() - prior.at < 24 * 3600_000) {
        if (prior.bodyHash !== bodyHash) {
          return json(res, 409, { message: 'The idempotency key was used with a different request.' });
        }
        return json(res, 202, prior.response);
      }
    }
    let b: Record<string, unknown>;
    try {
      b = JSON.parse(raw);
    } catch {
      return json(res, 422, { message: 'The given data was invalid.', errors: { body: ['Malformed JSON.'] } });
    }
    const errors: Record<string, string[]> = {};
    if (!isStr(b.from) || b.from.length === 0) errors.from = ['The from field is required.'];
    if (!isStrArr(b.to) || b.to.length < 1) errors.to = ['The to field must have at least 1 items.'];
    if (!isStr(b.subject) || b.subject.length > 998) errors.subject = ['The subject field is required.'];
    for (const f of ['text', 'html'] as const) {
      if (b[f] !== undefined && b[f] !== null && (!isStr(b[f]) || (b[f] as string).length < 3)) {
        errors[f] = [`The ${f} field must be at least 3 characters.`];
      }
    }
    if (b.headers !== undefined && (typeof b.headers !== 'object' || !Object.values(b.headers as object).every(isStr))) {
      errors.headers = ['The headers field must be a map of strings.'];
    }
    if (b.tag !== undefined && b.tag !== null && !(isStr(b.tag) && /^[a-zA-Z0-9_-]+(?:\s[a-zA-Z0-9_-]+)*$/.test(b.tag))) {
      errors.tag = ['The tag format is invalid.'];
    }
    if (Object.keys(errors).length) return json(res, 422, { message: 'The given data was invalid.', errors });
    const messageId = randomUUID();
    this.sent.push({
      provider: 'lettermint',
      from: b.from as string,
      to: b.to as string[],
      subject: b.subject as string,
      ...(isStr(b.text) ? { text: b.text } : {}),
      ...(isStr(b.html) ? { html: b.html } : {}),
      headers: (b.headers as Record<string, string>) ?? {},
      messageId,
      ...(typeof key === 'string' ? { idempotencyKey: key } : {}),
      receivedAt: Date.now(),
      body: raw,
    });
    const response = { message_id: messageId, status: 'pending' };
    if (typeof key === 'string') this.idempotent.set(key, { bodyHash, at: Date.now(), response });
    return json(res, 202, response);
  }
}

export const SCALEWAY_PATH = '/transactional-email/v1alpha1/regions/fr-par/emails';

export class ScalewayTemMock extends HttpMock {
  constructor(
    token = 'scw-test-only-secret-key',
    readonly projectId = '00000000-0000-4000-8000-000000000000',
  ) {
    super(token);
  }

  protected handle(req: IncomingMessage, raw: string, res: ServerResponse): void {
    if (req.method !== 'POST' || req.url !== SCALEWAY_PATH) {
      return json(res, 404, { message: 'resource is not found', type: 'not_found' });
    }
    if (req.headers['x-auth-token'] !== this.token) {
      return json(res, 401, { message: 'authentication is denied', type: 'denied_authentication' });
    }
    const failure = this.injected();
    if (failure) return json(res, failure.status, { message: 'internal error', type: 'internal' });
    let b: Record<string, unknown>;
    try {
      b = JSON.parse(raw);
    } catch {
      return json(res, 400, { message: 'invalid argument(s)', type: 'invalid_arguments' });
    }
    const addr = (v: unknown): v is { email: string; name?: string | null } =>
      typeof v === 'object' && v !== null && isStr((v as { email: unknown }).email);
    const ok =
      addr(b.from) &&
      Array.isArray(b.to) &&
      b.to.length > 0 &&
      b.to.every(addr) &&
      isStr(b.subject) &&
      isStr(b.text) &&
      isStr(b.html) &&
      b.project_id === this.projectId &&
      (b.additional_headers === undefined ||
        (Array.isArray(b.additional_headers) &&
          b.additional_headers.every((h: unknown) => isStr((h as { key: unknown }).key) && isStr((h as { value: unknown }).value))));
    if (!ok) return json(res, 400, { message: 'invalid argument(s)', type: 'invalid_arguments' });
    const now = new Date().toISOString();
    const to = (b.to as { email: string }[]).map((t) => t.email);
    const emails = to.map((rcpt) => {
      const id = randomUUID();
      return {
        id,
        message_id: `${id}@scw-tem.cloud`,
        project_id: this.projectId,
        mail_from: (b.from as { email: string }).email,
        mail_rcpt: rcpt,
        rcpt_type: 'to',
        subject: b.subject,
        created_at: now,
        updated_at: now,
        status: 'new',
        status_details: null,
        try_count: 0,
        last_tries: [],
        flags: [],
      };
    });
    const headers: Record<string, string> = {};
    for (const h of (b.additional_headers as { key: string; value: string }[] | undefined) ?? []) headers[h.key] = h.value;
    this.sent.push({
      provider: 'scaleway',
      from: (b.from as { email: string }).email,
      to,
      subject: b.subject as string,
      text: b.text as string,
      html: b.html as string,
      headers,
      messageId: emails[0]!.message_id,
      receivedAt: Date.now(),
      body: raw,
    });
    return json(res, 200, { emails });
  }
}
