/**
 * Email from the vault through the EU sending services
 * (`docs/email-recovery/spec.md` §10.6): Lettermint's Sending API first
 * (two attempts, each with the same `Idempotency-Key`), then Scaleway
 * Transactional Email in `fr-par`. Request shapes follow each provider's
 * published API; `packages/email-mocks/src/sending.ts` cites the sources.
 */

export interface SendingConfig {
  from: { email: string; name: string };
  lettermint: { url: string; token: string };
  scaleway: { url: string; token: string; projectId: string };
}

export interface Email {
  to: string;
  subject: string;
  text: string;
  /** Becomes the Lettermint `Idempotency-Key`; ties retries of one alert together. */
  idempotencyKey: string;
}

export interface SendResult {
  provider?: 'lettermint' | 'scaleway';
  /** Each attempt: provider and HTTP status (0 for a network error). */
  attempts: { provider: 'lettermint' | 'scaleway'; status: number }[];
}

const html = (text: string) =>
  text
    .split('\n\n')
    .map((p) => `<p>${p.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\n/g, '<br>')}</p>`)
    .join('');

const retriable = (status: number) => status === 0 || status === 429 || status >= 500;

export async function sendEmail(cfg: SendingConfig, mail: Email, fetchImpl: typeof fetch = fetch): Promise<SendResult> {
  const attempts: SendResult['attempts'] = [];
  const call = async (provider: 'lettermint' | 'scaleway', url: string, init: RequestInit) => {
    try {
      const r = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(15_000) });
      await r.arrayBuffer();
      attempts.push({ provider, status: r.status });
      return r.status;
    } catch {
      attempts.push({ provider, status: 0 });
      return 0;
    }
  };

  const lettermint = JSON.stringify({
    from: `${cfg.from.name} <${cfg.from.email}>`,
    to: [mail.to],
    subject: mail.subject,
    text: mail.text,
    tag: 'security-alert',
    settings: { track_opens: false, track_clicks: false },
  });
  for (let i = 0; i < 2; i++) {
    const status = await call('lettermint', `${cfg.lettermint.url}/v1/send`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-lettermint-token': cfg.lettermint.token,
        'idempotency-key': mail.idempotencyKey,
      },
      body: lettermint,
    });
    if (status === 202) return { provider: 'lettermint', attempts };
    if (!retriable(status)) break;
  }

  const scaleway = JSON.stringify({
    from: { email: cfg.from.email, name: cfg.from.name },
    to: [{ email: mail.to, name: null }],
    subject: mail.subject,
    text: mail.text,
    html: html(mail.text),
    project_id: cfg.scaleway.projectId,
    additional_headers: [],
  });
  for (let i = 0; i < 2; i++) {
    const status = await call('scaleway', `${cfg.scaleway.url}/transactional-email/v1alpha1/regions/fr-par/emails`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-auth-token': cfg.scaleway.token },
      body: scaleway,
    });
    if (status === 200) return { provider: 'scaleway', attempts };
    if (!retriable(status)) break;
  }
  return { attempts };
}
