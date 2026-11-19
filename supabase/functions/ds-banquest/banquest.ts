// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/ds-banquest/banquest.ts
//
// Banquest gateway client and the three flows of the school's own payments (2026-11-19):
// connect, pay (a one-time pay link for an order) and the signed webhook that marks the order paid.
// No Deno-only APIs here, so Node can test it against a mock Banquest (tests/banquest.test.ts).
//
// ASSUMPTIONS NOT IN BANQUEST'S DOCS (check them in the sandbox, each is isolated in one function):
//   1. authHeader(): "Basic base64(sourceKey:pin)". The docs only say "BasicAuthentication".
//   2. payLinkBody(): each pre-filled field as { value }. The docs show every field as `{}`.
//   3. The transaction's custom1 / key come back on GET /transactions/{id}.
// Docs: https://docs.banquestgateway.com/api/v2 and https://docs.banquestgateway.com/webhooks/v1

export type BqEnv = 'sandbox' | 'production';
export type BqCred = { key: string; pin?: string };
export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

export const BQ_BASE: Record<BqEnv, string> = {
  production: 'https://api.banquestgateway.com/api/v2',
  sandbox: 'https://api.sandbox.banquestgateway.com/api/v2',
};
// Where a mock server can stand in during tests (never settable from a request).
export type Ctx = { env: BqEnv; cred: BqCred; fetchImpl?: FetchLike; base?: string };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------- credentials ----------

export function encodeCred(c: BqCred): string {
  return JSON.stringify({ k: c.key, p: c.pin ?? '' });
}
export function decodeCred(s: string): BqCred {
  try {
    const o = JSON.parse(s);
    if (typeof o?.k === 'string') return { key: o.k, pin: typeof o.p === 'string' ? o.p : '' };
  } catch {
    // Older plain string: just the key.
  }
  return { key: s, pin: '' };
}

// ASSUMPTION 1
export function authHeader(c: BqCred): string {
  return 'Basic ' + btoa(`${c.key}:${c.pin ?? ''}`);
}

// ---------- HTTP ----------

export type BqResult = { status: number; json: any; text: string };

export async function bq(ctx: Ctx, method: string, path: string, body?: unknown): Promise<BqResult> {
  const f = ctx.fetchImpl ?? fetch;
  const res = await f((ctx.base ?? BQ_BASE[ctx.env]) + path, {
    method,
    headers: {
      Authorization: authHeader(ctx.cred),
      'Content-Type': 'application/json',
      // The docs ask integrations to identify themselves.
      'User-Agent': 'ControlMiles-Fleet/1.0 (+https://controlmiles.com)',
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(9000),
  });
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    // Not JSON.
  }
  return { status: res.status, json, text };
}

// ---------- webhook management ----------

export type Webhook = { id: number; signature: string; webhook_url: string };

export async function listWebhooks(ctx: Ctx): Promise<BqResult> {
  return bq(ctx, 'GET', '/webhooks');
}

// All events (events omitted = all, per the docs); the receiver ignores what it does not need.
export async function createWebhook(ctx: Ctx, url: string): Promise<Webhook | { error: string; status: number }> {
  const r = await bq(ctx, 'POST', '/webhooks', { webhook_url: url, description: 'ControlMiles payments', active: true });
  if (r.status === 201 && r.json?.id && r.json?.signature) return r.json as Webhook;
  if (r.status === 409) {
    const l = await listWebhooks(ctx);
    const found = Array.isArray(l.json) ? (l.json as Webhook[]).find((w) => w.webhook_url === url) : null;
    if (found?.signature) return found;
  }
  return { error: r.status === 422 ? 'WEBHOOK_LIMIT' : 'WEBHOOK_FAILED', status: r.status };
}

export async function deleteWebhook(ctx: Ctx, id: number): Promise<void> {
  try {
    await bq(ctx, 'DELETE', `/webhooks/${id}`);
  } catch {
    // Best effort: the school can also remove it in its Control Panel.
  }
}

// ---------- pay link ----------

export type PayLinkInput = {
  amountCents: number;
  description: string;
  orderId: string | null; // goes in custom1 so the webhook can find the order
  redirectUrl: string;
};

// ASSUMPTION 2: the one place that knows how Banquest wants a pre-filled field.
function field(value: string | number) {
  return { value };
}
export function payLinkBody(i: PayLinkInput) {
  return {
    general_fields: {
      amount: field((i.amountCents / 100).toFixed(2)),
      description: field(i.description.slice(0, 200)),
    },
    ...(i.orderId ? { custom_fields: { custom1: field(i.orderId) } } : {}),
    one_time_use: true,
    redirect_url: i.redirectUrl,
  };
}

export type PayLink = { link: string; key: string; orderTagged: boolean };

export async function createPayLink(
  ctx: Ctx,
  slug: string,
  i: PayLinkInput,
): Promise<PayLink | { error: 'KEY_REJECTED' | 'PAGE_NOT_FOUND' | 'PAGE_FIELDS' | 'PROVIDER_ERROR'; detail: string }> {
  const path = `/payment-pages/generate-pay-link/${encodeURIComponent(slug)}`;
  let tagged = !!i.orderId;
  let r = await bq(ctx, 'POST', path, payLinkBody(i));
  if (r.status === 400 && i.orderId) {
    // The page may have no custom1 field: try without it; the webhook then finds the order by the link key.
    tagged = false;
    r = await bq(ctx, 'POST', path, payLinkBody({ ...i, orderId: null }));
  }
  if ((r.status === 200 || r.status === 201) && typeof r.json?.payment_link === 'string' && r.json?.key) {
    return { link: r.json.payment_link, key: String(r.json.key), orderTagged: tagged };
  }
  const detail = (r.text || '').slice(0, 200);
  if (r.status === 401 || r.status === 403) return { error: 'KEY_REJECTED', detail };
  if (r.status === 404) return { error: 'PAGE_NOT_FOUND', detail };
  if (r.status === 400) return { error: 'PAGE_FIELDS', detail };
  return { error: 'PROVIDER_ERROR', detail: `HTTP ${r.status} ${detail}` };
}

// ---------- webhook receiving ----------

export async function hmacHex(secret: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// Banquest statuses that mean the money is really taken. 'approved' alone is an authorization that was
// not captured; 'originated' and 'pending' are ACH still in flight (the 'settled' event comes later).
const PAID = new Set(['captured', 'settled']);

export type TxCheck =
  | { paid: true; reference: string; amountCents: number; orderId: string | null; key: string | null }
  | { paid: false; reason: string };

export function checkTransaction(tx: any): TxCheck {
  const status = String(tx?.status_details?.status ?? '').toLowerCase();
  const type = String(tx?.transaction_details?.type ?? 'charge').toLowerCase();
  if (type !== 'charge') return { paid: false, reason: `type ${type}` };
  if (!PAID.has(status)) return { paid: false, reason: `status ${status || 'unknown'}` };
  const amount = Number(tx?.amount_details?.amount);
  if (!Number.isFinite(amount) || amount <= 0) return { paid: false, reason: 'no amount' };
  const c1 = String(tx?.custom_fields?.custom1 ?? '');
  const ref = tx?.transaction_details?.reference_number ?? tx?.id;
  if (ref === undefined || ref === null) return { paid: false, reason: 'no reference' };
  return {
    paid: true,
    reference: String(ref),
    amountCents: Math.round(amount * 100),
    orderId: UUID.test(c1) ? c1.toLowerCase() : null,
    key: typeof tx?.transaction_details?.key === 'string' && tx.transaction_details.key ? tx.transaction_details.key : null,
  };
}

export type ProviderSecrets = {
  organization_id: string;
  environment: BqEnv;
  page_slug: string;
  webhook_id?: number;
  webhook_token: string;
  source_key: string;
  signature: string;
};

export type WebhookDeps = {
  provider: (token: string) => Promise<ProviderSecrets | null>;
  orderByKey: (org: string, key: string) => Promise<string | null>;
  markPaid: (org: string, order: string, ref: string, cents: number, eventId: string) => Promise<string>;
  fetchImpl?: FetchLike;
  base?: string;
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

export async function handleWebhook(req: Request, deps: WebhookDeps): Promise<Response> {
  if (req.method !== 'POST') return json({ error: 'METHOD' }, 405);
  const token = new URL(req.url).searchParams.get('t') ?? '';
  if (!/^[0-9a-f]{64}$/.test(token)) return json({ error: 'NOT_FOUND' }, 404);
  const prov = await deps.provider(token);
  if (!prov) return json({ error: 'NOT_FOUND' }, 404);

  const raw = await req.text();
  const header = (req.headers.get('x-signature') ?? '').trim().toLowerCase();
  const expected = await hmacHex(prov.signature, raw);
  if (!header || !safeEqual(header, expected)) return json({ error: 'BAD_SIGNATURE' }, 401);

  let evt: any;
  try {
    evt = JSON.parse(raw);
  } catch {
    return json({ error: 'BAD_JSON' }, 400);
  }
  const eventId = typeof evt?.id === 'string' ? evt.id : '';
  const isCharge = evt?.event === 'transaction' && evt?.type === 'succeeded' && evt?.subType === 'charge';
  const isSettled = evt?.event === 'transaction' && evt?.type === 'status' && evt?.subType === 'settled';
  if (!eventId || (!isCharge && !isSettled)) return json({ ok: true, ignored: true });

  // Never trust the payload alone: read the transaction back from Banquest with the school's key.
  const refNumber = isCharge ? (evt?.data?.reference_number ?? evt?.data?.transaction?.id) : evt?.data?.id;
  if (!Number.isInteger(Number(refNumber)) || Number(refNumber) < 1) return json({ ok: true, ignored: true });
  const ctx: Ctx = { env: prov.environment, cred: decodeCred(prov.source_key), fetchImpl: deps.fetchImpl, base: deps.base };
  let r: BqResult;
  try {
    r = await bq(ctx, 'GET', `/transactions/${Number(refNumber)}`);
  } catch {
    return json({ error: 'PROVIDER_UNREACHABLE' }, 502); // Banquest retries
  }
  if (r.status >= 500) return json({ error: 'PROVIDER_ERROR' }, 502);
  if (r.status !== 200 || !r.json) return json({ ok: true, ignored: true, reason: `lookup ${r.status}` });

  const tx = checkTransaction(r.json);
  if (!tx.paid) return json({ ok: true, ignored: true, reason: tx.reason });

  let orderId = tx.orderId;
  if (!orderId && tx.key) orderId = await deps.orderByKey(prov.organization_id, tx.key);
  if (!orderId) return json({ ok: true, ignored: true, reason: 'no order' });

  const result = await deps.markPaid(prov.organization_id, orderId, tx.reference, tx.amountCents, eventId);
  return json({ ok: true, result });
}
