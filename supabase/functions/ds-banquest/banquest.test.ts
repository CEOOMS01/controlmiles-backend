// Tests for banquest.ts against an in-memory fake Banquest. Run with:
//   node --test supabase/functions/ds-banquest/banquest.test.ts
// The fake follows the shapes in docs.banquestgateway.com plus the three assumptions listed in banquest.ts;
// the sandbox must confirm those.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  authHeader, checkTransaction, createPayLink, createWebhook, decodeCred, encodeCred, handleWebhook, hmacHex,
  payLinkBody, type Ctx, type ProviderSecrets, type WebhookDeps,
} from './banquest.ts';

const ORDER = '3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b';
const ORG = '666e6fac-eba6-43d4-baf8-3bf14b824379';
const TOKEN = 'a'.repeat(64);
const SIG = 'webhook-signature-key';

type Handler = (url: URL, init: RequestInit) => { status: number; body?: unknown };
function fake(handler: Handler) {
  const calls: { method: string; path: string; body: any; auth: string | null }[] = [];
  const fetchImpl = async (url: string, init: RequestInit = {}) => {
    const u = new URL(url);
    const headers = new Headers(init.headers);
    calls.push({ method: init.method ?? 'GET', path: u.pathname.replace('/api/v2', '') + u.search, body: init.body ? JSON.parse(String(init.body)) : undefined, auth: headers.get('authorization') });
    const r = handler(u, init);
    return new Response(r.body === undefined ? '' : JSON.stringify(r.body), { status: r.status });
  };
  return { fetchImpl, calls };
}
const ctx = (f: ReturnType<typeof fake>): Ctx => ({ env: 'sandbox', cred: { key: 'KEY', pin: '1234' }, fetchImpl: f.fetchImpl });

// ---------- credentials and body ----------

test('auth header is Basic base64(key:pin) and the credential round-trips', () => {
  assert.equal(authHeader({ key: 'KEY', pin: '1234' }), 'Basic ' + Buffer.from('KEY:1234').toString('base64'));
  assert.equal(authHeader({ key: 'KEY' }), 'Basic ' + Buffer.from('KEY:').toString('base64'));
  assert.deepEqual(decodeCred(encodeCred({ key: 'K', pin: 'P' })), { key: 'K', pin: 'P' });
  assert.deepEqual(decodeCred('plain-key'), { key: 'plain-key', pin: '' });
});

test('pay link body: amount in dollars, order id in custom1, one time, https redirect', () => {
  const b: any = payLinkBody({ amountCents: 9050, description: 'Class 3', orderId: ORDER, redirectUrl: 'https://x.test/p' });
  assert.equal(b.general_fields.amount.value, '90.50');
  assert.equal(b.custom_fields.custom1.value, ORDER);
  assert.equal(b.one_time_use, true);
  assert.equal(b.redirect_url, 'https://x.test/p');
  assert.equal(payLinkBody({ amountCents: 100, description: 'x', orderId: null, redirectUrl: 'https://x.test' }).custom_fields, undefined);
});

// ---------- pay link ----------

test('pay link: success returns link and key, tagged with the order', async () => {
  const f = fake(() => ({ status: 201, body: { messages: [], payment_link: 'https://pay.banquest.com/s?x=1', key: 'K1' } }));
  const r = await createPayLink(ctx(f), 'front-line', { amountCents: 9000, description: 'DIP', orderId: ORDER, redirectUrl: 'https://c.test/p' });
  assert.deepEqual(r, { link: 'https://pay.banquest.com/s?x=1', key: 'K1', orderTagged: true });
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].path, '/payment-pages/generate-pay-link/front-line');
  assert.equal(f.calls[0].auth, authHeader({ key: 'KEY', pin: '1234' }));
});

test('pay link: a page without custom1 (400) is retried without it', async () => {
  const f = fake((_u, init) => {
    const b = JSON.parse(String(init.body));
    if (b.custom_fields) return { status: 400, body: { messages: ['custom1 does not exist'] } };
    return { status: 201, body: { payment_link: 'https://pay.banquest.com/s', key: 'K2' } };
  });
  const r: any = await createPayLink(ctx(f), 'p', { amountCents: 9000, description: 'DIP', orderId: ORDER, redirectUrl: 'https://c.test/p' });
  assert.equal(r.orderTagged, false);
  assert.equal(r.key, 'K2');
  assert.equal(f.calls.length, 2);
});

test('pay link: errors are mapped', async () => {
  const run = async (status: number, orderId: string | null = null) =>
    createPayLink(ctx(fake(() => ({ status, body: { messages: ['no'] } }))), 'p', { amountCents: 100, description: 'x', orderId, redirectUrl: 'https://c.test' });
  assert.equal((await run(401) as any).error, 'KEY_REJECTED');
  assert.equal((await run(403) as any).error, 'KEY_REJECTED');
  assert.equal((await run(404) as any).error, 'PAGE_NOT_FOUND');
  assert.equal((await run(400) as any).error, 'PAGE_FIELDS');
  assert.equal((await run(500) as any).error, 'PROVIDER_ERROR');
});

// ---------- webhook registration ----------

test('create webhook: 201 returns it; 409 finds the existing one; 422 is the limit', async () => {
  const url = 'https://p.supabase.co/functions/v1/ds-banquest/webhook?t=' + TOKEN;
  const ok = await createWebhook(ctx(fake(() => ({ status: 201, body: { id: 7, signature: 's', webhook_url: url } }))), url);
  assert.deepEqual(ok, { id: 7, signature: 's', webhook_url: url });
  const dup = fake((u, init) => (init.method === 'POST' ? { status: 409 } : { status: 200, body: [{ id: 9, signature: 'sig9', webhook_url: url }] }));
  assert.deepEqual(await createWebhook(ctx(dup), url), { id: 9, signature: 'sig9', webhook_url: url });
  assert.deepEqual(await createWebhook(ctx(fake(() => ({ status: 422 }))), url), { error: 'WEBHOOK_LIMIT', status: 422 });
});

// ---------- transaction check ----------

const tx = (over: any = {}) => ({
  id: 555,
  amount_details: { amount: 90 },
  transaction_details: { type: 'charge', reference_number: 555, key: 'K1' },
  status_details: { status: 'captured' },
  custom_fields: { custom1: ORDER },
  ...over,
});

test('check transaction: captured and settled count; authorizations, ACH in flight, refunds and zero do not', () => {
  assert.deepEqual(checkTransaction(tx()), { paid: true, reference: '555', amountCents: 9000, orderId: ORDER, key: 'K1' });
  assert.equal((checkTransaction(tx({ status_details: { status: 'settled' } })) as any).paid, true);
  for (const s of ['approved', 'originated', 'pending', 'declined', 'voided', 'returned', 'error', 'queued']) {
    assert.equal((checkTransaction(tx({ status_details: { status: s } })) as any).paid, false, s);
  }
  assert.equal((checkTransaction(tx({ transaction_details: { type: 'refund', reference_number: 1 } })) as any).paid, false);
  assert.equal((checkTransaction(tx({ amount_details: { amount: 0 } })) as any).paid, false);
  assert.equal((checkTransaction(tx({ custom_fields: { custom1: 'not-a-uuid' } })) as any).orderId, null);
  assert.equal((checkTransaction(tx({ amount_details: { amount: 19.99 } })) as any).amountCents, 1999);
});

// ---------- webhook receiving ----------

function chargeEvent(over: any = {}) {
  return { id: 'evt-1', event: 'transaction', type: 'succeeded', subType: 'charge', timestamp: '2026-11-19T10:00:00Z', data: { status: 'Approved', reference_number: 555, transaction: { id: 555 } }, ...over };
}
async function post(evt: unknown, deps: WebhookDeps, opts: { token?: string; sig?: string | null; body?: string } = {}) {
  const body = opts.body ?? JSON.stringify(evt);
  const sig = opts.sig === undefined ? await hmacHex(SIG, body) : opts.sig;
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (sig) headers['x-signature'] = sig;
  return handleWebhook(new Request(`https://x.test/functions/v1/ds-banquest/webhook?t=${opts.token ?? TOKEN}`, { method: 'POST', headers, body }), deps);
}
function deps(over: Partial<WebhookDeps> & { txResponse?: { status: number; body?: unknown } } = {}) {
  const marks: any[] = [];
  const f = fake(() => over.txResponse ?? { status: 200, body: tx() });
  const prov: ProviderSecrets = { organization_id: ORG, environment: 'sandbox', page_slug: 'p', webhook_token: TOKEN, source_key: encodeCred({ key: 'KEY', pin: '1234' }), signature: SIG };
  const d: WebhookDeps = {
    provider: async (t) => (t === TOKEN ? prov : null),
    orderByKey: async (_o, k) => (k === 'K1' ? ORDER : null),
    markPaid: async (...a) => { marks.push(a); return 'paid'; },
    fetchImpl: f.fetchImpl,
    ...over,
  };
  return { d, marks, f };
}

test('webhook: a valid signed charge reads the transaction back and marks the order paid', async () => {
  const { d, marks, f } = deps();
  const res = await post(chargeEvent(), d);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, result: 'paid' });
  assert.deepEqual(marks, [[ORG, ORDER, '555', 9000, 'evt-1']]);
  assert.equal(f.calls[0].path, '/transactions/555');
});

test('webhook: unknown address, missing or wrong signature, tampered body are refused and mark nothing', async () => {
  const { d, marks } = deps();
  assert.equal((await post(chargeEvent(), d, { token: 'b'.repeat(64) })).status, 404);
  assert.equal((await post(chargeEvent(), d, { token: 'short' })).status, 404);
  assert.equal((await post(chargeEvent(), d, { sig: null })).status, 401);
  assert.equal((await post(chargeEvent(), d, { sig: 'deadbeef' })).status, 401);
  const good = JSON.stringify(chargeEvent());
  const sigOfOther = await hmacHex(SIG, good);
  assert.equal((await post(null, d, { body: good.replace('555', '556'), sig: sigOfOther })).status, 401);
  assert.equal((await post(chargeEvent(), d, { sig: await hmacHex('another-key', good) })).status, 401);
  assert.equal(marks.length, 0);
});

test('webhook: signature in upper case is accepted; GET is refused', async () => {
  const { d } = deps();
  const body = JSON.stringify(chargeEvent());
  assert.equal((await post(null, d, { body, sig: (await hmacHex(SIG, body)).toUpperCase() })).status, 200);
  assert.equal((await handleWebhook(new Request(`https://x.test/w?t=${TOKEN}`, { method: 'GET' }), d)).status, 405);
});

test('webhook: events that are not a paid charge are acknowledged and ignored', async () => {
  const { d, marks, f } = deps();
  for (const e of [
    chargeEvent({ type: 'declined' }), chargeEvent({ subType: 'refund' }), chargeEvent({ event: 'batch', type: 'close' }),
    chargeEvent({ event: 'account_updater', type: 'updated' }), chargeEvent({ id: '' }),
  ]) {
    const r = await post(e, d);
    assert.equal(r.status, 200);
    assert.equal((await r.json()).ignored, true);
  }
  assert.equal(marks.length, 0);
  assert.equal(f.calls.length, 0);
});

test('webhook: a claimed charge whose transaction is not really captured is not marked paid', async () => {
  for (const status of ['approved', 'originated', 'declined', 'voided']) {
    const { d, marks } = deps({ txResponse: { status: 200, body: tx({ status_details: { status } }) } });
    const r = await post(chargeEvent(), d);
    assert.equal(r.status, 200);
    assert.equal((await r.json()).ignored, true, status);
    assert.equal(marks.length, 0, status);
  }
});

test('webhook: ACH settled event pays after origination did not', async () => {
  const { d, marks } = deps();
  const settled = { id: 'evt-2', event: 'transaction', type: 'status', subType: 'settled', data: { id: 555 } };
  assert.equal((await post(settled, d)).status, 200);
  assert.deepEqual(marks, [[ORG, ORDER, '555', 9000, 'evt-2']]);
});

test('webhook: order found by the link key when the page has no custom1', async () => {
  const { d, marks } = deps({ txResponse: { status: 200, body: tx({ custom_fields: {} }) } });
  await post(chargeEvent(), d);
  assert.deepEqual(marks, [[ORG, ORDER, '555', 9000, 'evt-1']]);
  const none = deps({ txResponse: { status: 200, body: tx({ custom_fields: {}, transaction_details: { type: 'charge', reference_number: 555, key: 'OTHER' } }) } });
  const r = await post(chargeEvent(), none.d);
  assert.equal((await r.json()).reason, 'no order');
  assert.equal(none.marks.length, 0);
});

test('webhook: a client who paid another amount reaches markPaid with that amount (the database refuses to pay it)', async () => {
  const { d, marks } = deps({ txResponse: { status: 200, body: tx({ amount_details: { amount: 1 } }) } });
  await post(chargeEvent(), d);
  assert.equal(marks[0][3], 100);
});

test('webhook: Banquest unreachable or failing answers 502 so it retries; a database failure throws (500)', async () => {
  const down = deps({ txResponse: { status: 503 } });
  assert.equal((await post(chargeEvent(), down.d)).status, 502);
  const boom = deps();
  boom.d.fetchImpl = async () => { throw new Error('network'); };
  assert.equal((await post(chargeEvent(), boom.d)).status, 502);
  const notFound = deps({ txResponse: { status: 404 } });
  assert.equal((await post(chargeEvent(), notFound.d)).status, 200);
  const dbDown = deps({ markPaid: async () => { throw new Error('db'); } });
  await assert.rejects(() => post(chargeEvent(), dbDown.d));
});

test('webhook: a reference that is not a number is ignored without calling Banquest', async () => {
  const { d, f } = deps();
  const r = await post(chargeEvent({ data: { reference_number: 'abc' } }), d);
  assert.equal((await r.json()).ignored, true);
  assert.equal(f.calls.length, 0);
});
