// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/ds-banquest/index.ts
//
// A driving school's own Banquest payments (2026-11-19). One function, four doors (all verify_jwt off;
// each door checks what it needs itself):
//   POST /connect     the school's admin, with their session token: saves the Banquest key, registers the
//                     webhook, and makes a test pay link so a wrong page or field shows up now, not at a client.
//   POST /disconnect  the school's admin: removes the webhook and the secrets.
//   POST /pay         anyone with an order id (a secret only its client has): a one-time pay link for that order.
//   POST /webhook     Banquest, signed (HMAC-SHA256 in X-Signature): marks the order paid.
// ControlMiles never holds the money and takes no commission. The Banquest key and the webhook signature live
// in Supabase Vault and are read here with the service role only.

import { createClient } from 'jsr:@supabase/supabase-js@2';
import {
  createPayLink,
  createWebhook,
  decodeCred,
  deleteWebhook,
  encodeCred,
  handleWebhook,
  listWebhooks,
  type BqEnv,
  type ProviderSecrets,
} from './banquest.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};
const SITE_URL = (Deno.env.get('SITE_URL') ?? 'https://controlmiles.com').replace(/\/+$/, '');
const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
}

const admin = createClient(SUPABASE_URL, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function randomToken(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
}

async function providerByOrg(org: string): Promise<ProviderSecrets | null> {
  const { data } = await admin.rpc('fn_ds_provider_secrets', { p_org: org, p_token: null });
  return (data as ProviderSecrets | null) ?? null;
}

// The caller must be an owner or admin of the school (organization) they name.
async function requireAdmin(req: Request, org: string): Promise<boolean> {
  const jwt = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (!jwt || !UUID.test(org)) return false;
  const { data: u } = await admin.auth.getUser(jwt);
  if (!u?.user) return false;
  const { data: m } = await admin
    .from('organization_members')
    .select('member_role')
    .eq('organization_id', org)
    .eq('user_id', u.user.id)
    .maybeSingle();
  if (!m || (m.member_role !== 'owner' && m.member_role !== 'admin')) return false;
  const { data: ok } = await admin.rpc('fn_org_feature_internal', { p_org_id: org, p_feature: 'student_portal' });
  return ok === true;
}

async function connect(req: Request): Promise<Response> {
  let b: Record<string, unknown>;
  try {
    b = await req.json();
  } catch {
    return respond({ error: 'INVALID' }, 400);
  }
  const org = String(b.org ?? '');
  if (!(await requireAdmin(req, org))) return respond({ error: 'FORBIDDEN' }, 403);
  const slug = String(b.page_slug ?? '').trim();
  const key = String(b.source_key ?? '').trim();
  const pin = String(b.pin ?? '').trim();
  const env: BqEnv = b.environment === 'sandbox' ? 'sandbox' : 'production';
  if (!/^[A-Za-z0-9_-]{2,80}$/.test(slug) || key.length < 6 || key.length > 200 || pin.length > 60) {
    return respond({ error: 'INVALID' }, 400);
  }

  const ctx = { env, cred: { key, pin } };
  // 1. The key works?
  const probe = await listWebhooks(ctx).catch(() => null);
  if (!probe) return respond({ error: 'PROVIDER_UNREACHABLE' }, 502);
  if (probe.status === 401 || probe.status === 403) return respond({ error: 'KEY_REJECTED' }, 400);
  if (probe.status >= 500) return respond({ error: 'PROVIDER_UNREACHABLE' }, 502);

  // 2. Test pay link (never paid): a wrong page name or a missing field fails here.
  const { data: pg } = await admin.from('ds_public_pages').select('slug').eq('organization_id', org).maybeSingle();
  const test = await createPayLink(ctx, slug, {
    amountCents: 100,
    description: 'ControlMiles connection test',
    orderId: null,
    redirectUrl: `${SITE_URL}/book/${pg?.slug ?? 'school'}/portal`,
  });
  if ('error' in test) return respond({ error: test.error, detail: test.detail }, 400);

  // 3. Webhook. The token is made here so it can be part of the address Banquest is given.
  const token = randomToken();
  const hook = await createWebhook(ctx, `${SUPABASE_URL}/functions/v1/ds-banquest/webhook?t=${token}`);
  if ('error' in hook) return respond({ error: hook.error }, 400);

  // The old webhook (a reconnect) is removed with the old key, best effort.
  const old = await providerByOrg(org);
  const { error } = await admin.rpc('fn_ds_provider_store', {
    p_org: org, p_env: env, p_slug: slug, p_credential: encodeCred({ key, pin }),
    p_webhook_id: hook.id, p_signature: hook.signature, p_token: token,
  });
  if (error) {
    console.error('[ds-banquest] store failed:', error);
    await deleteWebhook(ctx, hook.id);
    return respond({ error: 'UNEXPECTED' }, 500);
  }
  if (old?.source_key) {
    const oc = { env: old.environment, cred: decodeCred(old.source_key) };
    if (old.webhook_id && old.webhook_id !== hook.id) await deleteWebhook(oc, old.webhook_id);
  }
  await admin.from('ds_settings').upsert({ organization_id: org, payment_mode: 'banquest' }, { onConflict: 'organization_id' });
  return respond({ ok: true });
}

async function disconnect(req: Request): Promise<Response> {
  let b: Record<string, unknown>;
  try {
    b = await req.json();
  } catch {
    return respond({ error: 'INVALID' }, 400);
  }
  const org = String(b.org ?? '');
  if (!(await requireAdmin(req, org))) return respond({ error: 'FORBIDDEN' }, 403);
  const p = await providerByOrg(org);
  if (p?.source_key && p.webhook_id) await deleteWebhook({ env: p.environment, cred: decodeCred(p.source_key) }, p.webhook_id);
  await admin.rpc('fn_ds_provider_remove', { p_org: org });
  return respond({ ok: true });
}

async function pay(req: Request): Promise<Response> {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() ?? 'unknown';
  const { data: allowed, error: limitError } = await admin.rpc('check_rate_limit', {
    p_fn_name: 'ds-banquest-pay-ip', p_client_key: ip, p_max_requests: 30, p_window_seconds: 3600,
  });
  if (limitError) return respond({ error: 'UNAVAILABLE' }, 503);
  if (!allowed) return respond({ error: 'RATE_LIMITED' }, 429);

  let b: Record<string, unknown>;
  try {
    b = await req.json();
  } catch {
    return respond({ error: 'INVALID' }, 400);
  }
  const orderId = String(b.order_id ?? '');
  if (!UUID.test(orderId)) return respond({ error: 'INVALID' }, 400);

  const { data: o } = await admin
    .from('ds_service_orders')
    .select('id, organization_id, status, price_cents, service_name, payment_link')
    .eq('id', orderId)
    .maybeSingle();
  if (!o || o.status !== 'pending_payment') return respond({ error: 'NOT_PAYABLE' }, 404);
  if (o.payment_link) return respond({ ok: true, link: o.payment_link });

  const prov = await providerByOrg(o.organization_id);
  if (!prov) return respond({ error: 'NOT_CONNECTED' }, 409);
  const { data: pg } = await admin.from('ds_public_pages').select('slug').eq('organization_id', o.organization_id).maybeSingle();

  const made = await createPayLink({ env: prov.environment, cred: decodeCred(prov.source_key) }, prov.page_slug, {
    amountCents: o.price_cents,
    description: o.service_name,
    orderId: o.id,
    redirectUrl: `${SITE_URL}/book/${pg?.slug ?? 'school'}/portal/paid/${o.id}`,
  });
  if ('error' in made) {
    console.error('[ds-banquest] pay link failed:', made.error, made.detail);
    await admin.rpc('fn_ds_provider_error', { p_org: o.organization_id, p_message: `${made.error}: ${made.detail}` });
    return respond({ error: 'PROVIDER_ERROR' }, 502);
  }
  await admin
    .from('ds_service_orders')
    .update({ provider: 'banquest', provider_key: made.key, payment_link: made.link })
    .eq('id', o.id)
    .eq('status', 'pending_payment');
  return respond({ ok: true, link: made.link });
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  const path = new URL(req.url).pathname.replace(/\/+$/, '');
  try {
    if (path.endsWith('/webhook')) {
      return await handleWebhook(req, {
        provider: async (t) => {
          const { data } = await admin.rpc('fn_ds_provider_secrets', { p_org: null, p_token: t });
          return (data as ProviderSecrets | null) ?? null;
        },
        orderByKey: async (org, key) => {
          const { data } = await admin
            .from('ds_service_orders')
            .select('id')
            .eq('organization_id', org)
            .eq('provider_key', key)
            .maybeSingle();
          return data?.id ?? null;
        },
        markPaid: async (org, order, ref, cents, eventId) => {
          const { data, error } = await admin.rpc('fn_ds_order_paid_provider', {
            p_org: org, p_order: order, p_ref: ref, p_amount_cents: cents, p_event: eventId,
          });
          if (error) throw error;
          return String(data);
        },
      });
    }
    if (req.method !== 'POST') return respond({ error: 'METHOD' }, 405);
    if (path.endsWith('/connect')) return await connect(req);
    if (path.endsWith('/disconnect')) return await disconnect(req);
    if (path.endsWith('/pay')) return await pay(req);
    return respond({ error: 'NOT_FOUND' }, 404);
  } catch (err) {
    console.error('[ds-banquest] unexpected error:', err);
    return respond({ error: 'UNEXPECTED' }, 500);
  }
});
