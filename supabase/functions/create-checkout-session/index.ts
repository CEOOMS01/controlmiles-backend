// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/create-checkout-session/index.ts
//
// Creates a Stripe Checkout Session for a FLEET plan (Starter / Growth /
// Enterprise), for every service. ControlMiles never sees a card: the
// returned URL is Stripe's hosted page, and the subscription itself reaches
// the database only through stripe-webhook.
//
// Body: {"scope": "fleet", "organization_id", "tier": "starter" | "growth" | "enterprise"}.
// The caller must be an active owner/admin of that org (checked with the
// caller's own RLS-scoped client, never trusted from the body).
//
// Global pricing (2026-10-23, see _shared/fleet_pricing.ts): one monthly
// plan per tier with its cars included and a price per extra car (Stripe
// graduated tiers, quantity = the org's cars), extra branches beyond the
// plan's included ones, plus the ONE-TIME acquisition of the service (the
// right to use the professional software) on the first invoice. If the org
// already paid the acquisition at a lower plan, only the difference is due.
// Prices are found by lookup_key; the limits and fees come from the
// database (fleet_plans, service_license_fees).
//
// Earlier audit fixes kept (2026-10-03):
// - The seat quantity is the org's real vehicle count
//   (fn_org_billable_vehicles), not a number sent by the browser.
//   stripe-webhook re-syncs it on invoice.upcoming before each renewal.
// - An org that already has a live subscription gets ALREADY_SUBSCRIBED
//   (the billing portal is the way to change it), never a second one.
// - The existing Stripe customer is reused, so all invoices stay together.
// - success/cancel return to /admin/settings.
// - Personal (gig) plans are sold only in the app through Google Play.
//
// Until STRIPE_SECRET_KEY is set (or the Stripe prices exist) this answers
// configured:false, never a fake success.

import { createClient } from 'jsr:@supabase/supabase-js@2';
import {
  acquisitionDueCents,
  acquisitionFeeCents,
  branchExtras,
  branchKeyFor,
  checkoutLineFields,
  loadPlan,
  stripePricesByKey,
  type FleetTier,
} from './fleet_pricing.ts';
import { acquisitionCreditCents, firstChargeAt } from './checkout_rules.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers':
    'authorization, x-client-info, apikey, content-type',
};

const STRIPE_SECRET_KEY = Deno.env.get('STRIPE_SECRET_KEY') ?? '';

const SITE_URL = Deno.env.get('SITE_URL') ?? 'https://controlmiles.com';
const CHECKOUT_SUCCESS_URL = `${SITE_URL}/admin/settings?billing=success`;
const CHECKOUT_CANCEL_URL = `${SITE_URL}/admin/settings?billing=canceled`;

const LIVE_STATUSES = new Set(['active', 'trialing', 'past_due']);

// Keyed by user id (authenticated endpoint). Postgres-backed
// check_rate_limit, called with the service role (EXECUTE is revoked from
// client roles so nobody can fill another user's bucket).
const RATE_LIMIT_MAX = 5;
const RATE_LIMIT_WINDOW_SECONDS = 60;

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return respond({ error: 'Missing Authorization header' }, 401);
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const userClient = createClient(supabaseUrl, Deno.env.get('SUPABASE_ANON_KEY')!, {
      global: { headers: { Authorization: authHeader } },
    });
    const adminClient = createClient(supabaseUrl, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);

    const { data: userData, error: userError } = await userClient.auth.getUser();
    if (userError || !userData?.user) {
      return respond({ error: 'Invalid or expired session' }, 401);
    }

    const { data: allowed, error: rlError } = await adminClient.rpc('check_rate_limit', {
      p_fn_name: 'create-checkout-session',
      p_client_key: userData.user.id,
      p_max_requests: RATE_LIMIT_MAX,
      p_window_seconds: RATE_LIMIT_WINDOW_SECONDS,
    });
    if (rlError) console.warn('[create-checkout-session] rate limit check failed (failing open):', rlError);
    if (allowed === false) {
      return respond({ error: 'Too many requests, please try again shortly' }, 429);
    }

    const body = await req.json().catch(() => ({}));
    if (body?.scope !== 'fleet') {
      return respond({ error: 'Personal plans are purchased in the ControlMiles app.' }, 400);
    }

    const organizationId = String(body?.organization_id ?? '');
    const tier: FleetTier = body?.tier === 'enterprise' ? 'enterprise' : body?.tier === 'growth' ? 'growth' : 'starter';
    if (!organizationId) {
      return respond({ error: 'Missing organization_id' }, 400);
    }

    const { data: membership, error: membershipError } = await userClient
      .from('organization_members')
      .select('member_role')
      .eq('organization_id', organizationId)
      .eq('user_id', userData.user.id)
      .eq('is_active', true)
      .maybeSingle();
    if (membershipError || !membership || !['owner', 'admin'].includes(membership.member_role)) {
      return respond({ error: 'Not authorized for this organization' }, 403);
    }

    const { data: org, error: orgError } = await adminClient
      .from('organizations')
      .select('stripe_customer_id, stripe_subscription_id, subscription_status, subscription_updated_at, industry_template, service_acquired_at, service_acquisition_cents')
      .eq('id', organizationId)
      .maybeSingle();
    if (orgError || !org) {
      return respond({ error: 'Organization not found' }, 404);
    }
    if (LIVE_STATUSES.has(org.subscription_status ?? '')) {
      return respond({ error: 'ALREADY_SUBSCRIBED' }, 409);
    }
    if (!STRIPE_SECRET_KEY) {
      return respond({ error: 'Fleet subscriptions are not configured yet', configured: false }, 200);
    }

    const plan = await loadPlan(adminClient, tier);

    // Branches beyond the plan's included ones.
    const { count: activeBranches, error: branchError } = await adminClient
      .from('branches')
      .select('id', { count: 'exact', head: true })
      .eq('organization_id', organizationId)
      .eq('is_archived', false);
    if (branchError) throw branchError;
    const rule = branchExtras(plan, activeBranches ?? 0);
    if (rule.overMax) {
      return respond({ error: 'TOO_MANY_BRANCHES', max: rule.max }, 409);
    }

    const { data: seats, error: seatsError } = await adminClient.rpc('fn_org_billable_vehicles', {
      p_org_id: organizationId,
    });
    if (seatsError) throw seatsError;
    const quantity = Math.max(Number(seats) || 1, 1);
    if (plan.max_cars != null && quantity > plan.max_cars) {
      return respond({ error: 'TOO_MANY_VEHICLES', max: plan.max_cars }, 409);
    }

    // The acquisition of the service: the plan's fee minus what was paid.
    const service: string = org.industry_template ?? 'general';
    const fee = await acquisitionFeeCents(adminClient, service, tier);
    const now = new Date();
    const dueCents = acquisitionDueCents(fee, acquisitionCreditCents(org, now));
    // Free month (off while FIRST_MONTH_FREE is false): the first monthly charge is
    // one month after this payment (checkout_rules.ts).
    const firstCharge = firstChargeAt(org, now);

    const branchKey = branchKeyFor(tier);
    const prices = await stripePricesByKey(STRIPE_SECRET_KEY, [
      `fleet_plan_${tier}`,
      ...(branchKey ? [branchKey] : []),
      `acquisition_${service}_${tier}`,
      `acquisition_${tier}`,
    ]);
    const planPrice = prices.get(`fleet_plan_${tier}`);
    if (!planPrice) {
      return respond({ error: 'Fleet subscriptions are not configured yet', configured: false }, 200);
    }
    const branchPrice = branchKey ? prices.get(branchKey) : undefined;
    if (rule.extras > 0 && !branchPrice) {
      return respond({ error: 'Branch billing is not configured yet', configured: false }, 200);
    }
    const acquisitionPrice = prices.get(`acquisition_${service}_${tier}`) ?? prices.get(`acquisition_${tier}`) ?? null;

    const form = new URLSearchParams();
    form.set('mode', 'subscription');
    form.set('success_url', CHECKOUT_SUCCESS_URL);
    form.set('cancel_url', CHECKOUT_CANCEL_URL);
    for (const [k, v] of checkoutLineFields({
      planPriceId: planPrice.id,
      cars: quantity,
      branchPriceId: branchPrice?.id ?? null,
      branchExtras: rule.extras,
      acquisition: { dueCents, price: acquisitionPrice },
    })) {
      form.set(k, v);
    }
    form.set('client_reference_id', organizationId);
    if (org.stripe_customer_id) {
      form.set('customer', org.stripe_customer_id);
    } else if (userData.user.email) {
      form.set('customer_email', userData.user.email);
    }
    if (firstCharge) form.set('subscription_data[trial_end]', String(firstCharge));
    form.set('allow_promotion_codes', 'true');
    form.set('billing_address_collection', 'auto');
    form.set('subscription_data[metadata][organization_id]', organizationId);
    form.set('subscription_data[metadata][scope]', 'fleet');
    form.set('subscription_data[metadata][tier]', tier);
    form.set('subscription_data[metadata][service]', service);
    form.set('metadata[organization_id]', organizationId);
    form.set('metadata[scope]', 'fleet');
    form.set('metadata[tier]', tier);
    form.set('metadata[service]', service);
    // stripe-webhook records the acquisition as paid when this session completes.
    form.set('metadata[acquisition_due_cents]', String(dueCents));
    form.set('metadata[acquisition_total_cents]', String(fee ?? 0));

    const stripeRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Bearer ${STRIPE_SECRET_KEY}`,
        // One checkout per org/tier/seat count per minute even on double-click.
        'Idempotency-Key': `fleet-checkout-${organizationId}-${tier}-${quantity}-${rule.extras}-${dueCents}-${Math.floor(Date.now() / 60000)}`,
      },
      body: form.toString(),
    });

    if (!stripeRes.ok) {
      const text = await stripeRes.text();
      console.error(`[create-checkout-session] Stripe error ${stripeRes.status}: ${text}`);
      return respond({ error: 'Could not start checkout' }, 502);
    }

    const session = await stripeRes.json();
    return respond({
      url: session.url,
      configured: true,
      quantity,
      branch_extras: rule.extras,
      acquisition_cents: dueCents,
      first_charge_at: firstCharge ? new Date(firstCharge * 1000).toISOString() : null,
    });
  } catch (err: any) {
    console.error('[create-checkout-session] Unexpected error:', err);
    return respond({ error: 'Internal error' }, 500);
  }
});
