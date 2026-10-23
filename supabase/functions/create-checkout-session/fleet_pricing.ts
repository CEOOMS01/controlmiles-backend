// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/_shared/fleet_pricing.ts
//
// Global fleet pricing for billing (phase 2, 2026-10-23). Replaces
// school_pricing.ts: ONE price list for every service.
//
//   monthly plan   Starter $59 (3 cars) / Growth $125 (5) / Enterprise $175 (7),
//                  then a price per extra car (graduated tiers on the car count)
//   extra branches Starter 1 included (max 2) at $24.99, Growth 2 (max 4) at
//                  $19.99, Enterprise unlimited
//   acquisition    one-time payment per service and plan: $150 / $200 / $300
//
// The NUMBERS live in the database (fleet_plans, service_license_fees) and in
// Stripe; this module only finds the Stripe prices by their lookup_key and
// reads the limits from the database, so no price id is a secret or an env var:
//
//   fleet_plan_starter | _growth | _enterprise   monthly, graduated tiers, quantity = cars
//   fleet_branch_starter | _growth                monthly, per extra branch
//   school_domain                                 $29/month, driving school own address
//   acquisition_<tier>                            one-time (optionally
//   acquisition_<service>_<tier> overrides it for one service)
//
// Copied into create-checkout-session/ and stripe-webhook/ (the Edge Function
// deploy takes one folder); scripts/check_copies.py keeps the copies equal.

import type { SupabaseClient } from 'jsr:@supabase/supabase-js@2';

export type FleetTier = 'starter' | 'growth' | 'enterprise';

export const PLAN_KEY_PREFIX = 'fleet_plan_';
export const BRANCH_KEY_PREFIX = 'fleet_branch_';
export const DOMAIN_KEY = 'school_domain';
/** The Stripe product used for an acquisition amount that has no price (plan upgrade difference). */
export const ACQUISITION_PRODUCT = 'cm_service_acquisition';

export const isPlanKey = (k: string | null | undefined): boolean => !!k && k.startsWith(PLAN_KEY_PREFIX);
export const isBranchKey = (k: string | null | undefined): boolean => !!k && k.startsWith(BRANCH_KEY_PREFIX);
export const isDomainKey = (k: string | null | undefined): boolean => k === DOMAIN_KEY;
/** An add-on item (extra branches, own address), never the car item. */
export const isExtraKey = (k: string | null | undefined): boolean => isBranchKey(k) || isDomainKey(k);

export function tierFromKey(key: string | null | undefined): FleetTier | null {
  if (!isPlanKey(key)) return null;
  const t = key!.slice(PLAN_KEY_PREFIX.length);
  return t === 'starter' || t === 'growth' || t === 'enterprise' ? t : null;
}

/** The branch price of a plan (Enterprise has unlimited branches: none). */
export function branchKeyFor(tier: FleetTier): string | null {
  return tier === 'enterprise' ? null : `${BRANCH_KEY_PREFIX}${tier}`;
}

// ---- Stripe prices by lookup_key --------------------------------------------

export type StripePrice = { id: string; lookup_key: string | null; unit_amount: number | null };

const CACHE_MS = 5 * 60 * 1000;
const cache = new Map<string, { at: number; price: StripePrice }>();

/** Active prices for these lookup keys (missing keys are simply absent from the map). */
export async function stripePricesByKey(secret: string, keys: string[]): Promise<Map<string, StripePrice>> {
  const out = new Map<string, StripePrice>();
  const missing: string[] = [];
  const now = Date.now();
  for (const k of keys) {
    const hit = cache.get(k);
    if (hit && now - hit.at < CACHE_MS) out.set(k, hit.price);
    else missing.push(k);
  }
  if (missing.length > 0) {
    const qs = new URLSearchParams();
    qs.set('active', 'true');
    qs.set('limit', '100');
    for (const k of missing) qs.append('lookup_keys[]', k);
    const res = await fetch(`https://api.stripe.com/v1/prices?${qs.toString()}`, {
      headers: { Authorization: `Bearer ${secret}` },
    });
    if (!res.ok) throw new Error(`Stripe prices lookup -> ${res.status}: ${await res.text()}`);
    const body = await res.json();
    for (const p of body.data ?? []) {
      if (!p.lookup_key) continue;
      const price: StripePrice = { id: p.id, lookup_key: p.lookup_key, unit_amount: p.unit_amount ?? null };
      cache.set(p.lookup_key, { at: now, price });
      out.set(p.lookup_key, price);
    }
  }
  return out;
}

// ---- Limits and fees from the database ----------------------------------------

export type PlanRow = {
  tier: FleetTier;
  base_cents: number;
  included_cars: number;
  max_cars: number | null;
  included_branches: number | null;
  max_branches: number | null;
};

export async function loadPlan(db: SupabaseClient, tier: FleetTier): Promise<PlanRow> {
  const { data, error } = await db
    .from('fleet_plans')
    .select('tier, base_cents, included_cars, max_cars, included_branches, max_branches')
    .eq('tier', tier)
    .maybeSingle();
  if (error || !data) throw new Error(`fleet_plans ${tier}: ${error?.message ?? 'not found'}`);
  return data as PlanRow;
}

/** One-time acquisition fee of a service at a plan, in cents (null: no fee row). */
export async function acquisitionFeeCents(db: SupabaseClient, service: string, tier: FleetTier): Promise<number | null> {
  const { data, error } = await db
    .from('service_license_fees')
    .select('cents')
    .eq('service', service)
    .eq('tier', tier)
    .maybeSingle();
  if (error) throw new Error(`service_license_fees ${service}/${tier}: ${error.message}`);
  return data ? (data.cents as number) : null;
}

/** Extra branches to bill on a plan, and whether the account has more than the plan allows. */
export function branchExtras(plan: PlanRow, activeBranches: number): { extras: number; overMax: boolean; max: number | null } {
  if (plan.max_branches == null) return { extras: 0, overMax: false, max: null };
  const included = plan.included_branches ?? 0;
  return {
    extras: Math.min(Math.max(activeBranches - included, 0), Math.max(plan.max_branches - included, 0)),
    overMax: activeBranches > plan.max_branches,
    max: plan.max_branches,
  };
}

/** What is still owed for the acquisition: the fee of the plan minus what was already paid. */
export function acquisitionDueCents(feeCents: number | null, alreadyPaidCents: number | null): number {
  if (feeCents == null) return 0;
  return Math.max(feeCents - Math.max(alreadyPaidCents ?? 0, 0), 0);
}

// ---- Checkout lines ------------------------------------------------------------

/**
 * Form fields (key, value) of the Checkout line items: the car plan (quantity =
 * cars), the extra branches and the acquisition. The acquisition uses its Stripe
 * price when the amount due is that price's amount, else a one-off amount on the
 * acquisition product (plan upgrade: only the difference is due).
 */
export function checkoutLineFields(a: {
  planPriceId: string;
  cars: number;
  branchPriceId?: string | null;
  branchExtras: number;
  acquisition?: { dueCents: number; price?: StripePrice | null } | null;
}): [string, string][] {
  const f: [string, string][] = [];
  let i = 0;
  f.push([`line_items[${i}][price]`, a.planPriceId], [`line_items[${i}][quantity]`, String(a.cars)]);
  i++;
  if (a.branchExtras > 0 && a.branchPriceId) {
    f.push([`line_items[${i}][price]`, a.branchPriceId], [`line_items[${i}][quantity]`, String(a.branchExtras)]);
    i++;
  }
  if (a.acquisition && a.acquisition.dueCents > 0) {
    const p = a.acquisition.price;
    if (p && p.unit_amount === a.acquisition.dueCents) {
      f.push([`line_items[${i}][price]`, p.id]);
    } else {
      f.push(
        [`line_items[${i}][price_data][currency]`, 'usd'],
        [`line_items[${i}][price_data][product]`, ACQUISITION_PRODUCT],
        [`line_items[${i}][price_data][unit_amount]`, String(a.acquisition.dueCents)],
        [`line_items[${i}][price_data][tax_behavior]`, 'exclusive'],
      );
    }
    f.push([`line_items[${i}][quantity]`, '1']);
  }
  return f;
}
