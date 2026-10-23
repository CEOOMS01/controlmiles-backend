// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/create-checkout-session/checkout_rules.ts
//
// When things are charged (owner decision 2026-10-23):
//   * 15 days free (database trial, no card).
//   * To continue, the customer pays the ACQUISITION of the service (one-time)
//     plus the first month at once. There is NO free month after the trial
//     (owner decision 2026-10-23: the company cannot afford it). If it is ever
//     brought back, set FIRST_MONTH_FREE to true: the first monthly charge is
//     then one month after the payment, once per organization.
//   * Whoever cancels and comes back within 90 days does not pay the
//     acquisition again; after 90 days they do.
// Pure functions so they can be tested without Stripe or the database.

export const CREDIT_WINDOW_DAYS = 90;
export const FIRST_MONTH_FREE = false;

/** Same day next month (UTC), or the last day of that month when it is shorter. */
export function addOneMonth(from: Date): Date {
  const y = from.getUTCFullYear() + (from.getUTCMonth() === 11 ? 1 : 0);
  const m = (from.getUTCMonth() + 1) % 12;
  const lastDay = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  return new Date(Date.UTC(y, m, Math.min(from.getUTCDate(), lastDay),
    from.getUTCHours(), from.getUTCMinutes(), from.getUTCSeconds()));
}

/**
 * Unix time (seconds) when the first monthly charge should happen, or null
 * when the free month is not available (the organization had a subscription).
 */
export function firstChargeAt(org: { stripe_subscription_id: string | null }, now: Date): number | null {
  if (!FIRST_MONTH_FREE || org.stripe_subscription_id) return null;
  return Math.floor(addOneMonth(now).getTime() / 1000);
}

/**
 * What was already paid for the acquisition and still counts: all of it while
 * the organization comes back within 90 days of its last subscription change
 * (the cancellation), nothing after that.
 */
export function acquisitionCreditCents(
  org: { service_acquired_at: string | null; service_acquisition_cents: number | null; subscription_updated_at: string | null },
  now: Date,
): number {
  if (!org.service_acquired_at) return 0;
  if (org.subscription_updated_at) {
    const days = (now.getTime() - new Date(org.subscription_updated_at).getTime()) / 86_400_000;
    if (days > CREDIT_WINDOW_DAYS) return 0;
  }
  return Math.max(org.service_acquisition_cents ?? 0, 0);
}
