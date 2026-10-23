# ControlMiles backend (single source of truth)

One repo for everything that runs in Supabase project `zuujwmcftycmdaxesdya`:
`supabase/migrations` (schema), `supabase/functions` (Edge Functions), `supabase/templates` (auth emails).
Every service of the ecosystem (Gig app, Fleet app, web, Fleet Services, School Bus, Driving School) talks to this backend; none of them owns migrations any more.
See docs/CORE_CONTRACT.md for what the platform (core) offers each service.

## Rules
1. Nothing is applied to the database without a file here first (no ad-hoc `execute_sql` DDL). If an emergency change is made live, export it here the same day.
2. A migration never copies an old function body: start from the LIVE definition (`pg_get_functiondef`), because `create or replace` silently drops earlier fixes (this already regressed `create_driver_invite`).
3. Every new table is registered in `ops.domain_tables` (core / gig / fleet / school_bus / driving_school) in the same migration; triggers on core tables get a `WHEN` guard and an `ops.domain_triggers` row.
4. Deployed Edge Functions must match `supabase/functions`; check after each deploy.

## live-ledger/
Verbatim export (2026-10-23) of every row of `supabase_migrations.schema_migrations` of the live database (211 migrations, 2026-07-21 .. 2026-10-22), including ones whose files were never in git. It is the ground truth of what was applied, not something to replay: many entries duplicate files in `migrations/` under other timestamps. Next step is a clean baseline (`supabase db dump`) once the CLI is logged into the ControlMiles account.

## Known drift at export time
- Added from live: 7 migrations of 2026-10-22 (domain guard, school guardians, driving school client portal, public page age of majority) and `20261022190000_capture_vehicles_fleet_template.sql` (objects applied outside the history).
- Edge Functions added/updated from live: `send-guardian-invite`, `ds-portal-access`, `check-email-exists` (retired stub), `resolve-driver-login` (parent IDs).
- Edge Functions where the repo is NEWER than live (not deployed yet): `create-checkout-session`, `stripe-webhook`, `cgc-seal-trip`.
- `create_driver_invite` regression FIXED 2026-10-23 (migration 20261023151914).
- Referenced but missing: `supabase/checks/domain_boundaries.sql`.
- `supabase/pending/`: migrations written and tested but NOT to be applied yet because they depend on a deploy elsewhere (empty now).
- Edge Function `ds-public-enroll` (deployed 2026-10-23): the door for the public enrollment form; optional secret TURNSTILE_SECRET turns the captcha on.

## Stripe (test mode connected 2026-10-23)
Catalog created in the Stripe test account (Entorno de prueba de Olympus Mont Systems LLC), found by `lookup_key`, never by id:
`fleet_plan_starter|growth|enterprise` (monthly, graduated by car), `fleet_branch_starter|growth`, `school_domain`, `acquisition_starter|growth|enterprise` (one-time; `acquisition_<service>_<tier>` overrides one service).
Functions `create-checkout-session` and `stripe-webhook` use them (copy of `_shared/fleet_pricing.ts` inside each folder; run `python scripts/check_copies.py` before deploying).
Secrets to set in Supabase (Edge Functions > Secrets): `STRIPE_SECRET_KEY` (sk_test_...) and `STRIPE_WEBHOOK_SECRET` (whsec_... of the webhook endpoint). The old `STRIPE_PRICE_ID_*` secrets are no longer read.
Webhook endpoint URL: https://zuujwmcftycmdaxesdya.supabase.co/functions/v1/stripe-webhook ; events: customer.subscription.created, .updated, .deleted, .paused, .resumed, invoice.upcoming, checkout.session.completed, checkout.session.async_payment_succeeded.
