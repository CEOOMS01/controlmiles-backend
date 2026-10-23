alter table public.organizations
  add column stripe_customer_id text,
  add column subscription_tier text check (subscription_tier in ('starter', 'growth')),
  add column subscription_status text,
  add column subscription_vehicle_count integer,
  add column subscription_updated_at timestamptz;
