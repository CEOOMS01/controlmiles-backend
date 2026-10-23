create table public.ifta_fuel_tax_rates (
  id uuid primary key default gen_random_uuid(),
  quarter text not null,
  jurisdiction_code text not null,
  fuel_type text not null,
  rate_usd numeric,
  source_quarter_label text not null,
  fetched_at timestamptz not null default now(),
  unique (quarter, jurisdiction_code, fuel_type)
);

alter table public.ifta_fuel_tax_rates enable row level security;

create policy ifta_fuel_tax_rates_select
on public.ifta_fuel_tax_rates
for select
using (auth.role() = 'authenticated');

create index ifta_fuel_tax_rates_quarter_idx on public.ifta_fuel_tax_rates (quarter);

create extension if not exists pg_net;
create extension if not exists pg_cron;

select cron.schedule(
  'ifta-quarterly-rate-sync',
  '0 6 1 1,4,7,10 *',
  $$
  select net.http_post(
    url := 'https://zuujwmcftycmdaxesdya.supabase.co/functions/v1/sync-ifta-tax-rates',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'X-Sync-Secret', (select decrypted_secret from vault.decrypted_secrets where name = 'ifta_sync_shared_secret')
    ),
    body := '{}'::jsonb
  );
  $$
);
