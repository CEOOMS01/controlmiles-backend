alter table public.vehicles
  add column fuel_tank_capacity_gal numeric check (fuel_tank_capacity_gal is null or fuel_tank_capacity_gal > 0);

create table public.fuel_anomalies (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  purchase_id uuid not null references public.fuel_purchases(id) on delete cascade,
  vehicle_id uuid not null references public.vehicles(id) on delete cascade,
  kind text not null check (kind in (
    'duplicate', 'over_capacity', 'location_mismatch', 'no_trip',
    'no_miles', 'low_mpg', 'price_mismatch', 'price_high'
  )),
  severity text not null check (severity in ('high', 'medium', 'low')),
  detail text not null,
  metrics jsonb not null default '{}'::jsonb,
  status text not null default 'open' check (status in ('open', 'dismissed', 'confirmed')),
  review_note text,
  reviewed_by uuid references public.profiles(id),
  reviewed_at timestamptz,
  notified_at timestamptz,
  created_at timestamptz not null default now(),
  unique (purchase_id, kind)
);

create index fuel_anomalies_org_status_idx on public.fuel_anomalies (organization_id, status, created_at desc);

alter table public.fuel_anomalies enable row level security;

create policy fuel_anomalies_select on public.fuel_anomalies
for select using (
  exists (
    select 1 from public.organization_members m
    where m.organization_id = fuel_anomalies.organization_id
      and m.user_id = auth.uid()
      and m.is_active
      and m.member_role in ('owner', 'admin', 'operator')
  )
);

alter table public.fuel_purchases
  add column receipt_path text generated always as
    (nullif(split_part(receipt_image_url, '/object/public/fuel_receipts/', 2), '')) stored;
create index fuel_purchases_receipt_path_idx on public.fuel_purchases (receipt_path);

create policy fuel_receipts_select_org_admin
on storage.objects for select
using (
  bucket_id = 'fuel_receipts'
  and exists (
    select 1 from public.fuel_purchases fp
    where fp.receipt_path = storage.objects.name
      and fp.organization_id is not null
      and public.is_org_admin_or_owner(fp.organization_id)
  )
);

alter publication supabase_realtime add table public.fuel_anomalies;
