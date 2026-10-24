-- Address search without a public autocomplete (2026-10-24). Results of looking
-- up NON-personal places (schools, depots, generic stops) are cached per
-- organization, as the OpenStreetMap Nominatim policy asks of apps. Student
-- home addresses are personal data and are never cached here (they live on the
-- student row) nor sent to Nominatim.
insert into ops.domain_tables (tbl, domain) values ('geocode_cache', 'core') on conflict do nothing;

create table if not exists public.geocode_cache (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  query_norm text not null check (char_length(query_norm) between 3 and 200),
  label text not null check (char_length(label) <= 240),
  latitude double precision not null check (latitude between -90 and 90),
  longitude double precision not null check (longitude between -180 and 180),
  provider text not null check (provider in ('census', 'nominatim')),
  created_at timestamptz not null default now(),
  primary key (organization_id, query_norm)
);

alter table public.geocode_cache enable row level security;

create policy geocode_cache_select on public.geocode_cache for select to authenticated
  using (public.is_org_operator_or_above(organization_id));
create policy geocode_cache_insert on public.geocode_cache for insert to authenticated
  with check (public.is_org_operator_or_above(organization_id));
create policy geocode_cache_update on public.geocode_cache for update to authenticated
  using (public.is_org_operator_or_above(organization_id))
  with check (public.is_org_operator_or_above(organization_id));

revoke all on public.geocode_cache from anon;
create index if not exists geocode_cache_created_idx on public.geocode_cache (created_at);
