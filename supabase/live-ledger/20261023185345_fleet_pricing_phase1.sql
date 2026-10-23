-- One global fleet price list (phase 1 of docs/PRICING_PLAN, owner decision
-- 2026-10-23). Until now only driving schools had a base price with cars
-- included, a car cap for Starter and a branch allowance; every other
-- service was priced per vehicle. This puts the driving-school table in data
-- and applies it to every service:
--
--   plan        monthly  cars incl.  extra car   extras from car 16  Starter cap  branches incl./max  extra branch
--   starter     $59      3           $12.99      same                10 cars      1 / 2               $24.99
--   growth      $125     5           $19.99      $16.99              none         2 / 4               $19.99
--   enterprise  $175     7           $27.99      $23.99              none         unlimited           -
--
-- Plus a ONE-TIME acquisition fee per plan, the same for every service
-- (the right to use the professional software of that service):
-- starter $150, growth $200, enterprise $300. The table is per service AND
-- plan so one service can get its own amount later without code.
--
-- This phase only changes data and limits. Nothing is charged yet (Stripe
-- is phase 2) and no page reads the new tables yet (phase 3).

-- 1. Tables (registered first: the domain guard refuses unregistered ones).
insert into ops.domain_tables (tbl, domain) values ('fleet_plans', 'core'), ('service_license_fees', 'core')
on conflict (tbl) do update set domain = excluded.domain;

create table if not exists public.fleet_plans (
  tier text primary key check (tier in ('starter', 'growth', 'enterprise')),
  sort smallint not null,
  base_cents integer not null check (base_cents >= 0),
  included_cars integer not null check (included_cars >= 0),
  extra_car_cents integer not null check (extra_car_cents >= 0),
  volume_car_cents integer check (volume_car_cents is null or volume_car_cents >= 0),
  volume_from integer not null default 16 check (volume_from > 1),
  max_cars integer check (max_cars is null or max_cars > 0),
  included_branches integer check (included_branches is null or included_branches >= 0),
  max_branches integer check (max_branches is null or max_branches >= 1),
  extra_branch_cents integer check (extra_branch_cents is null or extra_branch_cents >= 0)
);

create table if not exists public.service_license_fees (
  service text not null check (service in ('general', 'delivery', 'field_service', 'trucking', 'construction',
                                           'passenger', 'sales', 'driving_school', 'school_transport')),
  tier text not null references public.fleet_plans (tier),
  cents integer not null check (cents >= 0),
  primary key (service, tier)
);

alter table public.fleet_plans enable row level security;
alter table public.service_license_fees enable row level security;
revoke all on public.fleet_plans, public.service_license_fees from anon, authenticated;
comment on table public.fleet_plans is
  'Internal: the global fleet price list. Read through public_pricing_catalog() and the limit functions.';
comment on table public.service_license_fees is
  'Internal: one-time acquisition fee per service and plan. Read through public_pricing_catalog().';

insert into public.fleet_plans
  (tier, sort, base_cents, included_cars, extra_car_cents, volume_car_cents, volume_from, max_cars,
   included_branches, max_branches, extra_branch_cents) values
  ('starter',    1,  5900, 3, 1299, null, 16, 10,   1,    2,    2499),
  ('growth',     2, 12500, 5, 1999, 1699, 16, null, 2,    4,    1999),
  ('enterprise', 3, 17500, 7, 2799, 2399, 16, null, null, null, null)
on conflict (tier) do nothing;

insert into public.service_license_fees (service, tier, cents)
select s.service, t.tier, t.cents
  from (values ('general'), ('delivery'), ('field_service'), ('trucking'), ('construction'),
               ('passenger'), ('sales'), ('driving_school'), ('school_transport')) as s(service)
 cross join (values ('starter', 15000), ('growth', 20000), ('enterprise', 30000)) as t(tier, cents)
on conflict (service, tier) do nothing;

-- 2. What an organization has paid for the acquisition of its service
-- (written by the Stripe webhook in phase 2; protected like the other
-- billing columns).
alter table public.organizations
  add column if not exists service_acquired_at timestamptz,
  add column if not exists service_acquisition_cents integer,
  add column if not exists service_acquisition_tier text;

create or replace function public.fn_guard_org_billing_columns()
returns trigger
language plpgsql
set search_path to 'public'
as $function$
begin
  if current_user not in ('authenticated', 'anon') then
    return new;
  end if;

  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
    new.created_at := now();
    new.tier_enforcement_exempt := false;
    new.stripe_customer_id := null;
    new.stripe_subscription_id := null;
    new.subscription_tier := null;
    new.subscription_status := null;
    new.subscription_vehicle_count := null;
    new.subscription_updated_at := null;
    new.fleet_type_confirmed_at := null;
    new.service_acquired_at := null;
    new.service_acquisition_cents := null;
    new.service_acquisition_tier := null;
    return new;
  end if;

  if new.id is distinct from old.id
     or new.created_by is distinct from old.created_by
     or new.created_at is distinct from old.created_at
     or new.tier_enforcement_exempt is distinct from old.tier_enforcement_exempt
     or new.stripe_customer_id is distinct from old.stripe_customer_id
     or new.stripe_subscription_id is distinct from old.stripe_subscription_id
     or new.subscription_tier is distinct from old.subscription_tier
     or new.subscription_status is distinct from old.subscription_status
     or new.subscription_vehicle_count is distinct from old.subscription_vehicle_count
     or new.subscription_updated_at is distinct from old.subscription_updated_at
     or new.industry_template is distinct from old.industry_template
     or new.fleet_type_confirmed_at is distinct from old.fleet_type_confirmed_at
     or new.service_acquired_at is distinct from old.service_acquired_at
     or new.service_acquisition_cents is distinct from old.service_acquisition_cents
     or new.service_acquisition_tier is distinct from old.service_acquisition_tier
  then
    raise exception 'PROTECTED_ORG_COLUMN: this field cannot be changed directly';
  end if;
  return new;
end;
$function$;

-- 3. Branch allowance for every service (was driving school only; the other
-- services had no limit). Same numbers as before for driving schools. No
-- subscription: 1 branch, no extras.
create or replace function public.fn_org_branch_allowance_internal(p_org uuid)
returns table(included integer, max_branches integer, extra_price_cents integer, active integer)
language sql
stable security definer
set search_path to 'public'
as $function$
  with o as (
    select o.id, o.tier_enforcement_exempt from public.organizations o where o.id = p_org
  ), t as (
    select case
             when (select tier_enforcement_exempt from o) or public.fn_org_enterprise_internal(p_org) then 'enterprise'
             else public.fn_org_tier_internal(p_org)
           end as tier
  )
  select case when t.tier = 'none' then 1 else p.included_branches end,
         case when t.tier = 'none' then 1 else p.max_branches end,
         case when t.tier = 'none' then null else p.extra_branch_cents end,
         (select count(*)::int from public.branches b where b.organization_id = p_org and not b.is_archived)
    from o
    cross join t
    left join public.fleet_plans p on p.tier = t.tier;
$function$;

-- 4. The Starter car cap for every service (was driving school only), read
-- from fleet_plans. Exempt accounts, Growth and Enterprise are not capped.
-- Replaces fn_vehicles_school_limit and its trigger. Core table trigger:
-- registered first (domain guard rule R3).
delete from ops.domain_triggers where tbl = 'vehicles' and tg = 'tr_vehicles_school_limit';
insert into ops.domain_triggers (tbl, tg, domain, guard) values ('vehicles', 'tr_vehicles_plan_limit', 'core', null)
on conflict (tbl, tg) do update set domain = excluded.domain, guard = excluded.guard;

create or replace function public.fn_vehicles_plan_limit()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_active int;
  v_max int;
begin
  if new.organization_id is null or coalesce(new.is_archived, false) then return new; end if;
  if tg_op = 'UPDATE' and not coalesce(old.is_archived, false) and old.organization_id is not distinct from new.organization_id then
    return new;
  end if;
  if exists (select 1 from public.organizations o where o.id = new.organization_id and o.tier_enforcement_exempt) then
    return new;
  end if;
  if public.fn_org_enterprise_internal(new.organization_id) or public.fn_org_tier_internal(new.organization_id) <> 'starter' then
    return new;
  end if;
  select p.max_cars into v_max from public.fleet_plans p where p.tier = 'starter';
  if v_max is null then return new; end if;
  select count(*) into v_active from public.vehicles
   where organization_id = new.organization_id and not coalesce(is_archived, false) and id <> new.id;
  if v_active >= v_max then
    raise exception 'Starter allows up to % cars. Upgrade to Growth to add more.', v_max using errcode = 'P0001';
  end if;
  return new;
end $function$;
revoke execute on function public.fn_vehicles_plan_limit() from public, anon, authenticated;

drop trigger if exists tr_vehicles_school_limit on public.vehicles;
create trigger tr_vehicles_plan_limit
  before insert or update of is_archived, organization_id on public.vehicles
  for each row when (new.organization_id is not null)
  execute function public.fn_vehicles_plan_limit();
drop function if exists public.fn_vehicles_school_limit();

-- 5. What the public pricing page reads: plans, acquisition fees and, for
-- each service, the features it gets at every plan (from plan_feature_rules).
create or replace function public.public_pricing_catalog()
returns jsonb
language sql
stable security definer
set search_path to 'public'
as $function$
  select jsonb_build_object(
    'plans', (select jsonb_agg(to_jsonb(p) - 'sort' order by p.sort) from public.fleet_plans p),
    'acquisition', (select jsonb_agg(jsonb_build_object('service', f.service, 'tier', f.tier, 'cents', f.cents)
                                      order by f.service, f.tier)
                      from public.service_license_fees f),
    'services', (select jsonb_agg(jsonb_build_object(
                          'service', s.service,
                          'features', jsonb_build_object(
                            'starter', public.fn_plan_features(s.service, 1),
                            'growth', public.fn_plan_features(s.service, 2),
                            'enterprise', public.fn_plan_features(s.service, 3)))
                        order by s.service)
                   from (select distinct service from public.service_license_fees) s));
$function$;
revoke execute on function public.public_pricing_catalog() from public;
grant execute on function public.public_pricing_catalog() to anon, authenticated;
