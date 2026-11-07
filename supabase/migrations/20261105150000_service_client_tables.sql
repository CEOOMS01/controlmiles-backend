-- One real client table per service, so no account or vehicle is ever
-- ambiguous about which service it belongs to.
--   gig_clients                 one row per Gig driver (profiles.id)           domain gig
--   driving_school_clients      one row per driving-school company             domain driving_school
--   school_bus_clients          one row per school-bus company                 domain school_bus
--   sales_clients               one row per sales company                      domain fleet
--   trucking_clients            one row per trucking company                   domain fleet
--   general_business_clients    one row per general transport business         domain fleet
-- profiles / organizations stay the identity tables (41 foreign keys depend
-- on profiles); the service tables hang off them and triggers keep them in
-- sync. Purely additive: nothing existing is moved or dropped.
-- Domain boundaries (ops.domain_*): every table/trigger is registered first,
-- and no function touches tables of two different services, so each service
-- has its own sync function and triggers.

insert into ops.domain_tables (tbl, domain) values
  ('gig_clients', 'gig'),
  ('driving_school_clients', 'driving_school'),
  ('school_bus_clients', 'school_bus'),
  ('sales_clients', 'fleet'),
  ('trucking_clients', 'fleet'),
  ('general_business_clients', 'fleet');

insert into ops.domain_triggers (tbl, tg, domain, guard) values
  ('organizations', 'tr_organizations_service', 'core', null),
  ('vehicles', 'tr_vehicles_1_service', 'core', null),
  ('profiles', 'tr_profiles_gig_client', 'gig', 'account_type = ''gig'''),
  ('organizations', 'tr_org_svc_driving_school_add', 'driving_school', 'service = ''driving_school'''),
  ('organizations', 'tr_org_svc_driving_school_drop', 'driving_school', 'service = ''driving_school'''),
  ('organizations', 'tr_org_svc_school_bus_add', 'school_bus', 'service = ''school_bus'''),
  ('organizations', 'tr_org_svc_school_bus_drop', 'school_bus', 'service = ''school_bus'''),
  ('organizations', 'tr_org_svc_sales_add', 'fleet', 'service = ''sales'''),
  ('organizations', 'tr_org_svc_sales_drop', 'fleet', 'service = ''sales'''),
  ('organizations', 'tr_org_svc_trucking_add', 'fleet', 'service = ''trucking'''),
  ('organizations', 'tr_org_svc_trucking_drop', 'fleet', 'service = ''trucking'''),
  ('organizations', 'tr_org_svc_general_business_add', 'fleet', 'service = ''general_business'''),
  ('organizations', 'tr_org_svc_general_business_drop', 'fleet', 'service = ''general_business''');

create or replace function public.service_for_industry(p_industry text)
returns text language sql immutable as $$
  select case p_industry
    when 'driving_school'   then 'driving_school'
    when 'school_transport' then 'school_bus'
    when 'sales'            then 'sales'
    when 'trucking'         then 'trucking'
    else 'general_business'
  end
$$;

create table public.gig_clients (
  profile_id uuid primary key references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table public.driving_school_clients (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table public.school_bus_clients (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table public.sales_clients (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table public.trucking_clients (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table public.general_business_clients (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.organizations add column service text;
alter table public.vehicles add column service text;

-- organizations.service follows industry_template
create function public.fn_sync_org_service()
returns trigger language plpgsql as $$
begin
  new.service := public.service_for_industry(new.industry_template);
  return new;
end $$;

create trigger tr_organizations_service
  before insert or update of industry_template on public.organizations
  for each row execute function public.fn_sync_org_service();

-- vehicles.service: the company's service, or 'gig' for a driver-owned vehicle
create function public.fn_set_vehicle_service()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.organization_id is not null then
    select o.service into new.service from organizations o where o.id = new.organization_id;
  else
    new.service := 'gig';
  end if;
  return new;
end $$;

create trigger tr_vehicles_1_service
  before insert or update of organization_id, owner_user_id on public.vehicles
  for each row execute function public.fn_set_vehicle_service();

-- Gig drivers
create function public.fn_sync_gig_client()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into gig_clients(profile_id) values (new.id) on conflict do nothing;
  return new;
end $$;

create trigger tr_profiles_gig_client
  after insert or update of account_type on public.profiles
  for each row when (new.account_type = 'gig')
  execute function public.fn_sync_gig_client();

-- One sync function + add/drop trigger pair per company service
create function public.fn_sync_driving_school_client()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.service = 'driving_school' then
    insert into driving_school_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from driving_school_clients where organization_id = new.id;
  end if;
  return new;
end $$;
create trigger tr_org_svc_driving_school_add
  after insert or update of service on public.organizations
  for each row when (new.service = 'driving_school')
  execute function public.fn_sync_driving_school_client();
create trigger tr_org_svc_driving_school_drop
  after update of service on public.organizations
  for each row when (old.service = 'driving_school' and new.service <> 'driving_school')
  execute function public.fn_sync_driving_school_client();

create function public.fn_sync_school_bus_client()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.service = 'school_bus' then
    insert into school_bus_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from school_bus_clients where organization_id = new.id;
  end if;
  return new;
end $$;
create trigger tr_org_svc_school_bus_add
  after insert or update of service on public.organizations
  for each row when (new.service = 'school_bus')
  execute function public.fn_sync_school_bus_client();
create trigger tr_org_svc_school_bus_drop
  after update of service on public.organizations
  for each row when (old.service = 'school_bus' and new.service <> 'school_bus')
  execute function public.fn_sync_school_bus_client();

create function public.fn_sync_sales_client()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.service = 'sales' then
    insert into sales_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from sales_clients where organization_id = new.id;
  end if;
  return new;
end $$;
create trigger tr_org_svc_sales_add
  after insert or update of service on public.organizations
  for each row when (new.service = 'sales')
  execute function public.fn_sync_sales_client();
create trigger tr_org_svc_sales_drop
  after update of service on public.organizations
  for each row when (old.service = 'sales' and new.service <> 'sales')
  execute function public.fn_sync_sales_client();

create function public.fn_sync_trucking_client()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.service = 'trucking' then
    insert into trucking_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from trucking_clients where organization_id = new.id;
  end if;
  return new;
end $$;
create trigger tr_org_svc_trucking_add
  after insert or update of service on public.organizations
  for each row when (new.service = 'trucking')
  execute function public.fn_sync_trucking_client();
create trigger tr_org_svc_trucking_drop
  after update of service on public.organizations
  for each row when (old.service = 'trucking' and new.service <> 'trucking')
  execute function public.fn_sync_trucking_client();

create function public.fn_sync_general_business_client()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.service = 'general_business' then
    insert into general_business_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from general_business_clients where organization_id = new.id;
  end if;
  return new;
end $$;
create trigger tr_org_svc_general_business_add
  after insert or update of service on public.organizations
  for each row when (new.service = 'general_business')
  execute function public.fn_sync_general_business_client();
create trigger tr_org_svc_general_business_drop
  after update of service on public.organizations
  for each row when (old.service = 'general_business' and new.service <> 'general_business')
  execute function public.fn_sync_general_business_client();

-- Backfill what already exists. Only the new `service` column is written,
-- so none of the other organization/vehicle triggers fire.
update public.organizations set service = public.service_for_industry(industry_template);
update public.vehicles v set service = coalesce(
  (select o.service from public.organizations o where o.id = v.organization_id), 'gig');
insert into public.gig_clients(profile_id)
  select id from public.profiles where account_type = 'gig';

alter table public.organizations
  alter column service set not null,
  add constraint organizations_service_check
    check (service in ('driving_school','school_bus','sales','trucking','general_business'));
alter table public.vehicles
  alter column service set not null,
  add constraint vehicles_service_check
    check (service in ('gig','driving_school','school_bus','sales','trucking','general_business'));

-- Access: a gig driver reads their own row, a company's members read theirs.
alter table public.gig_clients enable row level security;
alter table public.driving_school_clients enable row level security;
alter table public.school_bus_clients enable row level security;
alter table public.sales_clients enable row level security;
alter table public.trucking_clients enable row level security;
alter table public.general_business_clients enable row level security;

create policy gig_clients_own on public.gig_clients
  for select using (profile_id = auth.uid());

create policy driving_school_clients_members on public.driving_school_clients
  for select using (exists (select 1 from public.organization_members m
    where m.organization_id = driving_school_clients.organization_id
      and m.user_id = auth.uid() and m.is_active));
create policy school_bus_clients_members on public.school_bus_clients
  for select using (exists (select 1 from public.organization_members m
    where m.organization_id = school_bus_clients.organization_id
      and m.user_id = auth.uid() and m.is_active));
create policy sales_clients_members on public.sales_clients
  for select using (exists (select 1 from public.organization_members m
    where m.organization_id = sales_clients.organization_id
      and m.user_id = auth.uid() and m.is_active));
create policy trucking_clients_members on public.trucking_clients
  for select using (exists (select 1 from public.organization_members m
    where m.organization_id = trucking_clients.organization_id
      and m.user_id = auth.uid() and m.is_active));
create policy general_business_clients_members on public.general_business_clients
  for select using (exists (select 1 from public.organization_members m
    where m.organization_id = general_business_clients.organization_id
      and m.user_id = auth.uid() and m.is_active));

revoke execute on function
  public.fn_set_vehicle_service(), public.fn_sync_gig_client(),
  public.fn_sync_driving_school_client(), public.fn_sync_school_bus_client(),
  public.fn_sync_sales_client(), public.fn_sync_trucking_client(),
  public.fn_sync_general_business_client(), public.fn_sync_org_service()
  from public, anon, authenticated;
