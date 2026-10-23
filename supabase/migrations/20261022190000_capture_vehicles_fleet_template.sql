-- CAPTURE of live state (exported 2026-10-23). These objects exist in the
-- production database (zuujwmcftycmdaxesdya) but were applied outside the
-- migration history (no row in supabase_migrations.schema_migrations), so
-- no repo had them. Written idempotent: safe to run on a database that
-- already has them, and it recreates them on a fresh one.
--
-- What it is: vehicles.fleet_template is a denormalized copy of
-- organizations.industry_template, kept in sync by two triggers. The
-- school-bus and driving-school triggers on vehicles use it in their WHEN
-- clause, so they cost nothing for gig or other fleet vehicles
-- (domain boundary rule R4, ops.domain_triggers).

alter table public.vehicles add column if not exists fleet_template text;

create or replace function public.fn_vehicles_fleet_template()
returns trigger language plpgsql security definer set search_path to 'public' as $$
begin
  if new.organization_id is null then
    new.fleet_template := null;
  else
    select industry_template into new.fleet_template
      from public.organizations where id = new.organization_id;
  end if;
  return new;
end $$;
revoke execute on function public.fn_vehicles_fleet_template() from public, anon, authenticated;

create or replace function public.fn_org_fleet_template_to_vehicles()
returns trigger language plpgsql security definer set search_path to 'public' as $$
begin
  update public.vehicles set fleet_template = new.industry_template
   where organization_id = new.id and fleet_template is distinct from new.industry_template;
  return null;
end $$;
revoke execute on function public.fn_org_fleet_template_to_vehicles() from public, anon, authenticated;

drop trigger if exists tr_vehicles_0_fleet_template on public.vehicles;
create trigger tr_vehicles_0_fleet_template
  before insert or update of organization_id, fleet_template on public.vehicles
  for each row execute function public.fn_vehicles_fleet_template();

drop trigger if exists tr_organizations_fleet_template on public.organizations;
create trigger tr_organizations_fleet_template
  after update of industry_template on public.organizations
  for each row when (new.industry_template is distinct from old.industry_template)
  execute function public.fn_org_fleet_template_to_vehicles();

drop trigger if exists tr_vehicles_driving_school_cycle on public.vehicles;
create trigger tr_vehicles_driving_school_cycle
  before insert or update of organization_id on public.vehicles
  for each row when (new.fleet_template = 'driving_school')
  execute function public.fn_vehicles_driving_school_cycle();

drop trigger if exists tr_vehicles_school_limit on public.vehicles;
create trigger tr_vehicles_school_limit
  before insert or update of is_archived, organization_id on public.vehicles
  for each row when (new.fleet_template = 'driving_school')
  execute function public.fn_vehicles_school_limit();

drop trigger if exists trg_vehicles_route_run_stops on public.vehicles;
create trigger trg_vehicles_route_run_stops
  after update of last_latitude, last_longitude on public.vehicles
  for each row
  when (new.fleet_template = 'school_transport'
        and (new.last_latitude is distinct from old.last_latitude
             or new.last_longitude is distinct from old.last_longitude))
  execute function public.fn_route_run_track_stops();

update public.vehicles v set fleet_template = o.industry_template
  from public.organizations o
 where o.id = v.organization_id and v.fleet_template is distinct from o.industry_template;
