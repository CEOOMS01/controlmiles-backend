update public.vehicles v
set odometer_cycle = 'monthly'
from public.organizations o
where o.id = v.organization_id
  and o.industry_template = 'driving_school'
  and v.odometer_cycle <> 'monthly';

create or replace function public.fn_vehicles_driving_school_cycle()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if new.organization_id is not null and exists (
    select 1 from public.organizations o
    where o.id = new.organization_id and o.industry_template = 'driving_school'
  ) then
    new.odometer_cycle := 'monthly';
  end if;
  return new;
end;
$$;
revoke execute on function public.fn_vehicles_driving_school_cycle() from public, anon, authenticated;

drop trigger if exists tr_vehicles_driving_school_cycle on public.vehicles;
create trigger tr_vehicles_driving_school_cycle
  before insert or update of organization_id on public.vehicles
  for each row execute function public.fn_vehicles_driving_school_cycle();

create or replace function public.fn_org_driving_school_cycle()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if new.industry_template = 'driving_school'
     and new.industry_template is distinct from old.industry_template then
    update public.vehicles
    set odometer_cycle = 'monthly'
    where organization_id = new.id and odometer_cycle <> 'monthly';
  end if;
  return new;
end;
$$;
revoke execute on function public.fn_org_driving_school_cycle() from public, anon, authenticated;

drop trigger if exists tr_org_driving_school_cycle on public.organizations;
create trigger tr_org_driving_school_cycle
  after update of industry_template on public.organizations
  for each row execute function public.fn_org_driving_school_cycle();
