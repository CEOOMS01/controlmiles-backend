create or replace function public.fn_enforce_odometer_cycle_tier()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_premium boolean;
  v_exempt boolean;
begin
  if new.odometer_cycle = 'weekly' or new.organization_id is not null then
    return new;
  end if;

  select premium_entitled, tier_enforcement_exempt
    into v_premium, v_exempt
    from public.profiles
    where id = new.owner_user_id;

  if coalesce(v_exempt, false) or coalesce(v_premium, false) then
    return new;
  end if;

  raise exception 'PREMIUM_REQUIRED_FOR_ODOMETER_CYCLE';
end;
$$;

drop trigger if exists tr_vehicles_enforce_odometer_cycle_tier on public.vehicles;
create trigger tr_vehicles_enforce_odometer_cycle_tier
  before insert or update of odometer_cycle on public.vehicles
  for each row execute function public.fn_enforce_odometer_cycle_tier();
