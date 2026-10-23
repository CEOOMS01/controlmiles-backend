create or replace function public.fn_vehicles_set_cycle_anchor()
returns trigger
language plpgsql
set search_path to 'public'
as $$
begin
  if new.odometer_cycle_anchor is null then
    new.odometer_cycle_anchor := (new.created_at::date) - (extract(isodow from new.created_at::date)::int - 1);
  end if;
  return new;
end;
$$;

create or replace function public.fn_odometer_cycle_start(p_vehicle_id uuid, p_date date)
returns date
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare
  v_vehicle record;
  v_cycle text;
  v_anchor date;
  v_anchor_monday date;
  v_monday date;
  v_days_since_anchor int;
begin
  select * into v_vehicle from public.vehicles where id = p_vehicle_id;
  if v_vehicle is null then
    return null;
  end if;

  if not (
    v_vehicle.owner_user_id = auth.uid()
    or v_vehicle.assigned_driver_id = auth.uid()
    or (v_vehicle.organization_id is not null and public.is_org_member(v_vehicle.organization_id))
  ) then
    return null;
  end if;

  v_cycle := coalesce(v_vehicle.odometer_cycle, 'weekly');
  v_anchor := coalesce(
    v_vehicle.odometer_cycle_anchor,
    (v_vehicle.created_at::date) - (extract(isodow from v_vehicle.created_at::date)::int - 1)
  );

  v_monday := p_date - (extract(isodow from p_date)::int - 1);

  if v_cycle = 'weekly' then
    return v_monday;
  elsif v_cycle = 'monthly' then
    return date_trunc('month', p_date)::date;
  else
    v_anchor_monday := v_anchor - (extract(isodow from v_anchor)::int - 1);
    v_days_since_anchor := v_monday - v_anchor_monday;
    return v_anchor_monday + (floor(v_days_since_anchor / 14.0)::int * 14);
  end if;
end;
$$;
