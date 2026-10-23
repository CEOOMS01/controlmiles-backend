create or replace function public.fn_delete_personal_rows_on_profile_delete()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform set_config('cm.account_deletion', 'on', true);
  delete from public.vehicle_inspections where user_id = old.id and organization_id is null;
  delete from public.trip_incidents where user_id = old.id and organization_id is null;
  delete from public.fuel_purchases where user_id = old.id and organization_id is null;
  delete from public.session_gps_breadcrumbs where user_id = old.id and organization_id is null;
  return old;
end $$;

create or replace function public.fn_freeze_closed_route()
returns trigger
language plpgsql
set search_path to 'public'
as $$
begin
  if current_setting('cm.account_deletion', true) is not distinct from 'on' then
    return NEW;
  end if;
  if OLD.status = 'closed' then
    raise exception 'Cannot modify a closed route';
  end if;
  if NEW.status = 'closed' and OLD.status is distinct from 'closed' then
    NEW.closed_at := now();
  end if;
  return NEW;
end;
$$;

create or replace function public.fn_freeze_started_shift_block()
returns trigger
language plpgsql
set search_path to 'public'
as $$
begin
  if current_setting('cm.shift_block_rpc', true) is not distinct from 'on'
     or current_setting('cm.account_deletion', true) is not distinct from 'on' then
    return new;
  end if;
  if old.status = 'scheduled' then
    return new;
  end if;
  if old.status = 'cancelled' and new.status = 'scheduled'
     and (new.driver_id, new.vehicle_id, new.block_date, new.start_time, new.end_time, new.note)
         is not distinct from
         (old.driver_id, old.vehicle_id, old.block_date, old.start_time, old.end_time, old.note) then
    return new;
  end if;
  raise exception 'A class that already started cannot be edited';
end $$;
