-- Olympus Mont Systems LLC - ControlMiles (Gig only)
-- A personal user who drove before adding a car has closed trips with
-- vehicle_id null. Closed trips are frozen on purpose (fn_freeze_closed_session:
-- the mileage record is evidence), so the app could never attach them to a car.
--
-- This adds ONE narrow exception, not a general edit:
--   * only fills a blank vehicle_id (never changes one car to another);
--   * only the caller's own personal trips (no organization), closed, not
--     CGC-sealed;
--   * only to a personal, non-archived car the caller owns;
--   * only inside assign_trips_to_vehicle(), through a transaction-local flag
--     that clients cannot set, and nothing else on the row may change;
--   * every trip it touches is recorded in trip_vehicle_assignments.
-- Fleet is unaffected: company trips always carry a vehicle.

insert into ops.domain_tables (tbl, domain) values ('trip_vehicle_assignments', 'gig') on conflict do nothing;

create table if not exists public.trip_vehicle_assignments (
  id uuid primary key default gen_random_uuid(),
  session_id uuid not null,
  user_id uuid not null,
  vehicle_id uuid not null,
  miles double precision,
  assigned_at timestamptz not null default now()
);
alter table public.trip_vehicle_assignments enable row level security;
create policy trip_vehicle_assignments_select_own on public.trip_vehicle_assignments
  for select to authenticated using (user_id = auth.uid());
revoke insert, update, delete on public.trip_vehicle_assignments from anon, authenticated;
create index if not exists trip_vehicle_assignments_user_idx on public.trip_vehicle_assignments (user_id);

create or replace function public.fn_freeze_closed_session()
returns trigger language plpgsql as $$
begin
  if OLD.is_closed = true then
    if OLD.cgc_sealed_at is null
       and NEW.cgc_sealed_at is not null
       and (to_jsonb(NEW) - 'cgc_decision_id' - 'cgc_sealed_at' - 'updated_at')
         = (to_jsonb(OLD) - 'cgc_decision_id' - 'cgc_sealed_at' - 'updated_at') then
      return NEW;
    end if;
    -- The one exception: fill a blank vehicle_id (see header).
    if OLD.vehicle_id is null
       and NEW.vehicle_id is not null
       and OLD.cgc_sealed_at is null
       and OLD.organization_id is null
       and coalesce(current_setting('cm.assign_trip_vehicle', true), '') = 'on'
       and (to_jsonb(NEW) - 'vehicle_id' - 'updated_at')
         = (to_jsonb(OLD) - 'vehicle_id' - 'updated_at') then
      return NEW;
    end if;
    raise exception 'Cannot modify a closed session';
  end if;
  return NEW;
end;
$$;

create or replace function public.assign_trips_to_vehicle(p_vehicle_id uuid)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_uid uuid := auth.uid();
  v record;
  n int;
  m double precision;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  select owner_user_id, organization_id, is_archived into v
    from public.vehicles where id = p_vehicle_id;
  if not found
     or v.organization_id is not null
     or v.owner_user_id is distinct from v_uid
     or coalesce(v.is_archived, false) then
    raise exception 'VEHICLE_NOT_YOURS' using errcode = 'P0001';
  end if;

  perform set_config('cm.assign_trip_vehicle', 'on', true);
  with upd as (
    update public.sessions
       set vehicle_id = p_vehicle_id
     where user_id = v_uid
       and organization_id is null
       and is_closed
       and vehicle_id is null
       and cgc_sealed_at is null
    returning id, total_miles
  ), ins as (
    insert into public.trip_vehicle_assignments (session_id, user_id, vehicle_id, miles)
    select id, v_uid, p_vehicle_id, total_miles from upd
    returning 1
  )
  select count(*), coalesce(sum(total_miles), 0) into n, m from upd;
  perform set_config('cm.assign_trip_vehicle', 'off', true);

  return jsonb_build_object('assigned', n, 'miles', m);
end;
$$;
revoke execute on function public.assign_trips_to_vehicle(uuid) from public, anon;
grant execute on function public.assign_trips_to_vehicle(uuid) to authenticated;
