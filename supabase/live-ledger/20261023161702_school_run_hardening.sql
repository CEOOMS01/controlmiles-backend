-- School bus hardening (audit 2026-10-23, findings 7 and 10). Both functions
-- start from the live definitions.
--
-- 10. fn_route_run_track_stops runs on every location update of a school bus
--     (trigger on vehicles). It had no error handling, so any failure in the
--     stop logic aborted the update of the bus's position itself. It now
--     only raises a warning: a position update is never lost to stop tracking.
--
-- 7.  start_route_run, when the day's run already exists (app restarted, a
--     new trip, a substitute took over), updated monitor_name but not
--     monitor_id, so the run kept the previous monitor member while the name
--     said otherwise. Both now follow the day's crew.

create or replace function public.fn_route_run_track_stops()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_run record;
  v_stop record;
begin
  if new.last_latitude is null or new.last_longitude is null then
    return new;
  end if;
  begin
    for v_run in
      select id, organization_id, route_id from public.route_runs
       where vehicle_id = new.id and status = 'in_progress'
    loop
      update public.route_stop_events e
         set departed_at = now()
        from public.route_stops s
       where e.run_id = v_run.id and e.stop_id = s.id and e.departed_at is null
         and public.fn_meters_between(s.latitude, s.longitude, new.last_latitude, new.last_longitude) > s.radius_meters * 1.5;
      for v_stop in
        select s.id from public.route_stops s
         where s.route_id = v_run.route_id
           and public.fn_meters_between(s.latitude, s.longitude, new.last_latitude, new.last_longitude) <= s.radius_meters
           and not exists (select 1 from public.route_stop_events e where e.run_id = v_run.id and e.stop_id = s.id)
      loop
        insert into public.route_stop_events (organization_id, run_id, stop_id, method)
        values (v_run.organization_id, v_run.id, v_stop.id, 'auto')
        on conflict (run_id, stop_id) do nothing;
      end loop;
    end loop;
  exception when others then
    raise warning 'fn_route_run_track_stops failed for vehicle %: %', new.id, sqlerrm;
  end;
  return new;
end $function$;

create or replace function public.start_route_run(p_route_id uuid, p_session_id uuid)
returns uuid
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_route public.routes%rowtype;
  v_session public.sessions%rowtype;
  v_today date;
  v_run_id uuid;
  v_status text;
  v_crew record;
begin
  select * into v_route from public.routes where id = p_route_id;
  if not found then
    raise exception 'ROUTE_NOT_ASSIGNED';
  end if;
  perform public.fn_require_org_feature(v_route.organization_id, 'school');
  v_today := public.fn_org_today(v_route.organization_id);
  select * into v_crew from public.fn_route_crew(p_route_id, v_today);
  if v_crew.driver_id is distinct from auth.uid() then
    raise exception 'ROUTE_NOT_ASSIGNED';
  end if;
  if v_route.status <> 'active' or v_route.route_type not in ('school_am', 'school_pm') then
    raise exception 'ROUTE_NOT_ACTIVE';
  end if;
  select * into v_session from public.sessions
   where id = p_session_id and user_id = auth.uid() and not coalesce(is_closed, false);
  if not found then
    raise exception 'TRIP_NOT_ACTIVE';
  end if;

  select id, status into v_run_id, v_status from public.route_runs
   where route_id = p_route_id and run_date = v_today;
  if v_status = 'completed' then
    raise exception 'ROUTE_ALREADY_COMPLETED';
  end if;
  if v_run_id is not null then
    update public.route_runs
       set session_id = p_session_id, vehicle_id = coalesce(v_session.vehicle_id, vehicle_id), driver_id = auth.uid(),
           monitor_id = v_crew.monitor_id, monitor_name = v_crew.monitor_name
     where id = v_run_id;
    perform public.fn_route_run_mark_current_stops(v_run_id);
    return v_run_id;
  end if;

  if exists (
    select 1 from public.route_runs
     where driver_id = auth.uid() and status = 'in_progress' and run_date = v_today
  ) then
    raise exception 'ANOTHER_ROUTE_IN_PROGRESS';
  end if;

  insert into public.route_runs (organization_id, route_id, run_date, driver_id, vehicle_id, session_id, monitor_name)
  values (v_route.organization_id, p_route_id, v_today, auth.uid(),
          coalesce(v_session.vehicle_id, v_crew.vehicle_id), p_session_id, v_crew.monitor_name)
  returning id into v_run_id;
  perform public.fn_route_run_mark_current_stops(v_run_id);
  return v_run_id;
end $function$;
