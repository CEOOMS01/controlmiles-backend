-- "Not riding the bus" notices reach the driver app (2026-10-25), step 2 of
-- 20261025140753_student_ride_notices.
--
-- * my_school_routes_today: every student now carries `notice` (null, or
--   {reason, will_attend_school, note}) when a parent/the office told us they
--   are not riding this run. `status` is unchanged, so app versions that do not
--   know about notices keep working exactly as before; the new app shows the
--   student as notified and lets the driver skip the stop.
-- * complete_route_run: a student with a notice for that run no longer blocks
--   finishing (an afternoon rider told us to skip would otherwise be red/expected
--   and raise UNRESOLVED_STUDENTS).

create or replace function public.fn_ride_notice_applies(p_student_id uuid, p_date date, p_route_type text)
returns boolean
language sql
stable
security definer
set search_path to 'public'
as $$
  select exists (
    select 1 from public.student_ride_notices n
     where n.student_id = p_student_id and n.notice_date = p_date
       and n.part in ('both', case when p_route_type = 'school_pm' then 'pm' else 'am' end)
  );
$$;
revoke all on function public.fn_ride_notice_applies(uuid, date, text) from public, anon, authenticated;

create or replace function public.complete_route_run(p_run_id uuid, p_child_check boolean, p_latitude double precision, p_longitude double precision)
returns void
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_run public.route_runs%rowtype := public.fn_my_open_run(p_run_id);
  v_route_type text := (select route_type from public.routes where id = v_run.route_id);
  v_on_board int;
  v_unresolved int;
begin
  if not coalesce(p_child_check, false) then
    raise exception 'CHILD_CHECK_REQUIRED';
  end if;
  select count(*) into v_on_board
    from public.ridership_events b
   where b.run_id = p_run_id and b.action = 'board'
     and not exists (select 1 from public.ridership_events x
                      where x.run_id = p_run_id and x.student_id = b.student_id and x.action = 'alight');
  if v_on_board > 0 then
    raise exception 'STUDENTS_STILL_ON_BOARD';
  end if;
  select count(*) into v_unresolved
    from public.student_stop_assignments a
   where a.route_id = v_run.route_id and a.action = 'board'
     and public.fn_rider_status(v_run.route_id, p_run_id, a.stop_id, a.student_id, 'board') in ('red', 'expected')
     and not public.fn_ride_notice_applies(a.student_id, v_run.run_date, v_route_type);
  if v_unresolved > 0 then
    raise exception 'UNRESOLVED_STUDENTS';
  end if;
  update public.route_stop_events set departed_at = coalesce(departed_at, now())
   where run_id = p_run_id;
  update public.route_runs
     set status = 'completed', completed_at = now(), child_check_at = now(),
         child_check_latitude = p_latitude, child_check_longitude = p_longitude
   where id = p_run_id;
end $$;

create or replace function public.my_school_routes_today(p_organization_id uuid)
returns jsonb
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare
  v_today date := public.fn_org_today(p_organization_id);
  v_dow smallint := extract(isodow from v_today)::smallint;
begin
  if auth.uid() is null then raise exception 'Not authenticated'; end if;
  if not public.fn_org_feature_internal(p_organization_id, 'school') then return '[]'::jsonb; end if;
  return coalesce((
    select jsonb_agg(route_json order by start_time nulls last, route_name)
    from (
      select r.scheduled_start_time as start_time, r.name as route_name,
        (select jsonb_build_object(
          'id', r.id, 'name', r.name, 'route_type', r.route_type,
          'scheduled_start_time', r.scheduled_start_time,
          'vehicle_id', crew.vehicle_id,
          'my_role', case when crew.driver_id = auth.uid() then 'driver' else 'monitor' end,
          'school', (select ss.name from public.school_sites ss where ss.id = r.school_site_id),
          'run', (select jsonb_build_object('id', rr.id, 'status', rr.status, 'started_at', rr.started_at,
                                            'completed_at', rr.completed_at)
                    from public.route_runs rr where rr.id = run.id),
          'stops', coalesce((
            select jsonb_agg(stop_json order by seq)
            from (
              select s.seq,
                jsonb_build_object(
                  'id', s.id, 'seq', s.seq, 'name', s.name, 'address', s.address,
                  'latitude', s.latitude, 'longitude', s.longitude, 'radius_meters', s.radius_meters,
                  'scheduled_time', s.scheduled_time, 'stop_kind', s.stop_kind,
                  'arrived_at', (select e.arrived_at from public.route_stop_events e
                                  where e.stop_id = s.id and e.run_id = run.id),
                  'departed_at', (select e.departed_at from public.route_stop_events e
                                   where e.stop_id = s.id and e.run_id = run.id),
                  'students', coalesce((
                    select jsonb_agg(jsonb_build_object(
                      'id', st.id, 'name', st.first_name || coalesce(' ' || st.last_initial || '.', ''),
                      'grade', st.grade, 'action', a.action,
                      'done', exists (select 1 from public.ridership_events re
                                       where re.run_id = run.id and re.student_id = st.id and re.action = a.action),
                      'status', public.fn_rider_status(r.id, run.id, s.id, st.id, a.action),
                      'release_reason', (select re.reason from public.ridership_events re
                                          where re.run_id = run.id and re.student_id = st.id and re.action = 'released'),
                      'release_note', (select re.note from public.ridership_events re
                                        where re.run_id = run.id and re.student_id = st.id and re.action = 'released'),
                      'notice', (select jsonb_build_object('reason', n.reason,
                                                           'will_attend_school', n.will_attend_school,
                                                           'note', n.note)
                                   from public.student_ride_notices n
                                  where n.student_id = st.id and n.notice_date = v_today
                                    and n.part in ('both', case when r.route_type = 'school_pm' then 'pm' else 'am' end)))
                      order by st.first_name)
                      from (
                        select sa.student_id, sa.action
                          from public.student_stop_assignments sa
                         where sa.stop_id = s.id
                        union all
                        -- Planned pick-up, no planned drop-off: dropped off at the last stop.
                        select b.student_id, 'alight'::text
                          from public.student_stop_assignments b
                         where b.route_id = r.id and b.action = 'board'
                           and s.seq = (select max(s2.seq) from public.route_stops s2 where s2.route_id = r.id)
                           and not exists (select 1 from public.student_stop_assignments x
                                            where x.route_id = r.id and x.student_id = b.student_id and x.action = 'alight')
                      ) a
                      join public.students st on st.id = a.student_id and st.is_active), '[]'::jsonb)) as stop_json
              from public.route_stops s where s.route_id = r.id
            ) stops_q), '[]'::jsonb))) as route_json
      from public.routes r
      cross join lateral public.fn_route_crew(r.id, v_today) crew
      left join lateral (select rr.id from public.route_runs rr
                          where rr.route_id = r.id and rr.run_date = v_today) run on true
     where r.organization_id = p_organization_id
       and (crew.driver_id = auth.uid() or crew.monitor_id = auth.uid())
       and r.route_type in ('school_am', 'school_pm')
       and r.status = 'active'
       and v_dow = any (r.service_days)
    ) q
  ), '[]'::jsonb);
end $$;
