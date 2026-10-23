-- School bus: a route that cannot be finished (audit 2026-10-23, finding 4).
-- The office can plan a child's pick-up without a drop-off (the web does not
-- force both). Once the driver marks that child on board there was no stop
-- where the child could be marked off, so complete_route_run answered
-- STUDENTS_STILL_ON_BOARD forever and the run could never be closed.
--
-- Rule now: a child with a planned pick-up and NO planned drop-off on the
-- route is listed at the route's LAST stop to be dropped off there, and
-- record_ridership accepts that drop-off there. Nothing else changes: a
-- planned drop-off still has to be recorded at its own stop, and
-- complete_route_run is untouched (it still refuses to finish with a child
-- on board).
-- Both functions start from the live definitions.

create or replace function public.my_school_routes_today(p_organization_id uuid)
returns jsonb
language plpgsql
stable security definer
set search_path to 'public'
as $function$
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
                                        where re.run_id = run.id and re.student_id = st.id and re.action = 'released'))
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
end $function$;

create or replace function public.record_ridership(p_run_id uuid, p_stop_id uuid, p_student_id uuid, p_action text, p_done boolean, p_reason text default null::text, p_note text default null::text)
returns void
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_run public.route_runs%rowtype := public.fn_my_crew_run(p_run_id);
  v_assign_action text := case when p_action = 'released' then 'board' else p_action end;
begin
  if p_action not in ('board', 'alight', 'released') then raise exception 'Invalid action'; end if;
  if not exists (
    select 1 from public.student_stop_assignments
     where student_id = p_student_id and route_id = v_run.route_id and stop_id = p_stop_id and action = v_assign_action
  ) and not (
    -- Planned pick-up with no planned drop-off: dropped off at the last stop.
    p_action = 'alight'
    and p_stop_id = (select s2.id from public.route_stops s2 where s2.route_id = v_run.route_id order by s2.seq desc limit 1)
    and exists (select 1 from public.student_stop_assignments b
                 where b.student_id = p_student_id and b.route_id = v_run.route_id and b.action = 'board')
    and not exists (select 1 from public.student_stop_assignments x
                     where x.student_id = p_student_id and x.route_id = v_run.route_id and x.action = 'alight')
  ) then
    raise exception 'Student is not assigned to this stop';
  end if;
  if p_done then
    if p_action = 'released' and p_reason is null then
      raise exception 'RELEASE_REASON_REQUIRED';
    end if;
    insert into public.ridership_events (organization_id, run_id, stop_id, student_id, action, reason, note, recorded_by)
    values (v_run.organization_id, p_run_id, p_stop_id, p_student_id, p_action,
            case when p_action = 'released' then p_reason end,
            case when p_action = 'released' then nullif(trim(p_note), '') end,
            auth.uid())
    on conflict (run_id, student_id, action)
      do update set reason = excluded.reason, note = excluded.note, at = now(), recorded_by = excluded.recorded_by;
    if p_action = 'board' then
      delete from public.ridership_events where run_id = p_run_id and student_id = p_student_id and action = 'released';
    elsif p_action = 'released' then
      delete from public.ridership_events where run_id = p_run_id and student_id = p_student_id and action = 'board';
    end if;
  else
    delete from public.ridership_events
     where run_id = p_run_id and student_id = p_student_id and action = p_action;
  end if;
end $function$;
