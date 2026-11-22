-- bus_route_needs let ANYONE in when the route had no monitor (2026-11-22).
--
-- Found by tests/service_isolation.sql with real users of other services: the access check was
--     if not (is_operator_or_above or driver = me or monitor = me) then raise ...
-- On a route without a monitor the last term is NULL, so the whole condition is NULL, and "if NULL" does not
-- raise: any signed-in user could read the needs codes and notes of that route's students. Nobody outside the
-- team had accounts and the tables held no real needs, so nothing was exposed in practice, but it is the kind of
-- hole the separation work exists to close. Every term is now forced to true/false.
-- Applied to the Fleet project on 2026-11-22.

create or replace function public.bus_route_needs(p_route_id uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_org uuid; v_crew record; v_ok boolean; v_res jsonb;
begin
  select organization_id into v_org from public.routes where id = p_route_id;
  if v_org is null then raise exception 'ROUTE_NOT_FOUND'; end if;
  perform public.fn_require_org_feature(v_org, 'school');
  select * into v_crew from public.fn_route_crew(p_route_id, public.fn_org_today(v_org));
  -- every term is forced to true/false: a route without a monitor gives NULL, and "not NULL" would let anyone in
  v_ok := coalesce(public.is_org_operator_or_above(v_org), false)
       or coalesce(v_crew.driver_id = auth.uid(), false)
       or coalesce(v_crew.monitor_id = auth.uid(), false);
  if not v_ok then raise exception 'NOT_AUTHORIZED'; end if;
  with riders as (select distinct a.student_id from public.bus_stop_assignments a where a.route_id = p_route_id),
  needs as (
    select n.student_id, c.code, c.label, c.grp, c.sort
      from public.bus_student_needs n
      join public.bus_need_catalog c on c.id = n.need_id and c.is_active
     where n.student_id in (select student_id from riders)
  ),
  progs as (
    select s.id as student_id, c.code, c.label
      from public.bus_students s
      join public.bus_need_catalog c on c.id = s.program_need_id
     where s.id in (select student_id from riders)
  )
  select jsonb_build_object(
    -- only the codes used on this route: the driver sees what he needs, not the whole catalog
    'legend', coalesce((select jsonb_agg(jsonb_build_object('code', l.code, 'label', l.label, 'group', l.grp) order by l.grp, l.code)
                          from (select distinct code, label, grp from needs
                                union select distinct code, label, 'program' from progs) l), '[]'::jsonb),
    'students', coalesce((select jsonb_object_agg(r.student_id::text, jsonb_build_object(
                  'codes', coalesce((select jsonb_agg(n.code order by n.sort, n.code) from needs n where n.student_id = r.student_id), '[]'::jsonb),
                  'program', (select p.code from progs p where p.student_id = r.student_id),
                  'note', (select s.transport_note from public.bus_students s where s.id = r.student_id)))
                  from riders r), '{}'::jsonb))
    into v_res;
  return v_res;
end $$;
revoke execute on function public.bus_route_needs(uuid) from public, anon;
