CREATE OR REPLACE FUNCTION public.fn_send_safety_summaries()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  v_end date := (now() at time zone 'utc')::date - 1;
  v_start date := v_end - 14;
  v_prev_start date := v_start - 15;
  n int := 0;
begin
  with drivers as (
    select m.user_id, m.organization_id
    from public.organization_members m
    where m.member_role = 'driver' and m.is_active
  ),
  cur as (
    select s.user_id, s.organization_id, sum(coalesce(s.total_miles, 0))::numeric mi
    from public.sessions s
    join drivers d on d.user_id = s.user_id and d.organization_id = s.organization_id
    where s.date_key between v_start and v_end
    group by 1, 2
  ),
  prev as (
    select s.user_id, s.organization_id, sum(coalesce(s.total_miles, 0))::numeric mi
    from public.sessions s
    join drivers d on d.user_id = s.user_id and d.organization_id = s.organization_id
    where s.date_key between v_prev_start and v_start - 1
    group by 1, 2
  ),
  ev as (
    select e.user_id, e.organization_id,
      count(*) filter (where e.event_type = 'harsh_braking' and e.recorded_at >= v_start::timestamptz) hb,
      count(*) filter (where e.event_type = 'hard_acceleration' and e.recorded_at >= v_start::timestamptz) ha,
      count(*) filter (where e.event_type = 'speeding' and e.recorded_at >= v_start::timestamptz) sp,
      sum(case e.event_type when 'harsh_braking' then 3 when 'hard_acceleration' then 2 when 'speeding' then 5 else 0 end)
        filter (where e.recorded_at < v_start::timestamptz) prev_pts
    from public.driver_safety_events e
    join drivers d on d.user_id = e.user_id and d.organization_id = e.organization_id
    where e.recorded_at >= v_prev_start::timestamptz and e.recorded_at < (v_end + 1)::timestamptz
    group by 1, 2
  ),
  rws as (
    select c.user_id, c.organization_id, c.mi,
      coalesce(ev.hb, 0) hb, coalesce(ev.ha, 0) ha, coalesce(ev.sp, 0) sp,
      public.fn_safety_score(3 * coalesce(ev.hb, 0) + 2 * coalesce(ev.ha, 0) + 5 * coalesce(ev.sp, 0), c.mi) score,
      public.fn_safety_score(coalesce(ev.prev_pts, 0), p.mi) prev_score
    from cur c
    left join prev p on p.user_id = c.user_id and p.organization_id = c.organization_id
    left join ev on ev.user_id = c.user_id and ev.organization_id = c.organization_id
    where c.mi > 0
  ),
  ins as (
    insert into public.driver_notifications (user_id, organization_id, kind, data)
    select r.user_id, r.organization_id, 'safety_summary',
      jsonb_build_object(
        'period_start', v_start, 'period_end', v_end,
        'miles', round(r.mi, 1),
        'harsh_braking', r.hb, 'hard_acceleration', r.ha, 'speeding', r.sp,
        'score', r.score, 'previous_score', r.prev_score,
        'trend', case
          when r.score is null or r.prev_score is null then
            case when r.score is null then 'unrated' when r.score >= 90 then 'good' else 'attention' end
          when r.score > r.prev_score then 'better'
          when r.score < r.prev_score then 'worse'
          else 'steady' end)
    from rws r
    returning 1
  )
  select count(*) into n from ins;
  return n;
end;
$function$;
REVOKE EXECUTE ON FUNCTION public.fn_send_safety_summaries() FROM PUBLIC, anon, authenticated;
