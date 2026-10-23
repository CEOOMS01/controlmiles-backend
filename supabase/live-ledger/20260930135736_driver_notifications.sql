create table public.driver_notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  kind text not null check (kind in ('trip_safety', 'safety_summary')),
  session_id uuid references public.sessions(id) on delete set null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  read_at timestamptz
);
create index driver_notifications_user_idx on public.driver_notifications (user_id, created_at desc);
create unique index driver_notifications_trip_once on public.driver_notifications (session_id) where kind = 'trip_safety';
alter table public.driver_notifications enable row level security;
create policy driver_notifications_select_own on public.driver_notifications
for select using (user_id = auth.uid());

CREATE OR REPLACE FUNCTION public.mark_driver_notifications_read(p_ids uuid[] DEFAULT NULL)
RETURNS void
LANGUAGE sql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  update public.driver_notifications
  set read_at = now()
  where user_id = auth.uid() and read_at is null
    and (p_ids is null or id = any (p_ids));
$function$;
REVOKE EXECUTE ON FUNCTION public.mark_driver_notifications_read(uuid[]) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.mark_driver_notifications_read(uuid[]) TO authenticated;

CREATE OR REPLACE FUNCTION public.fn_notify_trip_safety()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  v_hb int; v_ha int; v_sp int;
begin
  if new.organization_id is null or not new.is_closed or coalesce(old.is_closed, false) then
    return null;
  end if;
  begin
    select count(*) filter (where event_type = 'harsh_braking'),
           count(*) filter (where event_type = 'hard_acceleration'),
           count(*) filter (where event_type = 'speeding')
    into v_hb, v_ha, v_sp
    from public.driver_safety_events
    where session_id = new.id;
    if v_hb + v_ha + v_sp > 0 then
      insert into public.driver_notifications (user_id, organization_id, kind, session_id, data)
      values (new.user_id, new.organization_id, 'trip_safety', new.id,
              jsonb_build_object('harsh_braking', v_hb, 'hard_acceleration', v_ha, 'speeding', v_sp,
                                 'miles', round(coalesce(new.total_miles, 0)::numeric, 1),
                                 'trip_date', coalesce(new.date_key, new.start_time::date)))
      on conflict do nothing;
    end if;
  exception when others then
    raise warning 'trip safety notification failed for %: %', new.id, sqlerrm;
  end;
  return null;
end;
$function$;

create trigger sessions_notify_trip_safety
after update of is_closed on public.sessions
for each row execute function public.fn_notify_trip_safety();

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
    select s.user_id, s.organization_id, sum(coalesce(s.total_miles, 0)) mi
    from public.sessions s
    join drivers d on d.user_id = s.user_id and d.organization_id = s.organization_id
    where s.date_key between v_start and v_end
    group by 1, 2
  ),
  prev as (
    select s.user_id, s.organization_id, sum(coalesce(s.total_miles, 0)) mi
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
        'miles', round(r.mi::numeric, 1),
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

select cron.schedule('driver-safety-summaries', '0 14 1,16 * *', $$select public.fn_send_safety_summaries();$$);
