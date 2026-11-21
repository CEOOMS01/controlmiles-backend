-- Admin bell as a notification panel (2026-11-20, owner request): every event gets a traffic-light level,
-- alerts that were about a situation that has since been fixed show green with a tick ("resolved"), and each
-- person can dismiss events from their own panel (one, or all they can see). Dismissing hides it for that person
-- only; the log itself (schedule_events) is untouched.
--   red    = needs action now (instructor did not show, class with no instructor starting within the hour,
--            instructor 15+ min late)
--   amber  = pay attention (late start under 15 min, no instructor yet but not close, late release / cancel)
--   green  = information, or an alert that is resolved

create table if not exists public.schedule_event_dismissals (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null,
  event_id uuid not null references public.schedule_events(id) on delete cascade,
  dismissed_at timestamptz not null default now(),
  primary key (user_id, event_id)
);
alter table public.schedule_event_dismissals enable row level security;
drop policy if exists schedule_event_dismissals_own on public.schedule_event_dismissals;
create policy schedule_event_dismissals_own on public.schedule_event_dismissals for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
revoke all on public.schedule_event_dismissals from anon;

create or replace function public.dismiss_schedule_events(p_org uuid, p_ids uuid[] default null) returns integer
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if auth.uid() is null or not public.is_org_operator_or_above(p_org) then raise exception 'FORBIDDEN'; end if;
  insert into public.schedule_event_dismissals (organization_id, user_id, event_id)
  select e.organization_id, auth.uid(), e.id
    from public.schedule_events e
   where e.organization_id = p_org and public.fn_branch_gate(p_org, e.branch_id)
     and (p_ids is null or e.id = any (p_ids))
  on conflict do nothing;
  get diagnostics n = row_count;
  return n;
end $$;
revoke all on function public.dismiss_schedule_events(uuid, uuid[]) from public, anon;
grant execute on function public.dismiss_schedule_events(uuid, uuid[]) to authenticated;

create or replace function public.get_schedule_events(p_org uuid, p_limit integer default 50)
returns jsonb language plpgsql security definer set search_path to 'public' as $$
declare
  v_last timestamptz;
begin
  if auth.uid() is null or not public.is_org_operator_or_above(p_org) then raise exception 'FORBIDDEN'; end if;
  select r.last_read_at into v_last from public.schedule_event_reads r where r.organization_id = p_org and r.user_id = auth.uid();
  return jsonb_build_object(
    'unread', (select count(*) from public.schedule_events e
                where e.organization_id = p_org and public.fn_branch_gate(p_org, e.branch_id)
                  and e.created_at > coalesce(v_last, 'epoch'::timestamptz)
                  and not exists (select 1 from public.schedule_event_dismissals d where d.user_id = auth.uid() and d.event_id = e.id)),
    'events', coalesce((
      select jsonb_agg(x order by x.rank, x.created_at desc) from (
        select y.*, (case y.severity when 'red' then 0 when 'amber' then 1 else 2 end) as rank from (
          select e.id, e.kind, e.created_at, e.actor_role, e.payload, e.block_id, e.branch_id,
                 e.created_at > coalesce(v_last, 'epoch'::timestamptz) as is_new,
                 (e.actor_id is not null and e.actor_id = e.instructor_id) as by_instructor,
                 nullif(trim(concat_ws(' ', pa.first_name, pa.last_name)), '') as actor_name,
                 nullif(trim(concat_ws(' ', pi.first_name, pi.last_name)), '') as instructor_name,
                 z.resolved,
                 case
                   when e.kind in ('class_no_show', 'class_unclaimed_soon') and z.resolved then 'green'
                   when e.kind = 'class_no_show' then 'red'
                   when e.kind = 'class_unclaimed_soon' then
                        case when coalesce((e.payload->>'minutes_left')::numeric, 0) <= 60 then 'red' else 'amber' end
                   when e.kind = 'class_late_start' then
                        case when coalesce((e.payload->>'late_minutes')::numeric, 0) >= 15 then 'red' else 'amber' end
                   when e.kind = 'class_released' and coalesce((e.payload->>'hours_before')::numeric, 99) < 24 then 'amber'
                   when e.kind = 'class_cancelled' and coalesce((e.payload->>'late_cancel')::boolean, false) then 'amber'
                   when e.kind = 'class_deleted' then 'amber'
                   else 'green'
                 end as severity
            from public.schedule_events e
            left join public.profiles pa on pa.id = e.actor_id
            left join public.profiles pi on pi.id = e.instructor_id
            left join public.shift_blocks b on b.id = e.block_id
            cross join lateral (select case e.kind
                   -- fixed when the class started, was cancelled or deleted, or (for "no instructor") got one
                   when 'class_no_show' then (b.id is null or b.status <> 'scheduled' or b.started_at is not null or b.driver_id is distinct from e.instructor_id)
                   when 'class_unclaimed_soon' then (b.id is null or b.status <> 'scheduled' or b.driver_id is not null)
                   else false end as resolved) z
           where e.organization_id = p_org and public.fn_branch_gate(p_org, e.branch_id)
             and not exists (select 1 from public.schedule_event_dismissals d where d.user_id = auth.uid() and d.event_id = e.id)
        ) y
        order by (case y.severity when 'red' then 0 when 'amber' then 1 else 2 end), y.created_at desc
        limit least(greatest(coalesce(p_limit, 50), 1), 200)) x
    ), '[]'::jsonb));
end $$;
