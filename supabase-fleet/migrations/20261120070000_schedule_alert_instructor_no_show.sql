-- Driving school: alert for the admin bell when an assigned instructor does not show up (2026-11-20, owner request).
-- A class WITH an instructor whose start time passed 15 minutes ago and that is still 'scheduled' (never started)
-- writes one 'class_no_show' row into schedule_events, once per class. Fleet project only. Same readers as the
-- other alerts (operators/admins/owner, inside their branch); instructors never see this log.

do $$
declare c text;
begin
  for c in select conname from pg_constraint
            where conrelid = 'public.schedule_events'::regclass and contype = 'c'
              and pg_get_constraintdef(oid) like '%class_created%' loop
    execute format('alter table public.schedule_events drop constraint %I', c);
  end loop;
end $$;
alter table public.schedule_events add constraint schedule_events_kind_check check (kind in (
  'class_created', 'class_booked_portal', 'class_claimed', 'class_released', 'class_reassigned',
  'class_changed', 'class_cancelled', 'class_deleted',
  'time_off_added', 'time_off_removed', 'unavailable_added', 'unavailable_removed',
  'class_late_start', 'class_unclaimed_soon', 'class_no_show'));

-- Looked up every 5 minutes. Window: 15 minutes after the start until the class would be over (so an old class
-- is never reported long after the fact).
create or replace function public.fn_ds_alert_no_show_classes() returns integer
language plpgsql security definer set search_path = public as $$
declare
  r record;
  n int := 0;
begin
  for r in
    select b.id, b.organization_id, b.branch_id, b.driver_id, b.block_date, b.start_time, b.end_time,
           extract(epoch from (now() - ((b.block_date + b.start_time) at time zone coalesce(o.timezone, 'America/New_York')))) / 60 as mins_after,
           extract(epoch from (now() - ((b.block_date + b.end_time) at time zone coalesce(o.timezone, 'America/New_York')))) / 60 as mins_after_end
      from public.shift_blocks b
      join public.organizations o on o.id = b.organization_id
     where b.driver_id is not null and b.status = 'scheduled' and b.started_at is null
       and b.block_date between current_date - 1 and current_date + 1
       and not exists (select 1 from public.schedule_events e where e.block_id = b.id and e.kind = 'class_no_show')
  loop
    if r.mins_after >= 15 and r.mins_after_end < 0 then
      insert into public.schedule_events (organization_id, branch_id, kind, actor_role, instructor_id, block_id, payload)
      values (r.organization_id, r.branch_id, 'class_no_show', 'system', r.driver_id, r.id,
              jsonb_build_object('date', r.block_date, 'start', r.start_time, 'end', r.end_time,
                                 'minutes_after', round(r.mins_after)));
      n := n + 1;
    end if;
  end loop;
  return n;
end $$;
revoke all on function public.fn_ds_alert_no_show_classes() from public, anon, authenticated;

select cron.schedule('ds-no-show-class-alerts', '*/5 * * * *', 'select public.fn_ds_alert_no_show_classes()');
