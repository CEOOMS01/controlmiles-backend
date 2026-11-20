-- Driving school: two alerts for the admin bell (2026-11-19, owner request). Fleet project only.
--   * class_late_start     -- an instructor started a class after its start time.
--   * class_unclaimed_soon -- a class with no instructor is about to begin (pickup_lead + 2 h window).
-- Both are rows of schedule_events, so they reach the web bell live and only operators/admins can read them
-- (RLS: is_org_operator_or_above). Instructors never see this log.

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
  'class_late_start', 'class_unclaimed_soon'));

-- Late start: written the moment the class goes in_progress with late_minutes > 0.
create or replace function public.fn_log_class_late_start() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.status = 'in_progress' and coalesce(new.late_minutes, 0) > 0
     and (old.status is distinct from 'in_progress' or old.late_minutes is distinct from new.late_minutes) then
    insert into public.schedule_events (organization_id, branch_id, kind, actor_id, actor_role, instructor_id, block_id, payload)
    values (new.organization_id, new.branch_id, 'class_late_start', new.driver_id, 'driver', new.driver_id, new.id,
            jsonb_build_object('date', new.block_date, 'start', new.start_time, 'end', new.end_time,
                               'late_minutes', new.late_minutes));
  end if;
  return new;
end $$;
drop trigger if exists tr_shift_blocks_late_start on public.shift_blocks;
create trigger tr_shift_blocks_late_start after update on public.shift_blocks
  for each row execute function public.fn_log_class_late_start();

-- Unclaimed class about to start: once per class, looked up every 5 minutes.
create or replace function public.fn_ds_alert_unclaimed_classes() returns integer
language plpgsql security definer set search_path = public as $$
declare
  r record;
  n int := 0;
begin
  for r in
    select b.id, b.organization_id, b.branch_id, b.block_date, b.start_time, b.end_time,
           extract(epoch from (((b.block_date + b.start_time) at time zone coalesce(o.timezone, 'America/New_York')) - now())) / 60 as mins
      from public.shift_blocks b
      join public.organizations o on o.id = b.organization_id
     where b.driver_id is null and b.status = 'scheduled'
       and b.block_date between current_date - 1 and current_date + 1
       and not exists (select 1 from public.schedule_events e where e.block_id = b.id and e.kind = 'class_unclaimed_soon')
  loop
    if r.mins is not null and r.mins <= 120 and r.mins > -15 then
      insert into public.schedule_events (organization_id, branch_id, kind, actor_role, block_id, payload)
      values (r.organization_id, r.branch_id, 'class_unclaimed_soon', 'system', r.id,
              jsonb_build_object('date', r.block_date, 'start', r.start_time, 'end', r.end_time,
                                 'minutes_left', greatest(0, round(r.mins))));
      n := n + 1;
    end if;
  end loop;
  return n;
end $$;
revoke all on function public.fn_ds_alert_unclaimed_classes() from public, anon, authenticated;

select cron.schedule('ds-unclaimed-class-alerts', '*/5 * * * *', 'select public.fn_ds_alert_unclaimed_classes()');
