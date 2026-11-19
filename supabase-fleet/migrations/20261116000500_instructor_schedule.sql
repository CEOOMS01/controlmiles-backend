-- Driving school: instructor schedule (2026-11-16, owner request). Fleet project only.
--
-- * An instructor sees the schedule of their school location (branch), takes a class that has no
--   instructor, releases one of theirs, and marks time off / unavailable hours.
-- * Admins and operators get a log of EVERY schedule change by any role (schedule_events) that the
--   web panel shows as a bell and updates live (Realtime).
-- * Portal clients can book (as before) but can no longer cancel or edit a class.
--
-- Instructors never write the tables directly: only through the SECURITY DEFINER functions below.

-- 1. A class may exist without an instructor, and knows its branch ------------------------------
alter table public.shift_blocks alter column driver_id drop not null;
alter table public.shift_blocks add column if not exists branch_id uuid references public.branches(id);
create index if not exists shift_blocks_open_idx
  on public.shift_blocks (organization_id, block_date) where driver_id is null;

create or replace function public.fn_shift_block_fill_branch() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.branch_id is null then
    if new.vehicle_id is not null then
      select v.branch_id into new.branch_id from public.vehicles v where v.id = new.vehicle_id;
    end if;
    if new.branch_id is null and new.driver_id is not null then
      select m.branch_id into new.branch_id from public.organization_members m
       where m.organization_id = new.organization_id and m.user_id = new.driver_id and m.is_active limit 1;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists tr_shift_blocks_fill_branch on public.shift_blocks;
create trigger tr_shift_blocks_fill_branch before insert on public.shift_blocks
  for each row execute function public.fn_shift_block_fill_branch();

-- 2. Change log for admins -----------------------------------------------------------------------
create table if not exists public.schedule_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  branch_id uuid references public.branches(id) on delete set null,
  kind text not null check (kind in (
    'class_created', 'class_booked_portal', 'class_claimed', 'class_released', 'class_reassigned',
    'class_changed', 'class_cancelled', 'class_deleted',
    'time_off_added', 'time_off_removed', 'unavailable_added', 'unavailable_removed')),
  actor_id uuid,
  actor_role text,
  instructor_id uuid,
  block_id uuid,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists schedule_events_org_idx on public.schedule_events (organization_id, created_at desc);
alter table public.schedule_events enable row level security;
drop policy if exists schedule_events_select on public.schedule_events;
create policy schedule_events_select on public.schedule_events for select to authenticated
  using (public.is_org_operator_or_above(organization_id));

create table if not exists public.schedule_event_reads (
  organization_id uuid not null references public.organizations(id) on delete cascade,
  user_id uuid not null,
  last_read_at timestamptz not null default now(),
  primary key (organization_id, user_id)
);
alter table public.schedule_event_reads enable row level security;
drop policy if exists schedule_event_reads_own on public.schedule_event_reads;
create policy schedule_event_reads_own on public.schedule_event_reads for all to authenticated
  using (user_id = auth.uid() and public.is_org_operator_or_above(organization_id))
  with check (user_id = auth.uid() and public.is_org_operator_or_above(organization_id));

insert into ops.domain_tables (tbl, domain) values ('schedule_events', 'driving_school'), ('schedule_event_reads', 'driving_school')
  on conflict do nothing;

-- Writes that log: classes
create or replace function public.fn_log_shift_block_event() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_kind text;
  v_actor uuid := auth.uid();
  v_role text;
  r public.shift_blocks;
  v_tz text;
  v_hours numeric;
  v_instr uuid;
begin
  if current_setting('cm.account_deletion', true) is not distinct from 'on' then
    return coalesce(new, old);
  end if;

  if tg_op = 'INSERT' then
    r := new;
    if new.source = 'template' then return new; end if;
    v_kind := case when new.booked_via = 'portal' then 'class_booked_portal' else 'class_created' end;
  elsif tg_op = 'DELETE' then
    r := old;
    if not exists (select 1 from public.organizations o where o.id = old.organization_id) then return old; end if;
    if old.status in ('in_progress', 'done') then return old; end if;
    v_kind := 'class_deleted';
  else
    r := new;
    if old.status in ('in_progress', 'done') or new.status in ('in_progress', 'done') then return new; end if;
    if new.status = 'cancelled' and old.status <> 'cancelled' then
      v_kind := 'class_cancelled';
    elsif old.driver_id is distinct from new.driver_id then
      v_kind := case when new.driver_id is null then 'class_released'
                     when old.driver_id is null then 'class_claimed'
                     else 'class_reassigned' end;
    elsif (old.block_date, old.start_time, old.end_time, old.vehicle_id, old.note)
          is distinct from (new.block_date, new.start_time, new.end_time, new.vehicle_id, new.note) then
      v_kind := 'class_changed';
    else
      return new;
    end if;
  end if;

  select m.member_role into v_role from public.organization_members m
   where m.organization_id = r.organization_id and m.user_id = v_actor and m.is_active limit 1;
  v_role := coalesce(v_role, case when v_actor is null and r.booked_via = 'portal' then 'client'
                                  when v_actor is null then 'system' else 'user' end);

  select coalesce(o.timezone, 'America/New_York') into v_tz from public.organizations o where o.id = r.organization_id;
  v_hours := round((extract(epoch from (((r.block_date + r.start_time) at time zone v_tz) - now())) / 3600)::numeric, 1);
  v_instr := case when tg_op = 'UPDATE' and v_kind = 'class_released' then old.driver_id else r.driver_id end;

  insert into public.schedule_events (organization_id, branch_id, kind, actor_id, actor_role, instructor_id, block_id, payload)
  values (r.organization_id, r.branch_id, v_kind, v_actor, v_role, v_instr, r.id,
          jsonb_build_object('date', r.block_date, 'start', r.start_time, 'end', r.end_time,
                             'hours_before', v_hours, 'has_student', r.student_id is not null,
                             'late_cancel', r.late_cancel));
  return coalesce(new, old);
end $$;
drop trigger if exists tr_shift_blocks_log_event on public.shift_blocks;
create trigger tr_shift_blocks_log_event after insert or update or delete on public.shift_blocks
  for each row execute function public.fn_log_shift_block_event();

-- Writes that log: time off and unavailable hours
create or replace function public.fn_log_time_off_event() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  r public.ds_time_off;
  v_role text;
  v_branch uuid;
begin
  if current_setting('cm.account_deletion', true) is not distinct from 'on' then return coalesce(new, old); end if;
  r := case when tg_op = 'DELETE' then old else new end;
  if tg_op = 'DELETE' and not exists (select 1 from public.organizations o where o.id = r.organization_id) then return old; end if;
  select m.member_role into v_role from public.organization_members m
   where m.organization_id = r.organization_id and m.user_id = auth.uid() and m.is_active limit 1;
  select m.branch_id into v_branch from public.organization_members m
   where m.organization_id = r.organization_id and m.user_id = r.instructor_id and m.is_active limit 1;
  insert into public.schedule_events (organization_id, branch_id, kind, actor_id, actor_role, instructor_id, payload)
  values (r.organization_id, v_branch, case when tg_op = 'DELETE' then 'time_off_removed' else 'time_off_added' end,
          auth.uid(), coalesce(v_role, 'user'), r.instructor_id,
          jsonb_build_object('from', r.date_from, 'to', r.date_to, 'note', r.note));
  return coalesce(new, old);
end $$;
drop trigger if exists tr_ds_time_off_log_event on public.ds_time_off;
create trigger tr_ds_time_off_log_event after insert or delete on public.ds_time_off
  for each row execute function public.fn_log_time_off_event();

create or replace function public.fn_log_blocked_hours_event() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  r public.ds_blocked_hours;
  v_role text;
  v_branch uuid;
begin
  if current_setting('cm.account_deletion', true) is not distinct from 'on' then return coalesce(new, old); end if;
  r := case when tg_op = 'DELETE' then old else new end;
  if tg_op = 'DELETE' and not exists (select 1 from public.organizations o where o.id = r.organization_id) then return old; end if;
  select m.member_role into v_role from public.organization_members m
   where m.organization_id = r.organization_id and m.user_id = auth.uid() and m.is_active limit 1;
  select m.branch_id into v_branch from public.organization_members m
   where m.organization_id = r.organization_id and m.user_id = r.instructor_id and m.is_active limit 1;
  insert into public.schedule_events (organization_id, branch_id, kind, actor_id, actor_role, instructor_id, payload)
  values (r.organization_id, v_branch, case when tg_op = 'DELETE' then 'unavailable_removed' else 'unavailable_added' end,
          auth.uid(), coalesce(v_role, 'user'), r.instructor_id,
          jsonb_build_object('weekday', r.weekday, 'date', r.on_date, 'start', r.start_time, 'end', r.end_time, 'label', r.label));
  return coalesce(new, old);
end $$;
drop trigger if exists tr_ds_blocked_hours_log_event on public.ds_blocked_hours;
create trigger tr_ds_blocked_hours_log_event after insert or delete on public.ds_blocked_hours
  for each row execute function public.fn_log_blocked_hours_event();

-- 3. Instructor functions ------------------------------------------------------------------------
create or replace function public.fn_ds_member(p_org uuid) returns public.organization_members
language sql stable security definer set search_path = public as $$
  select m.* from public.organization_members m
   where m.organization_id = p_org and m.user_id = auth.uid() and m.is_active limit 1;
$$;

-- Does a class of [p_date, p_start, p_end] clash with instructor p_instr's own classes, blocked hours or time off?
create or replace function public.fn_ds_instructor_conflict(
  p_org uuid, p_instr uuid, p_date date, p_start time, p_end time, p_except uuid default null)
returns text language sql stable security definer set search_path = public as $$
  select case
    when exists (select 1 from public.shift_blocks b
                  where b.organization_id = p_org and b.driver_id = p_instr and b.block_date = p_date
                    and b.status in ('scheduled', 'in_progress') and b.id is distinct from p_except
                    and b.start_time < p_end and b.end_time > p_start) then 'OTHER_CLASS'
    when exists (select 1 from public.ds_time_off t
                  where t.organization_id = p_org and t.instructor_id = p_instr
                    and p_date between t.date_from and t.date_to) then 'TIME_OFF'
    when exists (select 1 from public.ds_blocked_hours h
                  where h.organization_id = p_org and (h.instructor_id is null or h.instructor_id = p_instr)
                    and (h.weekday is null or h.weekday = extract(dow from p_date)::int)
                    and (h.on_date is null or h.on_date = p_date)
                    and h.start_time < p_end and h.end_time > p_start) then 'UNAVAILABLE'
    else null end;
$$;

create or replace function public.get_branch_schedule(p_org uuid, p_from date default null, p_days integer default 7)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  m public.organization_members;
  v_tz text;
  v_from date;
  v_n int := least(greatest(coalesce(p_days, 7), 1), 31);
  v_is_op boolean;
  d date;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  m := public.fn_ds_member(p_org);
  if m.id is null or not public.fn_org_has_classes(p_org) then return jsonb_build_object('classes', '[]'::jsonb, 'off', '[]'::jsonb, 'unavailable', '[]'::jsonb, 'me', v_uid); end if;
  v_is_op := m.member_role in ('owner', 'admin', 'operator');
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_org;
  v_from := coalesce(p_from, (now() at time zone v_tz)::date);
  for d in select (v_from + g)::date from generate_series(0, v_n - 1) g loop
    perform public.materialize_shift_blocks(p_org, d);
  end loop;

  return jsonb_build_object(
    'me', v_uid,
    'classes', coalesce((
      select jsonb_agg(jsonb_build_object(
          'id', b.id, 'date', b.block_date, 'start_time', b.start_time, 'end_time', b.end_time,
          'status', b.status, 'instructor_id', b.driver_id,
          'instructor_name', nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''),
          'mine', b.driver_id = v_uid, 'open', b.driver_id is null,
          'vehicle_label', nullif(concat_ws(' ', v.make, v.model), ''), 'vehicle_display_id', v.display_id,
          'student_name', case when b.driver_id = v_uid or v_is_op
                               then nullif(trim(concat_ws(' ', st.first_name, st.last_name)), '') end,
          'has_student', b.student_id is not null,
          'note', case when b.driver_id = v_uid or v_is_op then b.note end
        ) order by b.block_date, b.start_time)
        from public.shift_blocks b
        left join public.profiles p on p.id = b.driver_id
        left join public.vehicles v on v.id = b.vehicle_id
        left join public.ds_students st on st.id = b.student_id
       where b.organization_id = p_org and b.status <> 'cancelled'
         and b.block_date >= v_from and b.block_date < v_from + v_n
         and (m.any_branch or m.branch_id is null or b.branch_id is null or b.branch_id = m.branch_id)
    ), '[]'::jsonb),
    'off', coalesce((
      select jsonb_agg(jsonb_build_object('id', t.id, 'instructor_id', t.instructor_id,
          'instructor_name', nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''),
          'from', t.date_from, 'to', t.date_to, 'mine', t.instructor_id = v_uid,
          'note', case when t.instructor_id = v_uid or v_is_op then t.note end) order by t.date_from)
        from public.ds_time_off t
        join public.profiles p on p.id = t.instructor_id
       where t.organization_id = p_org and t.date_to >= v_from and t.date_from < v_from + v_n
         and exists (select 1 from public.organization_members x
                      where x.organization_id = p_org and x.user_id = t.instructor_id and x.is_active
                        and (m.any_branch or m.branch_id is null or x.branch_id is null or x.branch_id = m.branch_id))
    ), '[]'::jsonb),
    'unavailable', coalesce((
      select jsonb_agg(jsonb_build_object('id', h.id, 'instructor_id', h.instructor_id,
          'instructor_name', nullif(trim(concat_ws(' ', p.first_name, p.last_name)), ''),
          'weekday', h.weekday, 'date', h.on_date, 'start_time', h.start_time, 'end_time', h.end_time,
          'label', h.label, 'mine', h.instructor_id = v_uid) order by h.on_date nulls last, h.weekday nulls last, h.start_time)
        from public.ds_blocked_hours h
        left join public.profiles p on p.id = h.instructor_id
       where h.organization_id = p_org
         and (h.on_date is null or (h.on_date >= v_from and h.on_date < v_from + v_n))
    ), '[]'::jsonb));
end $$;

create or replace function public.claim_class(p_block uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  b public.shift_blocks;
  m public.organization_members;
  v_tz text;
  v_conflict text;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  select * into b from public.shift_blocks where id = p_block for update;
  if b.id is null then raise exception 'CLASS_NOT_FOUND'; end if;
  m := public.fn_ds_member(b.organization_id);
  if m.id is null or m.member_role = 'monitor' or not public.fn_org_has_classes(b.organization_id) then
    raise exception 'CLASS_NOT_FOUND';
  end if;
  if not (m.any_branch or m.branch_id is null or b.branch_id is null or b.branch_id = m.branch_id) then
    raise exception 'CLASS_NOT_FOUND';
  end if;
  if b.status <> 'scheduled' then raise exception 'CLASS_NOT_AVAILABLE'; end if;
  if b.driver_id is not null then raise exception 'CLASS_ALREADY_TAKEN'; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = b.organization_id;
  if ((b.block_date + b.start_time) at time zone v_tz) <= now() then raise exception 'CLASS_STARTED'; end if;
  v_conflict := public.fn_ds_instructor_conflict(b.organization_id, v_uid, b.block_date, b.start_time, b.end_time, b.id);
  if v_conflict is not null then raise exception 'SCHEDULE_CONFLICT:%', v_conflict; end if;
  update public.shift_blocks set driver_id = v_uid where id = b.id;
  return jsonb_build_object('id', b.id, 'claimed', true);
end $$;

create or replace function public.release_class(p_block uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  b public.shift_blocks;
  v_tz text;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  select * into b from public.shift_blocks where id = p_block for update;
  if b.id is null or b.driver_id is distinct from v_uid then raise exception 'NOT_YOUR_CLASS'; end if;
  if b.status <> 'scheduled' then raise exception 'CLASS_NOT_AVAILABLE'; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = b.organization_id;
  if ((b.block_date + b.start_time) at time zone v_tz) <= now() then raise exception 'CLASS_STARTED'; end if;
  update public.shift_blocks set driver_id = null where id = b.id;
  return jsonb_build_object('id', b.id, 'released', true);
end $$;

-- Releases (driver_id = null) the caller's future scheduled classes that match a time-off / unavailable rule.
create or replace function public.fn_ds_release_range(
  p_org uuid, p_date_from date, p_date_to date, p_weekday int, p_start time, p_end time, p_do_release boolean)
returns integer language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  v_tz text;
  v_today date;
  v_ids uuid[];
begin
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_org;
  v_today := (now() at time zone v_tz)::date;
  select coalesce(array_agg(b.id), '{}') into v_ids from public.shift_blocks b
   where b.organization_id = p_org and b.driver_id = v_uid and b.status = 'scheduled'
     and b.block_date >= greatest(v_today, p_date_from) and b.block_date <= p_date_to
     and (p_weekday is null or extract(dow from b.block_date)::int = p_weekday)
     and (p_start is null or (b.start_time < p_end and b.end_time > p_start))
     and ((b.block_date + b.start_time) at time zone v_tz) > now();
  if cardinality(v_ids) > 0 and p_do_release then
    update public.shift_blocks set driver_id = null where id = any(v_ids);
  end if;
  return cardinality(v_ids);
end $$;

create or replace function public.set_my_time_off(
  p_org uuid, p_from date, p_to date, p_note text default null, p_release boolean default false)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  m public.organization_members;
  v_tz text;
  v_n int;
  v_id uuid;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  m := public.fn_ds_member(p_org);
  if m.id is null or m.member_role = 'monitor' or not public.fn_org_has_classes(p_org) then raise exception 'NOT_A_MEMBER'; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_org;
  if p_from is null or p_to is null or p_to < p_from or p_to > p_from + 120
     or p_from < (now() at time zone v_tz)::date then
    raise exception 'INVALID_DATES';
  end if;
  v_n := public.fn_ds_release_range(p_org, p_from, p_to, null, null, null, false);
  if v_n > 0 and not coalesce(p_release, false) then raise exception 'HAS_CLASSES:%', v_n; end if;
  if v_n > 0 then perform public.fn_ds_release_range(p_org, p_from, p_to, null, null, null, true); end if;
  insert into public.ds_time_off (organization_id, instructor_id, date_from, date_to, note)
  values (p_org, v_uid, p_from, p_to, nullif(left(p_note, 200), '')) returning id into v_id;
  return jsonb_build_object('id', v_id, 'released', v_n);
end $$;

create or replace function public.delete_my_time_off(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from public.ds_time_off where id = p_id and instructor_id = auth.uid();
  if not found then raise exception 'NOT_FOUND'; end if;
end $$;

create or replace function public.set_my_unavailable(
  p_org uuid, p_on_date date, p_weekday integer, p_start time, p_end time,
  p_label text default null, p_release boolean default false)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  m public.organization_members;
  v_tz text;
  v_today date;
  v_n int;
  v_id uuid;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  m := public.fn_ds_member(p_org);
  if m.id is null or m.member_role = 'monitor' or not public.fn_org_has_classes(p_org) then raise exception 'NOT_A_MEMBER'; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_org;
  v_today := (now() at time zone v_tz)::date;
  if p_start is null or p_end is null or p_end <= p_start
     or ((p_on_date is null) = (p_weekday is null))
     or (p_on_date is not null and p_on_date < v_today)
     or (p_weekday is not null and (p_weekday < 0 or p_weekday > 6)) then
    raise exception 'INVALID_HOURS';
  end if;
  v_n := public.fn_ds_release_range(p_org, coalesce(p_on_date, v_today), coalesce(p_on_date, v_today + 120),
                                    p_weekday, p_start, p_end, false);
  if v_n > 0 and not coalesce(p_release, false) then raise exception 'HAS_CLASSES:%', v_n; end if;
  if v_n > 0 then
    perform public.fn_ds_release_range(p_org, coalesce(p_on_date, v_today), coalesce(p_on_date, v_today + 120),
                                       p_weekday, p_start, p_end, true);
  end if;
  insert into public.ds_blocked_hours (organization_id, instructor_id, weekday, on_date, start_time, end_time, label)
  values (p_org, v_uid, p_weekday, p_on_date, p_start, p_end, nullif(left(p_label, 60), '')) returning id into v_id;
  return jsonb_build_object('id', v_id, 'released', v_n);
end $$;

create or replace function public.delete_my_unavailable(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  delete from public.ds_blocked_hours where id = p_id and instructor_id = auth.uid();
  if not found then raise exception 'NOT_FOUND'; end if;
end $$;

-- 4. Admin bell ----------------------------------------------------------------------------------
create or replace function public.get_schedule_events(p_org uuid, p_limit integer default 50) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_last timestamptz;
begin
  if auth.uid() is null or not public.is_org_operator_or_above(p_org) then raise exception 'FORBIDDEN'; end if;
  select r.last_read_at into v_last from public.schedule_event_reads r where r.organization_id = p_org and r.user_id = auth.uid();
  return jsonb_build_object(
    'unread', (select count(*) from public.schedule_events e where e.organization_id = p_org and e.created_at > coalesce(v_last, 'epoch'::timestamptz)),
    'events', coalesce((
      select jsonb_agg(x order by x.created_at desc) from (
        select e.id, e.kind, e.created_at, e.actor_role, e.payload, e.block_id, e.branch_id,
               e.created_at > coalesce(v_last, 'epoch'::timestamptz) as is_new,
               nullif(trim(concat_ws(' ', pa.first_name, pa.last_name)), '') as actor_name,
               nullif(trim(concat_ws(' ', pi.first_name, pi.last_name)), '') as instructor_name
          from public.schedule_events e
          left join public.profiles pa on pa.id = e.actor_id
          left join public.profiles pi on pi.id = e.instructor_id
         where e.organization_id = p_org
         order by e.created_at desc limit least(greatest(coalesce(p_limit, 50), 1), 200)) x
    ), '[]'::jsonb));
end $$;

create or replace function public.mark_schedule_events_read(p_org uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or not public.is_org_operator_or_above(p_org) then raise exception 'FORBIDDEN'; end if;
  insert into public.schedule_event_reads (organization_id, user_id, last_read_at) values (p_org, auth.uid(), now())
  on conflict (organization_id, user_id) do update set last_read_at = now();
end $$;

-- 5. Portal clients can no longer cancel or edit a class ------------------------------------------
create or replace function public.fn_ds_portal_cancel_for(p_student uuid, p_block uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  raise exception 'CLASS_CANCEL_NOT_ALLOWED';
end $$;

-- 6. Live updates for the admin schedule and the bell ---------------------------------------------
do $$
declare t text;
begin
  foreach t in array array['shift_blocks', 'schedule_events', 'ds_time_off', 'ds_blocked_hours'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

-- 7. Grants: signed-in users only (new functions) ---------------------------------------------------
do $$
declare f text;
begin
  foreach f in array array[
    'get_branch_schedule(uuid,date,integer)', 'claim_class(uuid)', 'release_class(uuid)',
    'set_my_time_off(uuid,date,date,text,boolean)', 'delete_my_time_off(uuid)',
    'set_my_unavailable(uuid,date,integer,time,time,text,boolean)', 'delete_my_unavailable(uuid)',
    'get_schedule_events(uuid,integer)', 'mark_schedule_events_read(uuid)'] loop
    execute format('revoke all on function public.%s from public, anon', f);
    execute format('grant execute on function public.%s to authenticated', f);
  end loop;
  foreach f in array array[
    'fn_ds_member(uuid)', 'fn_ds_instructor_conflict(uuid,uuid,date,time,time,uuid)',
    'fn_ds_release_range(uuid,date,date,integer,time,time,boolean)', 'fn_log_shift_block_event()',
    'fn_log_time_off_event()', 'fn_log_blocked_hours_event()', 'fn_shift_block_fill_branch()'] loop
    execute format('revoke all on function public.%s from public, anon, authenticated', f);
  end loop;
end $$;
