-- Driving school agenda (2026-10-26).
--
-- The school's big calendar and the client's booking calendar read the SAME
-- availability rules, so what a client sees free is what the office sees free:
--
--   * ds_blocked_hours: hours the school marks off (lunch 12-1 PM). Whole school
--     (instructor_id null) or one instructor; every day, one weekday, or one date.
--   * fn_ds_slot_grid: every candidate slot with a status (free / busy / break /
--     past). fn_ds_free_slots is now just the 'free' rows of it, so booking, the
--     portal list and the calendar can never disagree.
--   * A car is needed as well as an instructor. An instructor with no car of their
--     own draws from the school's pool: more instructors than cars (or the reverse)
--     simply means fewer free slots.
--   * fn_ds_portal_slots_for also returns 'grid': one cell per date/time with
--     free / busy / break, with no names of who is busy.
--   * Office: conflict check shared by "add class" and "move class" (instructor,
--     car, blocked hours, time off); moving a class keeps its length.

set local lock_timeout = '5s';

insert into ops.domain_tables (tbl, domain) values ('ds_blocked_hours', 'driving_school')
on conflict (tbl) do update set domain = excluded.domain;

create table if not exists public.ds_blocked_hours (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  -- null = the whole school
  instructor_id uuid references public.profiles(id) on delete cascade,
  -- both null = every day; weekday 0-6 (Sun-Sat) = that day each week; on_date = that date only
  weekday smallint check (weekday between 0 and 6),
  on_date date,
  start_time time not null,
  end_time time not null,
  label text check (label is null or char_length(label) <= 60),
  created_at timestamptz not null default now(),
  check (end_time > start_time),
  check (weekday is null or on_date is null)
);
create index if not exists ds_blocked_hours_org_idx on public.ds_blocked_hours (organization_id);

alter table public.ds_blocked_hours enable row level security;

drop policy if exists ds_blocked_hours_select on public.ds_blocked_hours;
create policy ds_blocked_hours_select on public.ds_blocked_hours for select
  using (public.fn_org_has_feature(organization_id, 'classes')
         and exists (select 1 from public.organization_members m
                      where m.organization_id = ds_blocked_hours.organization_id and m.user_id = auth.uid() and m.is_active));

drop policy if exists ds_blocked_hours_write on public.ds_blocked_hours;
create policy ds_blocked_hours_write on public.ds_blocked_hours for all
  using (public.is_org_operator_or_above(organization_id) and public.fn_org_has_feature(organization_id, 'classes'))
  with check (public.is_org_operator_or_above(organization_id) and public.fn_org_has_feature(organization_id, 'classes')
              and (instructor_id is null or exists (select 1 from public.organization_members m
                                                     where m.organization_id = ds_blocked_hours.organization_id
                                                       and m.user_id = ds_blocked_hours.instructor_id and m.is_active)));

grant select, insert, update, delete on public.ds_blocked_hours to authenticated;

-- ── Every candidate slot with its status ────────────────────────────────────
create or replace function public.fn_ds_slot_grid(p_org uuid, p_minutes int, p_from date, p_days int, p_lead_hours int)
returns table(instructor_id uuid, vehicle_id uuid, block_date date, start_time time, end_time time,
              starts_at timestamptz, status text)
language sql stable security definer set search_path to 'public' as $$
  with org as (
    select coalesce(timezone, 'America/New_York') tz from public.organizations where id = p_org
  ),
  fleet as (
    select exists (select 1 from public.vehicles v where v.organization_id = p_org and not v.is_archived) has_cars
  ),
  days as (
    select (p_from + g)::date d from generate_series(0, greatest(p_days, 1) - 1) g
  ),
  av as (
    select a.instructor_id, a.start_time a_start, a.end_time a_end, d.d,
           coalesce(a.vehicle_id, (select v.id from public.vehicles v
                                    where v.organization_id = p_org and v.assigned_driver_id = a.instructor_id
                                      and not v.is_archived order by v.created_at limit 1)) vid
      from public.ds_availability a
      join days d on a.weekday = extract(dow from d.d)::int
     where a.organization_id = p_org
       and exists (select 1 from public.organization_members m
                    where m.organization_id = p_org and m.user_id = a.instructor_id and m.is_active)
       and not exists (select 1 from public.ds_time_off t
                        where t.organization_id = p_org and t.instructor_id = a.instructor_id
                          and d.d between t.date_from and t.date_to)
  ),
  slots as (
    select av.instructor_id, av.vid, av.d, av.a_end,
           (av.a_start + make_interval(mins => k * p_minutes))::time st,
           (av.a_start + make_interval(mins => (k + 1) * p_minutes))::time en
      from av,
           generate_series(0, greatest(0, (extract(epoch from (av.a_end - av.a_start)) / 60)::int / p_minutes - 1)) k
  ),
  cand as (
    select s.instructor_id, s.vid, s.d, s.st, s.en,
           (s.d + s.st) at time zone (select tz from org) starts_at
      from slots s
     where s.en > s.st and s.en <= s.a_end
  ),
  picked as (
    -- no car of their own: the first school car that is free at that time
    select c.*, case when c.vid is not null then c.vid else pool.id end car
      from cand c
      left join lateral (
        select v.id from public.vehicles v
         where c.vid is null and v.organization_id = p_org and not v.is_archived
           and not exists (select 1 from public.shift_blocks b
                            where b.organization_id = p_org and b.block_date = c.d and b.status <> 'cancelled'
                              and b.vehicle_id = v.id and b.start_time < c.en and b.end_time > c.st)
         order by v.created_at limit 1) pool on true
  )
  select p.instructor_id, p.car, p.d, p.st, p.en, p.starts_at,
         case
           when p.starts_at < now() then 'past'
           when exists (select 1 from public.ds_blocked_hours h
                         where h.organization_id = p_org
                           and (h.instructor_id is null or h.instructor_id = p.instructor_id)
                           and (h.weekday is null or h.weekday = extract(dow from p.d)::int)
                           and (h.on_date is null or h.on_date = p.d)
                           and h.start_time < p.en and h.end_time > p.st) then 'break'
           when p.starts_at < now() + make_interval(hours => p_lead_hours) then 'busy'
           when exists (select 1 from public.shift_blocks b
                         where b.organization_id = p_org and b.block_date = p.d and b.status <> 'cancelled'
                           and b.driver_id = p.instructor_id and b.start_time < p.en and b.end_time > p.st) then 'busy'
           when p.vid is not null and exists (select 1 from public.shift_blocks b
                         where b.organization_id = p_org and b.block_date = p.d and b.status <> 'cancelled'
                           and b.vehicle_id = p.vid and b.start_time < p.en and b.end_time > p.st) then 'busy'
           when p.vid is null and (select has_cars from fleet) and p.car is null then 'busy'
           else 'free'
         end
    from picked p
   order by p.d, p.st, p.instructor_id;
$$;
revoke execute on function public.fn_ds_slot_grid(uuid, int, date, int, int) from public, anon, authenticated;

create or replace function public.fn_ds_free_slots(p_org uuid, p_minutes int, p_from date, p_days int, p_lead_hours int)
returns table(instructor_id uuid, vehicle_id uuid, block_date date, start_time time, end_time time, starts_at timestamptz)
language sql stable security definer set search_path to 'public' as $$
  select g.instructor_id, g.vehicle_id, g.block_date, g.start_time, g.end_time, g.starts_at
    from public.fn_ds_slot_grid(p_org, p_minutes, p_from, p_days, p_lead_hours) g
   where g.status = 'free'
   order by g.block_date, g.start_time, g.instructor_id;
$$;
revoke execute on function public.fn_ds_free_slots(uuid, int, date, int, int) from public, anon, authenticated;

-- ── What the client sees: free slots plus the whole grid (no names) ─────────
create or replace function public.fn_ds_portal_slots_for(p_student uuid)
returns jsonb language plpgsql stable security definer set search_path to 'public' as $$
declare
  st public.ds_students;
  pr public.ds_programs;
  cfg public.ds_settings;
  v_tz text;
begin
  select * into st from public.ds_students where id = p_student;
  if st.id is null then return null; end if;
  if not public.fn_org_feature_internal(st.organization_id, 'student_booking') then return null; end if;
  select * into cfg from public.ds_settings where organization_id = st.organization_id;
  if not coalesce(cfg.booking_enabled, false) then return null; end if;
  select * into pr from public.ds_programs where id = st.program_id and is_active;
  if pr.id is null or st.status not in ('registered', 'active') then return null; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = st.organization_id;
  return (
    with g as (
      select s.block_date, s.start_time, s.end_time, s.status
        from public.fn_ds_slot_grid(st.organization_id, pr.class_minutes, (now() at time zone v_tz)::date,
                                    cfg.booking_horizon_days, cfg.booking_lead_hours) s
        join public.organization_members m
          on m.organization_id = st.organization_id and m.user_id = s.instructor_id
       where s.status <> 'past'
         and (st.preferred_language is null or st.preferred_language = any (m.languages))
         and (st.branch_id is null or m.any_branch or m.branch_id is null or m.branch_id = st.branch_id)
    ),
    cell as (
      select block_date, start_time, end_time,
             case when bool_or(status = 'free') then 'free'
                  when bool_and(status = 'break') then 'break'
                  else 'busy' end status
        from g group by block_date, start_time, end_time
    )
    select jsonb_build_object(
      'minutes', pr.class_minutes,
      'language', st.preferred_language,
      'slots', coalesce((select jsonb_agg(jsonb_build_object('date', block_date, 'start', start_time, 'end', end_time)
                                          order by block_date, start_time)
                           from cell where status = 'free'), '[]'::jsonb),
      'grid', coalesce((select jsonb_agg(jsonb_build_object('date', block_date, 'start', start_time, 'end', end_time, 'status', status)
                                         order by block_date, start_time)
                          from cell), '[]'::jsonb)
    )
  );
end $$;
revoke execute on function public.fn_ds_portal_slots_for(uuid) from public, anon, authenticated;

-- ── Office: one conflict rule for add and move ──────────────────────────────
create or replace function public.fn_ds_conflict(p_org uuid, p_driver uuid, p_vehicle uuid, p_date date,
                                                 p_start time, p_end time, p_exclude uuid)
returns text language plpgsql stable security definer set search_path to 'public' as $$
declare
  v_label text;
begin
  select coalesce(h.label, '') into v_label
    from public.ds_blocked_hours h
   where h.organization_id = p_org
     and (h.instructor_id is null or h.instructor_id = p_driver)
     and (h.weekday is null or h.weekday = extract(dow from p_date)::int)
     and (h.on_date is null or h.on_date = p_date)
     and h.start_time < p_end and h.end_time > p_start
   limit 1;
  if found then return 'BLOCKED:' || v_label; end if;
  if exists (select 1 from public.ds_time_off t
              where t.organization_id = p_org and t.instructor_id = p_driver and p_date between t.date_from and t.date_to) then
    return 'TIME_OFF';
  end if;
  if exists (select 1 from public.shift_blocks b
              where b.organization_id = p_org and b.block_date = p_date and b.status <> 'cancelled'
                and (p_exclude is null or b.id <> p_exclude)
                and b.driver_id = p_driver and b.start_time < p_end and b.end_time > p_start) then
    return 'INSTRUCTOR_BUSY';
  end if;
  if p_vehicle is not null and exists (select 1 from public.shift_blocks b
              where b.organization_id = p_org and b.block_date = p_date and b.status <> 'cancelled'
                and (p_exclude is null or b.id <> p_exclude)
                and b.vehicle_id = p_vehicle and b.start_time < p_end and b.end_time > p_start) then
    return 'CAR_BUSY';
  end if;
  return null;
end $$;
revoke execute on function public.fn_ds_conflict(uuid, uuid, uuid, date, time, time, uuid) from public, anon, authenticated;

create or replace function public.ds_office_add_block(p_org uuid, p_driver uuid, p_vehicle uuid, p_date date,
                                                      p_start time, p_end time, p_student uuid, p_note text)
returns uuid language plpgsql security definer set search_path to 'public' as $$
declare
  v_conflict text;
  v_id uuid;
begin
  if not public.is_org_operator_or_above(p_org) then raise exception 'FORBIDDEN'; end if;
  if not public.fn_org_has_classes(p_org) then raise exception 'FORBIDDEN'; end if;
  if p_end <= p_start then raise exception 'BAD_TIME'; end if;
  if not exists (select 1 from public.organization_members m
                  where m.organization_id = p_org and m.user_id = p_driver and m.is_active) then
    raise exception 'BAD_INSTRUCTOR';
  end if;
  if p_vehicle is not null and not exists (select 1 from public.vehicles v where v.id = p_vehicle and v.organization_id = p_org) then
    raise exception 'BAD_CAR';
  end if;
  perform pg_advisory_xact_lock(hashtext(p_org::text || p_date::text));
  v_conflict := public.fn_ds_conflict(p_org, p_driver, p_vehicle, p_date, p_start, p_end, null);
  if v_conflict is not null then raise exception '%', v_conflict; end if;
  insert into public.shift_blocks (organization_id, driver_id, vehicle_id, block_date, start_time, end_time, note,
                                   source, status, student_id, booked_via, created_by)
  values (p_org, p_driver, p_vehicle, p_date, p_start, p_end, p_note, 'one_off', 'scheduled',
          case when public.fn_org_feature_internal(p_org, 'students') then p_student end, 'office', auth.uid())
  returning id into v_id;
  return v_id;
end $$;
revoke execute on function public.ds_office_add_block(uuid, uuid, uuid, date, time, time, uuid, text) from public, anon;
grant execute on function public.ds_office_add_block(uuid, uuid, uuid, date, time, time, uuid, text) to authenticated;

-- Moves a scheduled class to another day/time (and instructor/car), keeping its
-- length. A class that comes from the weekly template would be re-created on its
-- old date, so that one is cancelled and replaced by a one-off copy.
create or replace function public.ds_office_move_block(p_block uuid, p_date date, p_start time, p_driver uuid, p_vehicle uuid)
returns uuid language plpgsql security definer set search_path to 'public' as $$
declare
  b public.shift_blocks;
  v_end time;
  v_conflict text;
  v_id uuid;
begin
  select * into b from public.shift_blocks where id = p_block;
  if b.id is null then raise exception 'NOT_FOUND'; end if;
  if not public.is_org_operator_or_above(b.organization_id) then raise exception 'FORBIDDEN'; end if;
  if b.status <> 'scheduled' then raise exception 'NOT_MOVABLE'; end if;
  if not exists (select 1 from public.organization_members m
                  where m.organization_id = b.organization_id and m.user_id = p_driver and m.is_active) then
    raise exception 'BAD_INSTRUCTOR';
  end if;
  if p_vehicle is not null and not exists (select 1 from public.vehicles v where v.id = p_vehicle and v.organization_id = b.organization_id) then
    raise exception 'BAD_CAR';
  end if;
  if (p_start + (b.end_time - b.start_time)) <= p_start then raise exception 'BAD_TIME'; end if;
  v_end := p_start + (b.end_time - b.start_time);
  perform pg_advisory_xact_lock(hashtext(b.organization_id::text || p_date::text));
  v_conflict := public.fn_ds_conflict(b.organization_id, p_driver, p_vehicle, p_date, p_start, v_end, b.id);
  if v_conflict is not null then raise exception '%', v_conflict; end if;
  if b.source = 'template' then
    insert into public.shift_blocks (organization_id, driver_id, vehicle_id, block_date, start_time, end_time, note,
                                     source, status, student_id, booked_via, created_by)
    values (b.organization_id, p_driver, p_vehicle, p_date, p_start, v_end, b.note, 'one_off', 'scheduled',
            b.student_id, 'office', auth.uid())
    returning id into v_id;
    update public.shift_blocks set status = 'cancelled' where id = b.id;
    return v_id;
  end if;
  update public.shift_blocks
     set block_date = p_date, start_time = p_start, end_time = v_end, driver_id = p_driver, vehicle_id = p_vehicle
   where id = b.id;
  return b.id;
end $$;
revoke execute on function public.ds_office_move_block(uuid, date, time, uuid, uuid) from public, anon;
grant execute on function public.ds_office_move_block(uuid, date, time, uuid, uuid) to authenticated;

-- A week (or any range) of classes for the office calendar.
create or replace function public.get_org_shift_range(p_org uuid, p_from date, p_days int)
returns setof public.shift_blocks language plpgsql security definer set search_path to 'public' as $$
declare
  d date;
begin
  if not public.is_org_operator_or_above(p_org) then
    raise exception 'Only an owner, admin or operator can see the schedule';
  end if;
  for d in select (p_from + g)::date from generate_series(0, least(greatest(p_days, 1), 31) - 1) g loop
    perform public.materialize_shift_blocks(p_org, d);
  end loop;
  return query
    select * from public.shift_blocks
     where organization_id = p_org and block_date >= p_from and block_date < p_from + least(greatest(p_days, 1), 31)
     order by block_date, start_time;
end $$;
revoke execute on function public.get_org_shift_range(uuid, date, int) from public, anon;
grant execute on function public.get_org_shift_range(uuid, date, int) to authenticated;
