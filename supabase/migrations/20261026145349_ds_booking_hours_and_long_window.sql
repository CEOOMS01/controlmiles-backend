-- Online booking limits chosen by the school (2026-10-26):
--   * booking_open_time / booking_close_time: the school's working hours; no lesson
--     can be booked (online) outside them. Both null = no limit beyond each
--     instructor's own availability.
--   * booking_horizon_days now up to 365 (a student can book months ahead, e.g.
--     in January, when the school allows it).
alter table public.ds_settings
  add column if not exists booking_open_time time,
  add column if not exists booking_close_time time;

alter table public.ds_settings drop constraint if exists ds_settings_booking_hours_check;
alter table public.ds_settings add constraint ds_settings_booking_hours_check
  check ((booking_open_time is null and booking_close_time is null)
         or (booking_open_time is not null and booking_close_time is not null and booking_close_time > booking_open_time));

alter table public.ds_settings drop constraint if exists ds_settings_booking_horizon_days_check;
alter table public.ds_settings add constraint ds_settings_booking_horizon_days_check
  check (booking_horizon_days >= 1 and booking_horizon_days <= 365);

create or replace function public.fn_ds_slot_grid(p_org uuid, p_minutes int, p_from date, p_days int, p_lead_hours int)
returns table(instructor_id uuid, vehicle_id uuid, block_date date, start_time time, end_time time,
              starts_at timestamptz, status text)
language sql stable security definer set search_path to 'public' as $$
  with org as (
    select coalesce(timezone, 'America/New_York') tz from public.organizations where id = p_org
  ),
  cfg as (
    select s.booking_open_time o, s.booking_close_time c from public.ds_settings s where s.organization_id = p_org
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
           when (select o from cfg) is not null and (p.st < (select o from cfg) or p.en > (select c from cfg)) then 'break'
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
