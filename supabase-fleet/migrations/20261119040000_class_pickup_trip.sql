-- Driving school: the trip to pick up the student (2026-11-19, owner request). Fleet project only.
--
-- Tracking only opened a few minutes before a class (organizations.shift_start_window_minutes), so the drive to the
-- student's home was never recorded. Now, when the student has a pickup address, the instructor can start a PICKUP
-- trip from `pickup_lead_minutes` before the class (default 60). It is a normal business trip tied to the class
-- (sessions.pickup_block_id); on arrival the class starts with its own trip as before. No address = the student comes
-- to the school, so there is no pickup trip.

alter table public.organizations
  add column if not exists pickup_lead_minutes integer not null default 60;
alter table public.organizations drop constraint if exists organizations_pickup_lead_check;
alter table public.organizations
  add constraint organizations_pickup_lead_check check (pickup_lead_minutes >= 0 and pickup_lead_minutes <= 180);

alter table public.sessions
  add column if not exists pickup_block_id uuid references public.shift_blocks(id) on delete set null;
create index if not exists sessions_pickup_block_idx on public.sessions (pickup_block_id) where pickup_block_id is not null;

-- A pickup trip is only valid for the instructor's own scheduled class, with an address, inside the lead window.
create or replace function public.fn_check_pickup_session() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  b public.shift_blocks;
  o record;
  v_start timestamptz;
begin
  select * into b from public.shift_blocks where id = new.pickup_block_id;
  if b.id is null or b.driver_id is distinct from new.user_id or b.status <> 'scheduled' or new.shift_block_id is not null then
    raise exception 'PICKUP_NOT_ALLOWED';
  end if;
  select coalesce(timezone, 'America/New_York') tz, pickup_lead_minutes lead, shift_start_window_minutes win
    into o from public.organizations where id = b.organization_id;
  if o.lead <= 0 then raise exception 'PICKUP_NOT_ALLOWED'; end if;
  if not exists (select 1 from public.ds_students s where s.id = b.student_id and public.fn_ds_student_address(s) is not null) then
    raise exception 'PICKUP_NO_ADDRESS';
  end if;
  v_start := (b.block_date + b.start_time) at time zone o.tz;
  if now() < v_start - make_interval(mins => o.lead) or now() > v_start + make_interval(mins => o.win) then
    raise exception 'PICKUP_NOT_ALLOWED';
  end if;
  return new;
end $$;
drop trigger if exists tr_sessions_check_pickup on public.sessions;
create trigger tr_sessions_check_pickup before insert on public.sessions
  for each row when (new.pickup_block_id is not null) execute function public.fn_check_pickup_session();

-- my_next_class also says when the pickup trip opens (null: no address, a class already running, or switched off).
drop function if exists public.my_next_class(uuid);
create or replace function public.my_next_class(p_org uuid)
returns table (block_id uuid, block_date date, start_time time, end_time time, status text,
               vehicle_id uuid, vehicle_label text, vehicle_display_id text,
               student_name text, student_phone text, student_address text, note text,
               pickup_opens_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  v_tz text;
  v_lead int;
  v_now timestamp;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  if public.fn_ds_member(p_org) is null or not public.fn_org_has_classes(p_org) then return; end if;
  select coalesce(o.timezone, 'America/New_York'), o.pickup_lead_minutes into v_tz, v_lead
    from public.organizations o where o.id = p_org;
  v_now := now() at time zone v_tz;
  return query
  select b.id, b.block_date, b.start_time, b.end_time, b.status, b.vehicle_id,
         nullif(concat_ws(' ', v.make, v.model), ''), v.display_id,
         nullif(trim(concat_ws(' ', st.first_name, st.last_name)), ''),
         nullif(trim(st.phone), ''), public.fn_ds_student_address(st), b.note,
         case when b.status = 'scheduled' and v_lead > 0 and public.fn_ds_student_address(st) is not null
              then ((b.block_date + b.start_time) at time zone v_tz) - make_interval(mins => v_lead) end
    from public.shift_blocks b
    left join public.vehicles v on v.id = b.vehicle_id
    left join public.ds_students st on st.id = b.student_id
   where b.organization_id = p_org and b.driver_id = v_uid
     and b.status in ('scheduled', 'in_progress') and (b.block_date + b.end_time) > v_now
   order by (b.status = 'in_progress') desc, b.block_date, b.start_time
   limit 2;
end $$;
revoke all on function public.my_next_class(uuid) from public, anon;
grant execute on function public.my_next_class(uuid) to authenticated;
