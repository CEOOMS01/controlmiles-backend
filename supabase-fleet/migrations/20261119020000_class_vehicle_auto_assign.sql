-- Driving school: the car belongs to the CLASS, not to the instructor (2026-11-19, owner request). Fleet project only.
--
-- * Every class (scheduled, no car yet) gets a free car automatically: an active car of the school that is not
--   used by another class at the same time. Earliest class first.
-- * No car free -> the class waits ("waiting for a car") and takes the first car that frees up (a class cancelled,
--   moved or deleted, or a car added / put back in service).
-- * An admin can still pick a car by hand; the automatic step only fills classes that have none.
-- * Students get a pickup address; the instructor sees it (and the phone) on their own classes and can navigate.
-- * The instructor's "next class" (with its car, student and address) comes from my_next_class().

-- 1. Student address -----------------------------------------------------------------------------
alter table public.ds_students add column if not exists address_line text;
alter table public.ds_students add column if not exists city text;
alter table public.ds_students add column if not exists state text;
alter table public.ds_students add column if not exists postal_code text;

create or replace function public.fn_ds_student_address(st public.ds_students) returns text
language sql immutable as $$
  select nullif(trim(both ', ' from concat_ws(', ',
    nullif(trim(st.address_line), ''),
    nullif(trim(st.city), ''),
    nullif(trim(concat_ws(' ', nullif(trim(st.state), ''), nullif(trim(st.postal_code), ''))), ''))), '');
$$;

-- 2. Automatic car for a class ---------------------------------------------------------------------
create or replace function public.fn_ds_vehicle_free(
  p_org uuid, p_vehicle uuid, p_date date, p_start time, p_end time, p_except uuid default null)
returns boolean language sql stable security definer set search_path = public as $$
  select not exists (
    select 1 from public.shift_blocks x
     where x.organization_id = p_org and x.vehicle_id = p_vehicle and x.block_date = p_date
       and x.status <> 'cancelled' and x.id is distinct from p_except
       and x.start_time < p_end and x.end_time > p_start);
$$;

create or replace function public.fn_ds_assign_vehicles(p_org uuid) returns integer
language plpgsql security definer set search_path = public as $$
declare
  r record;
  v_car uuid;
  v_tz text;
  v_now timestamp;
  n int := 0;
begin
  if current_setting('cm.vehicle_autoassign', true) is not distinct from 'on' then return 0; end if;
  select coalesce(o.timezone, 'America/New_York') into v_tz from public.organizations o where o.id = p_org;
  if v_tz is null then return 0; end if;
  v_now := now() at time zone v_tz;
  perform set_config('cm.vehicle_autoassign', 'on', true);

  for r in
    select b.id, b.block_date, b.start_time, b.end_time, b.branch_id
      from public.shift_blocks b
     where b.organization_id = p_org and b.status = 'scheduled' and b.vehicle_id is null
       and (b.block_date + b.end_time) > v_now
     order by b.block_date, b.start_time, b.created_at
  loop
    select c.id into v_car
      from public.vehicles c
     where c.organization_id = p_org and c.is_active and not coalesce(c.is_archived, false)
       and coalesce(c.service, 'driving_school') = 'driving_school'
       and (r.branch_id is null or c.branch_id is null or c.branch_id = r.branch_id)
       and public.fn_ds_vehicle_free(p_org, c.id, r.block_date, r.start_time, r.end_time, r.id)
     order by (select count(*) from public.shift_blocks x
                where x.vehicle_id = c.id and x.block_date = r.block_date and x.status <> 'cancelled'),
              c.display_id
     limit 1;
    if v_car is not null then
      update public.shift_blocks set vehicle_id = v_car where id = r.id;
      n := n + 1;
    end if;
  end loop;

  perform set_config('cm.vehicle_autoassign', 'off', true);
  return n;
end $$;
revoke all on function public.fn_ds_assign_vehicles(uuid) from public, anon, authenticated;
revoke all on function public.fn_ds_vehicle_free(uuid, uuid, date, time, time, uuid) from public, anon, authenticated;

create or replace function public.fn_ds_autoassign_blocks_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform public.fn_ds_assign_vehicles(coalesce(new.organization_id, old.organization_id));
  return null;
end $$;

drop trigger if exists tr_shift_blocks_autoassign_ins on public.shift_blocks;
create trigger tr_shift_blocks_autoassign_ins after insert on public.shift_blocks
  for each row when (new.vehicle_id is null and new.status = 'scheduled')
  execute function public.fn_ds_autoassign_blocks_trg();
drop trigger if exists tr_shift_blocks_autoassign_upd on public.shift_blocks;
create trigger tr_shift_blocks_autoassign_upd after update of vehicle_id, status, block_date, start_time, end_time, branch_id
  on public.shift_blocks for each row execute function public.fn_ds_autoassign_blocks_trg();
drop trigger if exists tr_shift_blocks_autoassign_del on public.shift_blocks;
create trigger tr_shift_blocks_autoassign_del after delete on public.shift_blocks
  for each row execute function public.fn_ds_autoassign_blocks_trg();

create or replace function public.fn_ds_autoassign_vehicles_trg() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  perform public.fn_ds_assign_vehicles(new.organization_id);
  return null;
end $$;
drop trigger if exists tr_vehicles_autoassign on public.vehicles;
create trigger tr_vehicles_autoassign after insert or update of is_active, is_archived, branch_id, service
  on public.vehicles for each row when (new.organization_id is not null and new.is_active)
  execute function public.fn_ds_autoassign_vehicles_trg();

-- A car picked automatically is not a schedule change worth a bell for the admin.
do $$
declare d text; nd text;
begin
  d := pg_get_functiondef('public.fn_log_shift_block_event()'::regprocedure);
  nd := replace(d, E'begin\n  if current_setting(''cm.account_deletion''',
    E'begin\n  if current_setting(''cm.vehicle_autoassign'', true) is not distinct from ''on'' then\n    return coalesce(new, old);\n  end if;\n  if current_setting(''cm.account_deletion''');
  if nd = d then raise exception 'fn_log_shift_block_event: marker not found'; end if;
  execute nd;
end $$;

-- 3. The schedule carries the car id, and the student's address and phone for the instructor ---------
do $$
declare d text; nd text;
begin
  d := pg_get_functiondef('public.get_branch_schedule(uuid,date,integer)'::regprocedure);
  nd := replace(d, '''has_student'', b.student_id is not null,',
    '''has_student'', b.student_id is not null, ''vehicle_id'', b.vehicle_id, '
    || '''student_address'', case when b.driver_id = v_uid or v_is_op then public.fn_ds_student_address(st) end, '
    || '''student_phone'', case when b.driver_id = v_uid or v_is_op then nullif(trim(st.phone), '''') end,');
  if nd = d then raise exception 'get_branch_schedule: marker not found'; end if;
  execute nd;
end $$;

-- 4. The instructor's current or next class (home screen: car, student, address) ---------------------
create or replace function public.my_next_class(p_org uuid)
returns table (block_id uuid, block_date date, start_time time, end_time time, status text,
               vehicle_id uuid, vehicle_label text, vehicle_display_id text,
               student_name text, student_phone text, student_address text, note text)
language plpgsql stable security definer set search_path = public as $$
declare
  v_uid uuid := auth.uid();
  v_tz text;
  v_now timestamp;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  if public.fn_ds_member(p_org) is null or not public.fn_org_has_classes(p_org) then return; end if;
  select coalesce(o.timezone, 'America/New_York') into v_tz from public.organizations o where o.id = p_org;
  v_now := now() at time zone v_tz;
  return query
  select b.id, b.block_date, b.start_time, b.end_time, b.status, b.vehicle_id,
         nullif(concat_ws(' ', v.make, v.model), ''), v.display_id,
         nullif(trim(concat_ws(' ', st.first_name, st.last_name)), ''),
         nullif(trim(st.phone), ''), public.fn_ds_student_address(st), b.note
    from public.shift_blocks b
    left join public.vehicles v on v.id = b.vehicle_id
    left join public.ds_students st on st.id = b.student_id
   where b.organization_id = p_org and b.driver_id = v_uid
     and b.status in ('scheduled', 'in_progress') and (b.block_date + b.end_time) > v_now
   order by (b.status = 'in_progress') desc, b.block_date, b.start_time
   limit 1;
end $$;
revoke all on function public.my_next_class(uuid) from public, anon;
grant execute on function public.my_next_class(uuid) to authenticated;

-- Fill classes that already exist without a car.
do $$
declare o record;
begin
  for o in select distinct organization_id from public.shift_blocks where status = 'scheduled' and vehicle_id is null loop
    perform public.fn_ds_assign_vehicles(o.organization_id);
  end loop;
end $$;
