-- Driving school: the office can add or move a class WITHOUT an instructor (an "open" class that any
-- instructor of that location can take from the app). Fleet project only.
-- Same bodies as before, except that p_driver may now be null. fn_ds_conflict already copes with a null
-- instructor (it then checks only the school's blocked hours and the car).

create or replace function public.ds_office_add_block(
  p_org uuid, p_driver uuid, p_vehicle uuid, p_date date, p_start time, p_end time, p_student uuid, p_note text)
returns uuid language plpgsql security definer set search_path to 'public' as $function$
declare
  v_conflict text;
  v_id uuid;
begin
  if not public.is_org_operator_or_above(p_org) then raise exception 'FORBIDDEN'; end if;
  if not public.fn_org_has_classes(p_org) then raise exception 'FORBIDDEN'; end if;
  if p_end <= p_start then raise exception 'BAD_TIME'; end if;
  if p_driver is not null and not exists (select 1 from public.organization_members m
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
end $function$;

create or replace function public.ds_office_move_block(
  p_block uuid, p_date date, p_start time, p_driver uuid, p_vehicle uuid)
returns uuid language plpgsql security definer set search_path to 'public' as $function$
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
  if p_driver is not null and not exists (select 1 from public.organization_members m
                  where m.organization_id = b.organization_id and m.user_id = p_driver and m.is_active) then
    raise exception 'BAD_INSTRUCTOR';
  end if;
  if p_vehicle is not null and not exists (select 1 from public.vehicles v where v.id = p_vehicle and v.organization_id = b.organization_id) then
    raise exception 'BAD_CAR';
  end if;
  v_end := p_start + (b.end_time - b.start_time);
  if v_end <= p_start then raise exception 'BAD_TIME'; end if;
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
end $function$;

-- An open class created from the office belongs to the creator's location when it has no car or instructor.
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
    if new.branch_id is null and auth.uid() is not null then
      select m.branch_id into new.branch_id from public.organization_members m
       where m.organization_id = new.organization_id and m.user_id = auth.uid() and m.is_active
         and not m.any_branch limit 1;
    end if;
  end if;
  return new;
end $$;
