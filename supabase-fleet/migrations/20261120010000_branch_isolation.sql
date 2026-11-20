-- Fleet: a school's branches are separated from each other (2026-11-20, owner request).
--
-- THE RULE. Inside one school, people only see and touch what belongs to THEIR branch. The only ones who move
-- between branches are:
--   * the owner, always;
--   * an admin or operator the owner has explicitly allowed (organization_members.any_branch = true).
-- Everyone else (drivers/instructors, and admins/operators without that permission) is fenced into their own
-- branch. A row with no branch is "unassigned": only the owner and the allowed admins see it, plus people
-- who themselves have no branch (schools without branches keep working exactly as before).
--
-- HOW. Row level security gets one extra RESTRICTIVE policy per table (it is AND-ed with the existing policies, so
-- none of them had to be rewritten). The same check is added to the functions that bypass row level security
-- (they are SECURITY DEFINER) and read or change rows by id or by school. People who are not members of the school
-- (parents/clients on the portal, the server) pass the gate untouched: the existing policies still decide for them.
--
-- Only the owner may give or take away any_branch, or change an admin's branch. A branch-limited admin can only
-- place people inside their own branch.

-- ---------------------------------------------------------------- the gates
create or replace function public.fn_my_branch(p_org uuid) returns uuid
language sql stable security definer set search_path = public as $$
  select m.branch_id from public.organization_members m
   where m.organization_id = p_org and m.user_id = auth.uid() and m.is_active limit 1
$$;

create or replace function public.fn_branch_sees_all(p_org uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select m.member_role = 'owner' or (m.member_role in ('admin', 'operator') and coalesce(m.any_branch, false))
                     from public.organization_members m
                    where m.organization_id = p_org and m.user_id = auth.uid() and m.is_active limit 1), false)
$$;

-- true when the caller may touch a row of this branch (or is not a member at all: other policies decide then)
create or replace function public.fn_branch_gate(p_org uuid, p_branch uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select m.member_role = 'owner'
                       or (m.member_role in ('admin', 'operator') and coalesce(m.any_branch, false))
                       or m.branch_id is not distinct from p_branch
                     from public.organization_members m
                    where m.organization_id = p_org and m.user_id = auth.uid() and m.is_active limit 1), true)
$$;

-- same, for "everything that member does": looks at the branch of that member
create or replace function public.fn_member_gate(p_org uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select case when p_user is null then true else
    public.fn_branch_gate(p_org, (select x.branch_id from public.organization_members x
                                   where x.organization_id = p_org and x.user_id = p_user and x.is_active limit 1))
  end
$$;

-- a trip or a fuel purchase belongs to the branch of its car, or of its driver when the car has none
create or replace function public.fn_actor_gate(p_org uuid, p_vehicle uuid, p_user uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select public.fn_branch_gate(p_org, coalesce(
    (select v.branch_id from public.vehicles v where v.id = p_vehicle),
    (select x.branch_id from public.organization_members x
      where x.organization_id = p_org and x.user_id = p_user and x.is_active limit 1)))
$$;

create or replace function public.fn_org_all_gate(p_org uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select public.fn_branch_sees_all(p_org)
                    where exists (select 1 from public.organization_members m
                                   where m.organization_id = p_org and m.user_id = auth.uid() and m.is_active)), true)
$$;

create or replace function public.fn_student_gate(p_student uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select public.fn_branch_gate(s.organization_id, s.branch_id)
                       or exists (select 1 from public.shift_blocks b where b.student_id = s.id and b.driver_id = auth.uid())
                     from public.ds_students s where s.id = p_student), true)
$$;

create or replace function public.fn_vehicle_gate(p_vehicle uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select coalesce(v.assigned_driver_id = auth.uid(), false)
                       or coalesce(v.owner_user_id = auth.uid(), false)
                       or exists (select 1 from public.sessions s where s.vehicle_id = v.id and s.user_id = auth.uid()
                                     and not coalesce(s.is_closed, false))
                       or public.fn_branch_gate(v.organization_id, v.branch_id)
                     from public.vehicles v where v.id = p_vehicle), true)
$$;

create or replace function public.fn_block_gate(p_block uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select coalesce(b.driver_id = auth.uid(), false) or public.fn_branch_gate(b.organization_id, b.branch_id)
                     from public.shift_blocks b where b.id = p_block), true)
$$;

create or replace function public.fn_session_gate(p_session uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select coalesce(s.user_id = auth.uid(), false) or public.fn_actor_gate(s.organization_id, s.vehicle_id, s.user_id)
                     from public.sessions s where s.id = p_session), true)
$$;

create or replace function public.fn_purchase_gate(p_purchase uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select coalesce(f.user_id = auth.uid(), false) or public.fn_actor_gate(f.organization_id, f.vehicle_id, f.user_id)
                     from public.fuel_purchases f where f.id = p_purchase), true)
$$;

create or replace function public.fn_package_gate(p_package uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select public.fn_student_gate(k.student_id) from public.ds_student_packages k where k.id = p_package), true)
$$;

create or replace function public.fn_enrollment_gate(p_id uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select public.fn_branch_gate(e.organization_id, e.branch_id) from public.ds_enrollment_requests e where e.id = p_id), true)
$$;

-- used inside the SECURITY DEFINER functions: stop the call when the gate says no
create or replace function public.fn_guard(p_ok boolean) returns void
language plpgsql stable set search_path = public as $$
begin
  if auth.uid() is not null and not coalesce(p_ok, false) then
    raise exception 'That belongs to another branch' using errcode = '42501';
  end if;
end $$;

-- ------------------------------------------------ nobody edits branch rights by hand
-- Only the owner may change a member's branch / "all branches" permission directly on the table. Everyone else goes
-- through set_member_branch (below), which runs as the database and applies the rules.
create or replace function public.fn_members_branch_guard() returns trigger
language plpgsql security invoker set search_path = public as $$
begin
  if current_user not in ('authenticated', 'anon') then return new; end if;
  if tg_op = 'INSERT' then
    if (coalesce(new.any_branch, false) or new.branch_id is not null) and not public.is_org_owner(new.organization_id) then
      raise exception 'Only the owner can place someone in a branch' using errcode = '42501';
    end if;
  elsif new.any_branch is distinct from old.any_branch or new.branch_id is distinct from old.branch_id then
    if not public.is_org_owner(new.organization_id) then
      raise exception 'Only the owner can change a branch or the all-branches permission' using errcode = '42501';
    end if;
  end if;
  return new;
end $$;
drop trigger if exists tr_members_branch_guard on public.organization_members;
create trigger tr_members_branch_guard before insert or update on public.organization_members
  for each row execute function public.fn_members_branch_guard();

-- a branch-limited admin/operator who creates a car or a student leaves it in their own branch
create or replace function public.fn_fill_branch_from_actor() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.branch_id is null and new.organization_id is not null and auth.uid() is not null then
    select m.branch_id into new.branch_id from public.organization_members m
     where m.organization_id = new.organization_id and m.user_id = auth.uid() and m.is_active
       and m.member_role in ('admin', 'operator') and not coalesce(m.any_branch, false) limit 1;
  end if;
  return new;
end $$;
drop trigger if exists tr_vehicles_fill_branch on public.vehicles;
create trigger tr_vehicles_fill_branch before insert on public.vehicles for each row execute function public.fn_fill_branch_from_actor();
drop trigger if exists tr_ds_students_fill_branch on public.ds_students;
create trigger tr_ds_students_fill_branch before insert on public.ds_students for each row execute function public.fn_fill_branch_from_actor();

-- ----------------------------------------------- who may put people in a branch
create or replace function public.set_member_branch(p_organization_id uuid, p_user_id uuid, p_branch_id uuid, p_any_branch boolean)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_owner boolean;
  v_any boolean := coalesce(p_any_branch, false);
  v_tgt public.organization_members;
  v_mine uuid;
begin
  if not public.is_org_admin_or_owner(p_organization_id) then raise exception 'Not authorized'; end if;
  if p_branch_id is not null and not exists (
    select 1 from public.branches where id = p_branch_id and organization_id = p_organization_id
  ) then raise exception 'That branch belongs to another fleet'; end if;

  select * into v_tgt from public.organization_members
   where organization_id = p_organization_id and user_id = p_user_id and is_active limit 1;
  if v_tgt.user_id is null then raise exception 'That person is not an active member of this school'; end if;
  if v_tgt.member_role = 'owner' then raise exception 'The owner already sees every branch'; end if;
  if v_any and v_tgt.member_role not in ('admin', 'operator') then
    raise exception 'Only an admin or operator can be allowed to move between branches';
  end if;

  v_owner := public.is_org_owner(p_organization_id);
  if not v_owner then
    if v_any then raise exception 'Only the owner can allow someone to move between branches'; end if;
    if v_tgt.member_role <> 'driver' then raise exception 'Only the owner can change the branch of an admin or operator'; end if;
    if not public.fn_branch_sees_all(p_organization_id) then
      v_mine := public.fn_my_branch(p_organization_id);
      if p_branch_id is distinct from v_mine or (v_tgt.branch_id is not null and v_tgt.branch_id is distinct from v_mine) then
        raise exception 'You can only place people inside your own branch';
      end if;
    end if;
  end if;

  update public.organization_members
     set branch_id = case when v_any then null else p_branch_id end,
         any_branch = v_any
   where organization_id = p_organization_id and user_id = p_user_id;
end $$;

-- ---------------------------------------------------- the restrictive policies
do $$
declare r record;
begin
  for r in select * from (values
    -- table, command, using expression
    ('vehicles', 'all', 'coalesce(assigned_driver_id = auth.uid(), false) or coalesce(owner_user_id = auth.uid(), false) or public.fn_branch_gate(organization_id, branch_id)'),
    ('shift_blocks', 'all', 'coalesce(driver_id = auth.uid(), false) or public.fn_branch_gate(organization_id, branch_id)'),
    ('ds_students', 'all', 'public.fn_branch_gate(organization_id, branch_id) or exists (select 1 from public.shift_blocks b where b.student_id = ds_students.id and b.driver_id = auth.uid())'),
    ('schedule_events', 'all', 'public.fn_branch_gate(organization_id, branch_id)'),
    ('ds_enrollment_requests', 'all', 'public.fn_branch_gate(organization_id, branch_id)'),
    ('ds_service_orders', 'all', 'public.fn_branch_gate(organization_id, branch_id)'),
    ('sessions', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_actor_gate(organization_id, vehicle_id, user_id)'),
    ('fuel_purchases', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_actor_gate(organization_id, vehicle_id, user_id)'),
    ('session_gps_breadcrumbs', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_actor_gate(organization_id, vehicle_id, user_id)'),
    ('organization_members', 'all', 'user_id = auth.uid() or member_role = ''owner'' or public.fn_branch_gate(organization_id, branch_id)'),
    ('branches', 'select', 'public.fn_branch_gate(organization_id, id)'),
    ('branch_moves', 'select', 'public.fn_branch_gate(organization_id, from_branch_id) or public.fn_branch_gate(organization_id, to_branch_id)'),
    ('ds_time_off', 'all', 'coalesce(instructor_id = auth.uid(), false) or public.fn_member_gate(organization_id, instructor_id)'),
    ('ds_blocked_hours', 'all', 'coalesce(instructor_id = auth.uid(), false) or public.fn_member_gate(organization_id, instructor_id)'),
    ('ds_certificates', 'all', 'student_id is null or public.fn_student_gate(student_id)'),
    ('ds_client_students', 'all', 'student_id is null or public.fn_student_gate(student_id)'),
    ('ds_evaluations', 'all', 'student_id is null or public.fn_student_gate(student_id)'),
    ('ds_portal_links', 'all', 'student_id is null or public.fn_student_gate(student_id)'),
    ('ds_student_packages', 'all', 'student_id is null or public.fn_student_gate(student_id)'),
    ('ds_student_private', 'all', 'student_id is null or public.fn_student_gate(student_id)')
  ) as t(tbl, cmd, expr) loop
    execute format('drop policy if exists %I on public.%I', r.tbl || '_branch_gate', r.tbl);
    execute format('create policy %I on public.%I as restrictive for %s to authenticated using (%s)',
                   r.tbl || '_branch_gate', r.tbl, r.cmd, r.expr);
  end loop;
end $$;

-- the admin's view of profiles stops at the branch fence too (the owner's profile stays visible to everyone)
drop policy if exists profiles_select_org_admin on public.profiles;
create policy profiles_select_org_admin on public.profiles for select to authenticated using (
  exists (select 1 from public.organization_members om
           where om.user_id = profiles.id and public.is_org_admin_or_owner(om.organization_id)
             and (om.member_role = 'owner' or public.fn_branch_gate(om.organization_id, om.branch_id)))
);

-- --------------------------- the functions that bypass row level security get the same gate
do $$
declare r record; d text;
begin
  for r in select * from (values
    ('assign_vehicle_to_driver', 'perform public.fn_guard(public.fn_vehicle_gate(p_vehicle_id));'),
    ('set_vehicle_ifta', 'perform public.fn_guard(public.fn_vehicle_gate(p_vehicle_id));'),
    ('set_vehicle_tank_capacity', 'perform public.fn_guard(public.fn_vehicle_gate(p_vehicle_id));'),
    ('submit_fuel_purchase', 'perform public.fn_guard(public.fn_vehicle_gate(p_vehicle_id));'),
    ('submit_vehicle_inspection', 'perform public.fn_guard(public.fn_vehicle_gate(p_vehicle_id));'),
    ('submit_vehicle_odometer_checkpoint', 'perform public.fn_guard(public.fn_vehicle_gate(p_vehicle_id));'),
    ('update_vehicle_location', 'perform public.fn_guard(public.fn_vehicle_gate(p_vehicle_id));'),
    ('set_vehicle_branch', 'perform public.fn_guard(public.fn_org_all_gate((select organization_id from public.vehicles where id = p_vehicle_id)));'),
    ('set_branch_manager', 'perform public.fn_guard(public.fn_org_all_gate((select organization_id from public.branches where id = p_branch_id)));'),
    ('move_to_branch', 'perform public.fn_guard(public.fn_org_all_gate(p_organization_id));'),
    ('claim_class', 'perform public.fn_guard(public.fn_block_gate(p_block));'),
    ('ds_office_move_block', 'perform public.fn_guard(public.fn_block_gate(p_block));'),
    ('start_shift_block', 'perform public.fn_guard(public.fn_block_gate(p_block_id));'),
    ('ds_submit_evaluation', 'perform public.fn_guard(public.fn_block_gate(p_block_id));'),
    ('ds_office_add_block', 'perform public.fn_guard(public.fn_vehicle_gate(p_vehicle) and public.fn_student_gate(p_student) and public.fn_member_gate(p_org, p_driver));'),
    ('ds_student_classes', 'perform public.fn_guard(public.fn_student_gate(p_student));'),
    ('ds_student_progress', 'perform public.fn_guard(public.fn_student_gate(p_student));'),
    ('ds_create_portal_link', 'perform public.fn_guard(public.fn_student_gate(p_student));'),
    ('ds_revoke_portal_link', 'perform public.fn_guard(public.fn_student_gate(p_student));'),
    ('ds_issue_certificate', 'perform public.fn_guard(public.fn_student_gate(p_student));'),
    ('ds_set_emancipation', 'perform public.fn_guard(public.fn_student_gate(p_student));'),
    ('ds_client_link', 'perform public.fn_guard(public.fn_student_gate(p_student));'),
    ('unlink_guardian_student', 'perform public.fn_guard(public.fn_student_gate(p_student_id));'),
    ('create_guardian_invite', 'perform public.fn_guard(public.fn_student_gate(x)) from unnest(coalesce(p_student_ids, ''{}''::uuid[])) as x;'),
    ('ds_record_payment', 'perform public.fn_guard(public.fn_package_gate(p_package));'),
    ('ds_enrollment_approve', 'perform public.fn_guard(public.fn_enrollment_gate(p_id));'),
    ('ds_enrollment_decline', 'perform public.fn_guard(public.fn_enrollment_gate(p_id));'),
    ('ds_enrollment_undo', 'perform public.fn_guard(public.fn_enrollment_gate(p_id));'),
    ('set_trip_approval', 'perform public.fn_guard(public.fn_session_gate(p_session_id));'),
    ('correct_fuel_purchase_ifta', 'perform public.fn_guard(public.fn_purchase_gate(p_purchase_id));'),
    ('remove_driver_from_org', 'perform public.fn_guard(public.fn_member_gate(p_org_id, p_user_id));'),
    ('set_member_admin', 'perform public.fn_guard(public.fn_member_gate(p_org_id, p_user_id));'),
    ('set_member_operator', 'perform public.fn_guard(public.fn_member_gate(p_org_id, p_user_id));')
  ) as t(fname, guard) loop
    select pg_get_functiondef(p.oid) into d from pg_proc p
     where p.pronamespace = 'public'::regnamespace and p.proname = r.fname limit 1;
    if d is null then raise exception 'function % not found', r.fname; end if;
    if d like '%fn_guard(%' then continue; end if;
    d := regexp_replace(d, '\mbegin\M', 'begin ' || r.guard, 'i');
    execute d;
  end loop;
end $$;

-- the list/report functions: filter what they return instead of stopping
do $$
declare
  r record; d text;
begin
  for r in select * from (values
    ('get_org_shift_day', 'where organization_id = p_org and block_date = p_date',
       'where organization_id = p_org and block_date = p_date and public.fn_branch_gate(p_org, branch_id)'),
    ('get_org_shift_range', 'where organization_id = p_org and block_date >= p_from and block_date < p_from + least(greatest(p_days, 1), 31)',
       'where organization_id = p_org and public.fn_branch_gate(p_org, branch_id) and block_date >= p_from and block_date < p_from + least(greatest(p_days, 1), 31)'),
    ('get_schedule_events', 'where e.organization_id = p_org',
       'where e.organization_id = p_org and public.fn_branch_gate(p_org, e.branch_id)'),
    ('get_fleet_export_data', 'where s.organization_id = p_org_id',
       'where s.organization_id = p_org_id and public.fn_actor_gate(p_org_id, s.vehicle_id, s.user_id)'),
    ('driver_safety_scores', 'and (v_admin or s.user_id = auth.uid())',
       'and (s.user_id = auth.uid() or (v_admin and public.fn_actor_gate(p_organization_id, s.vehicle_id, s.user_id)))'),
    ('driver_safety_scores', 'and (v_admin or e.user_id = auth.uid())',
       'and (e.user_id = auth.uid() or (v_admin and public.fn_member_gate(p_organization_id, e.user_id)))'),
    ('compute_idle_events', 'where b.organization_id = p_organization_id',
       'where b.organization_id = p_organization_id and public.fn_actor_gate(p_organization_id, b.vehicle_id, b.user_id)'),
    ('compute_ifta_vehicle_state_miles', 'where b.organization_id = p_organization_id',
       'where b.organization_id = p_organization_id and public.fn_actor_gate(p_organization_id, b.vehicle_id, b.user_id)'),
    ('compute_state_mileage', 'where b.organization_id = p_organization_id',
       'where b.organization_id = p_organization_id and public.fn_actor_gate(p_organization_id, b.vehicle_id, b.user_id)'),
    ('get_branch_schedule', '(m.any_branch or m.branch_id is null or b.branch_id is null or b.branch_id = m.branch_id)',
       'public.fn_branch_gate(p_org, b.branch_id)'),
    ('get_branch_schedule', '(m.any_branch or m.branch_id is null or x.branch_id is null or x.branch_id = m.branch_id)',
       'public.fn_branch_gate(p_org, x.branch_id)'),
    ('get_branch_schedule', 'where h.organization_id = p_org',
       'where h.organization_id = p_org and public.fn_member_gate(p_org, h.instructor_id)')
  ) as t(fname, old, new) loop
    select pg_get_functiondef(p.oid) into d from pg_proc p
     where p.pronamespace = 'public'::regnamespace and p.proname = r.fname limit 1;
    if d is null then raise exception 'function % not found', r.fname; end if;
    if position(r.new in d) > 0 then continue; end if;
    if position(r.old in d) = 0 then raise exception 'anchor not found in %: %', r.fname, r.old; end if;
    execute replace(d, r.old, r.new);
  end loop;
end $$;

-- ------------------------------------------------------------------ grants
-- the new functions are closed to visitors; signed-in people keep the gates (the policies call them), but the guard
-- and the two trigger functions are for the database only
do $$
declare r record;
begin
  for r in select p.oid::regprocedure as sig, p.proname from pg_proc p
            where p.pronamespace = 'public'::regnamespace
              and (p.proname like 'fn\_%gate' or p.proname in ('fn_guard', 'fn_my_branch', 'fn_branch_sees_all',
                   'fn_members_branch_guard', 'fn_fill_branch_from_actor')) loop
    execute format('revoke execute on function %s from public, anon', r.sig);
    if r.proname in ('fn_guard', 'fn_members_branch_guard', 'fn_fill_branch_from_actor') then
      execute format('revoke execute on function %s from authenticated', r.sig);
    end if;
  end loop;
end $$;
