-- Fleet: branches inside one school must not see each other (branch isolation check).
--
-- HOW TO RUN: paste into the Fleet project's SQL editor (or execute_sql) after every migration that adds a table
-- or a function. It NEVER keeps anything: it builds two branches inside the school with the most classes, moves a
-- member and some rows around, checks who sees what, and always ends with an error whose text is the report (which
-- rolls everything back). Needs a school with at least one owner, one driver, one vehicle, one class and one student.
--
-- The rule being tested: a driver, or an admin/operator WITHOUT the "all branches" permission, sees only their own
-- branch; the owner and an admin WITH the permission see every branch; nobody but the owner can hand out or change
-- that permission.

do $$
declare
  org uuid; own uuid; drv uuid; bA uuid := gen_random_uuid(); bB uuid := gen_random_uuid();
  vA uuid; vB uuid; oblkB uuid; stuB uuid; persona text; step text; n bigint; out text := '';
begin
  select organization_id into org from public.shift_blocks group by organization_id order by count(*) desc limit 1;
  select user_id into own from public.organization_members where organization_id = org and member_role = 'owner' and is_active limit 1;
  select user_id into drv from public.organization_members where organization_id = org and member_role = 'driver' and is_active limit 1;
  if org is null or own is null or drv is null then raise exception 'Need a school with an owner and a driver'; end if;

  insert into public.branches (id, organization_id, name) values (bA, org, 'TEST A'), (bB, org, 'TEST B');
  select id into vA from public.vehicles where organization_id = org order by id limit 1;
  select id into vB from public.vehicles where organization_id = org and id <> vA order by id limit 1;
  update public.vehicles set branch_id = bA where id = vA;
  update public.vehicles set branch_id = bB where id = vB;
  select id into stuB from public.ds_students where organization_id = org order by id limit 1;
  update public.ds_students set branch_id = bB where id = stuB;
  -- the one exception: an instructor keeps a student they teach in the next days; take that away for the test
  update public.shift_blocks set student_id = null where student_id = stuB and status = 'scheduled' and block_date >= current_date - 2;
  select id into oblkB from public.shift_blocks where organization_id = org and driver_id is null and status = 'scheduled' limit 1;
  update public.shift_blocks set branch_id = bB where organization_id = org and status = 'scheduled' and block_date >= current_date and driver_id is distinct from drv;
  update public.shift_blocks set branch_id = bA where organization_id = org and status = 'scheduled' and block_date >= current_date and driver_id = drv;

  foreach persona in array array['driver', 'admin', 'admin + all branches', 'owner'] loop
    reset role;
    if persona = 'owner' then
      perform set_config('request.jwt.claims', json_build_object('sub', own, 'role', 'authenticated')::text, true);
    else
      update public.organization_members
         set member_role = case when persona = 'driver' then 'driver' else 'admin' end,
             branch_id = case when persona = 'admin + all branches' then null else bA end,
             any_branch = (persona = 'admin + all branches')
       where organization_id = org and user_id = drv;
      perform set_config('request.jwt.claims', json_build_object('sub', drv, 'role', 'authenticated')::text, true);
    end if;
    set local role authenticated;
    out := out || E'\n== ' || upper(persona) || E' (branch A) ==';

    select count(*) into n from public.vehicles where id = vB;          out := out || format(E'\n  car of branch B visible: %s', n);
    select count(*) into n from public.vehicles where id = vA;          out := out || format(E'\n  car of branch A visible: %s', n);
    select count(*) into n from public.shift_blocks where branch_id = bB; out := out || format(E'\n  classes of branch B visible: %s', n);
    select count(*) into n from public.shift_blocks where branch_id = bA; out := out || format(E'\n  classes of branch A visible: %s', n);
    select count(*) into n from public.ds_students where id = stuB;     out := out || format(E'\n  student of branch B visible: %s', n);
    select count(*) into n from public.branches where id = bB;          out := out || format(E'\n  branch B listed: %s', n);
    select count(*) into n from public.schedule_events where branch_id = bB; out := out || format(E'\n  alerts of branch B visible: %s', n);

    foreach step in array array[
      format('select public.claim_class(%L)', oblkB),
      format('select public.ds_student_classes(%L)', stuB),
      format('select public.ds_create_portal_link(%L)', stuB),
      format('select public.set_vehicle_ifta(%L, true, ''diesel'')', vB),
      format('select public.assign_vehicle_to_driver(%L, %L)', vB, drv),
      format('select public.set_vehicle_branch(%L, %L)', vA, bB),
      format('select public.move_to_branch(%L, ''vehicle'', %L, %L, false, ''moving the car for a test of the branch rules'')', org, vA, bB),
      format('select public.set_member_branch(%L, %L, %L, true)', org, drv, bB),
      format('select public.set_member_branch(%L, %L, %L, false)', org, drv, bB),
      format('update public.organization_members set any_branch = true where organization_id = %L and user_id = %L', org, drv),
      format('update public.organization_members set branch_id = %L where organization_id = %L and user_id = %L', bB, org, drv),
      format('select count(*) from public.get_org_shift_day(%L, current_date) where branch_id = %L', org, bB),
      format('select count(*) from public.get_org_shift_range(%L, current_date, 31) where branch_id = %L', org, bB)
    ] loop
      begin
        if step like 'select count(*)%' then
          execute step into n;
          out := out || format(E'\n  rows of branch B returned: %s  (%s)', n, left(step, 50));
        elsif step like 'update %' then
          execute step; get diagnostics n = row_count;
          out := out || format(E'\n  %s (%s rows changed) %s', case when n = 0 then 'blocked' else 'ALLOWED' end, n, left(step, 70));
        else
          execute step;
          out := out || E'\n  ALLOWED  ' || left(step, 100);
        end if;
      exception when others then
        out := out || E'\n  blocked  ' || rpad(left(step, 62), 62) || ' -> ' || left(sqlerrm, 44);
      end;
    end loop;
  end loop;

  raise exception E'BRANCH REPORT%', out;
end $$;
