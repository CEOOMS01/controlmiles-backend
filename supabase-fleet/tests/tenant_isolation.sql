-- Fleet: one school must never read or write another school (tenant isolation check).
--
-- HOW TO RUN: paste it into the Fleet project's SQL editor (or execute_sql) after every migration that adds a
-- table or a function. It NEVER changes anything: it always ends with an error whose text is the report, which
-- rolls back everything it tried. Needs at least two schools, one of them with data and a member who is not in it.
--
-- WHAT IT DOES. It finds the school with the most classes (the TARGET) and a member of ANOTHER school (the
-- ATTACKER), then as that attacker, once as a plain driver and once as the owner of their own school:
--   1. tries to read, update, delete and insert rows of the target in EVERY table that has organization_id;
--   2. calls the sensitive functions with the target's ids;
--   3. calls the server-only and helper functions that nobody but the database should run.
-- Then as a legitimate member of the target it checks the normal reads still work, and as an anonymous visitor
-- that nothing but the public pages answers.
-- A healthy report says "blocked" on every line of the attacker sections, no "LEAK" and no "ALLOWED".

do $$
declare
  orgB uuid; orgA uuid; atk uuid; stu uuid; veh uuid; oblk uuid; tblk uuid; bmem uuid; bdrv uuid; pkg uuid; ses uuid;
  persona text; t record; n bigint; rc bigint; out text := ''; q text; stmts text[];
begin
  select organization_id into orgB from public.shift_blocks group by organization_id order by count(*) desc limit 1;
  select m.user_id, m.organization_id into atk, orgA from public.organization_members m
   where m.is_active and m.organization_id <> orgB
     and not exists (select 1 from public.organization_members x where x.user_id = m.user_id and x.organization_id = orgB and x.is_active)
   limit 1;
  if orgB is null or atk is null then raise exception 'Need a school with data and a member of another school that is not in it'; end if;
  select id into stu from public.ds_students where organization_id = orgB limit 1;
  select id into veh from public.vehicles where organization_id = orgB limit 1;
  select id into oblk from public.shift_blocks where organization_id = orgB and driver_id is null limit 1;
  select id into tblk from public.shift_blocks where organization_id = orgB and driver_id is not null limit 1;
  select user_id into bmem from public.organization_members where organization_id = orgB and member_role = 'owner' and is_active limit 1;
  select user_id into bdrv from public.organization_members where organization_id = orgB and member_role = 'driver' and is_active limit 1;
  select id into pkg from public.ds_student_packages where organization_id = orgB limit 1;
  select id into ses from public.sessions where organization_id = orgB limit 1;

  foreach persona in array array['driver', 'owner'] loop
    reset role;
    update public.organization_members set member_role = persona where user_id = atk and organization_id = orgA;
    perform set_config('request.jwt.claims', json_build_object('sub', atk, 'role', 'authenticated')::text, true);
    set local role authenticated;
    out := out || E'\n== ATTACKER (' || persona || ' of another school) ==';
    for t in select c.table_name from information_schema.columns c
               join information_schema.tables tt on tt.table_schema = c.table_schema and tt.table_name = c.table_name and tt.table_type = 'BASE TABLE'
              where c.table_schema = 'public' and c.column_name = 'organization_id' order by 1 loop
      begin execute format('select count(*) from public.%I where organization_id = $1', t.table_name) into n using orgB;
        if n > 0 then out := out || format(E'\nREAD LEAK %s: %s', t.table_name, n); end if;
      exception when others then null; end;
      begin execute format('update public.%I set organization_id = organization_id where organization_id = $1', t.table_name) using orgB;
        get diagnostics rc = row_count;
        if rc > 0 then out := out || format(E'\nUPDATE LEAK %s: %s', t.table_name, rc); end if;
      exception when others then null; end;
      begin execute format('delete from public.%I where organization_id = $1', t.table_name) using orgB;
        get diagnostics rc = row_count;
        if rc > 0 then out := out || format(E'\nDELETE LEAK %s: %s', t.table_name, rc); end if;
      exception when others then null; end;
      begin execute format('insert into public.%I (organization_id) values ($1)', t.table_name) using orgB;
        out := out || format(E'\nINSERT ALLOWED %s', t.table_name);
      exception when others then null; end;
    end loop;
    stmts := array[
      format('select public.get_org_shift_day(%L, current_date)', orgB),
      format('select public.get_fleet_export_data(%L, current_date-30, current_date)', orgB),
      format('select public.driver_safety_scores(%L, current_date-30, current_date, ''day'')', orgB),
      format('select public.ds_student_classes(%L)', stu),
      format('select public.ds_student_progress(%L, %L)', orgB, stu),
      format('select public.ds_create_portal_link(%L)', stu),
      format('select public.ds_record_payment(%L, 100)', pkg),
      format('select public.ds_office_add_block(%L, null, null, current_date+3, ''10:00'', ''11:00'', null, null)', orgB),
      format('select public.claim_class(%L)', oblk),
      format('select public.start_shift_block(%L)', tblk),
      format('select public.create_driver_invite(%L, ''x@example.com'', ''a'', ''b'', ''driver'')', orgB),
      format('select public.set_member_admin(%L, %L, true)', orgB, bmem),
      format('select public.remove_driver_from_org(%L, %L)', orgB, bdrv),
      format('select public.assign_vehicle_to_driver(%L, %L)', veh, atk),
      format('select public.set_vehicle_ifta(%L, true, ''diesel'')', veh),
      format('select public.update_vehicle_location(%L, 0, 0, 0)', veh),
      format('select public.submit_vehicle_inspection(%L, ''pre_trip'', ''[]''::jsonb, 1)', veh),
      format('select public.set_trip_approval(%L, ''approved'', ''x'')', ses),
      format('select public.delete_organization(%L)', orgB),
      format('select public.set_fleet_type(%L, ''general'')', orgB),
      format('select public.switch_default_organization(%L)', orgB),
      format('select public.ds_set_custom_domain(%L, ''evil.example.com'')', orgB),
      -- server-only and helper functions: nobody but the database and the service role may run them
      format('select public.support_change_fleet_type(%L, ''general'', ''x'')', orgB),
      format('select public.close_abandoned_trips(interval ''1 second'')'),
      format('select public.fn_send_safety_summaries()'),
      format('select public.ds_due_class_reminders()'),
      format('select public.guardian_login_user(%L)', 'CM-X'),
      format('select public.fn_ds_portal_payload(%L)', stu),
      format('select public.fn_ds_student_snapshot(%L)', stu),
      format('select public.fn_ds_balance(%L)', stu),
      format('select public.fn_ds_free_slots(%L, 60, current_date, 3, 0)', orgB),
      format('select public.fn_ds_assign_vehicles(%L)', orgB),
      format('select public.fn_ds_provider_secrets(%L, ''x'')', orgB)
    ];
    foreach q in array stmts loop
      begin
        execute q;
        out := out || E'\n  ALLOWED  ' || left(q, 80);
      exception when others then
        out := out || E'\n  blocked  ' || rpad(left(q, 58), 58) || ' -> ' || left(sqlerrm, 48);
      end;
    end loop;
  end loop;

  reset role;
  perform set_config('request.jwt.claims', json_build_object('sub', bmem, 'role', 'authenticated')::text, true);
  set local role authenticated;
  out := out || E'\n== LEGITIMATE owner of the target school ==';
  begin select count(*) into n from public.shift_blocks where organization_id = orgB; out := out || format(E'\n  ok reads shift_blocks: %s', n); exception when others then out := out || E'\n  FAIL shift_blocks: ' || sqlerrm; end;
  begin select count(*) into n from public.vehicles where organization_id = orgB; out := out || format(E'\n  ok reads vehicles: %s', n); exception when others then out := out || E'\n  FAIL vehicles: ' || sqlerrm; end;
  begin perform public.get_org_shift_day(orgB, current_date); out := out || E'\n  ok get_org_shift_day'; exception when others then out := out || E'\n  FAIL get_org_shift_day: ' || sqlerrm; end;

  reset role;
  perform set_config('request.jwt.claims', '{"role":"anon"}', true);
  set local role anon;
  out := out || E'\n== ANONYMOUS visitor ==';
  begin perform public.get_branch_schedule(orgB); out := out || E'\n  ALLOWED get_branch_schedule'; exception when others then out := out || E'\n  blocked get_branch_schedule'; end;
  begin select count(*) into n from public.shift_blocks; out := out || format(E'\n  rows of shift_blocks an anonymous visitor sees: %s (must be 0)', n); exception when others then out := out || E'\n  blocked table read'; end;

  raise exception E'ISOLATION REPORT%', out;
end $$;
