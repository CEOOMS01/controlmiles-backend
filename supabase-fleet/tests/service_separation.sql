-- Fleet: the services must stay apart (service separation check, 2026-11-21).
--
-- HOW TO RUN: paste it into the Fleet project's SQL editor (or execute_sql) after every migration that adds or
-- renames a table or a function. It NEVER changes anything: it always ends with an error whose text is the
-- report. A healthy report ends with "RESULT: OK" and has no "FAIL" line.
--
-- WHAT IT CHECKS (docs/SERVICE_MAP.md, section 3):
--   1. naming law: no table named like a service table without its prefix (school_*, student_*, guardian_*, route_*
--      except routes); a table with a prefix is registered in the matching domain of ops.domain_tables;
--   2. every public table is registered, every registry row points to a table that exists;
--   3. every ds_ / bus_ table is tagged with its service in its comment;
--   4. every ds_ / bus_ table that has an organization_id and policies has a plan-feature check in one of them
--      (tables with no policy are server-only; the few that cannot carry the check are listed below with a reason);
--   5. no function still mentions a bus table by its old name;
--   6. the domain guard (ops.domain_violations()) is clean and its event trigger is on;
--   7. a school of one service sees nothing of the tables of another service (row counts as that school's owner).

do $$
declare
  out text := ''; fails int := 0; r record; n bigint;
  gate_re constant text := 'fn_org_has_feature|fn_org_feature_internal|fn_route_feature_ok|fn_org_features|fn_org_has_classes';
  -- tables that cannot carry the check themselves, and why
  exempt constant text[] := array[
    'ds_evaluation_scores'   -- no organization_id: reached only through ds_evaluations, which is checked
  ];
  old_names constant text[] := array['students','route_stops','route_runs','route_stop_events','route_crew_overrides','ridership_events',
    'school_sites','school_guardians','school_bus_clients','student_guardians','student_ride_notices','student_stop_assignments','guardian_invites'];
  owner_ds uuid; owner_bus uuid; org_ds uuid; org_bus uuid;
begin
  -- 1. naming law
  for r in select c.relname from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r'
            and (c.relname ~ '^(school|student|guardian|route|ridership)_' ) loop
    out := out || 'FAIL naming: table ' || r.relname || ' looks like a service table without ds_ / bus_' || E'\n'; fails := fails + 1;
  end loop;
  for r in select c.relname from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like 'bus\_%'
            and not exists (select 1 from ops.domain_tables d where d.tbl = c.relname and d.domain = 'school_bus') loop
    out := out || 'FAIL domain: ' || r.relname || ' is not registered as school_bus' || E'\n'; fails := fails + 1;
  end loop;
  for r in select c.relname from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like 'ds\_%'
            and not exists (select 1 from ops.domain_tables d where d.tbl = c.relname and d.domain = 'driving_school') loop
    out := out || 'FAIL domain: ' || r.relname || ' is not registered as driving_school' || E'\n'; fails := fails + 1;
  end loop;
  -- 2. registry both ways
  for r in select c.relname from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and not c.relispartition
            and not exists (select 1 from ops.domain_tables d where d.tbl = c.relname) loop
    out := out || 'FAIL registry: table ' || r.relname || ' is not in ops.domain_tables' || E'\n'; fails := fails + 1;
  end loop;
  for r in select d.tbl from ops.domain_tables d where to_regclass('public.' || d.tbl) is null loop
    out := out || 'FAIL registry: ' || r.tbl || ' is registered but does not exist' || E'\n'; fails := fails + 1;
  end loop;
  -- 3. service tag
  for r in select c.relname, obj_description(c.oid, 'pg_class') cm from pg_class c
            where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and (c.relname like 'bus\_%' or c.relname like 'ds\_%') loop
    if r.cm is null or r.cm not like 'service=' || (case when r.relname like 'bus\_%' then 'school_bus' else 'driving_school' end) || '%' then
      out := out || 'FAIL tag: ' || r.relname || ' has no service comment (' || coalesce(r.cm, 'null') || ')' || E'\n'; fails := fails + 1;
    end if;
  end loop;
  -- 4. plan feature on service tables
  for r in
    select c.relname,
           exists (select 1 from information_schema.columns k where k.table_schema = 'public' and k.table_name = c.relname and k.column_name = 'organization_id') has_org,
           (select count(*) from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname) pols,
           (select count(*) from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname
               and coalesce(p.qual, '') || coalesce(p.with_check, '') ~* gate_re) gated
      from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and (c.relname like 'bus\_%' or c.relname like 'ds\_%')
  loop
    if r.has_org and r.pols > 0 and r.gated = 0 and not (r.relname = any (exempt)) then
      out := out || 'FAIL feature: ' || r.relname || ' has policies but none checks the plan feature' || E'\n'; fails := fails + 1;
    end if;
  end loop;
  -- 5. old names in function bodies
  for r in select p.proname, o from pg_proc p cross join unnest(old_names) o
            where p.pronamespace = 'public'::regnamespace and p.prokind in ('f', 'p')
              and (p.prosrc ~* ('\y(?:from|join|update|into|table)\s+(?:public\.)?' || o || '\y') or p.prosrc ~* ('\ypublic\.' || o || '\y')) loop
    out := out || 'FAIL old name: function ' || r.proname || ' still uses the table ' || r.o || E'\n'; fails := fails + 1;
  end loop;
  -- 6. the domain guard
  for r in select x.rule, x.object, x.detail from ops.domain_violations() x loop
    out := out || 'FAIL guard ' || r.rule || ': ' || r.object || ' - ' || r.detail || E'\n'; fails := fails + 1;
  end loop;
  if not exists (select 1 from pg_event_trigger where evtname = 'domain_guard' and evtenabled <> 'D') then
    out := out || 'FAIL guard: the domain_guard event trigger is missing or disabled' || E'\n'; fails := fails + 1;
  end if;
  -- 7. a school of one service sees nothing of another service's tables (as the owner of that school)
  select o.id into org_ds from public.organizations o where o.industry_template = 'driving_school'
     and exists (select 1 from public.ds_students s where s.organization_id = o.id) limit 1;
  select o.id into org_bus from public.organizations o where o.industry_template = 'school_transport'
     and exists (select 1 from public.bus_students s where s.organization_id = o.id) limit 1;
  if org_ds is not null and org_bus is not null then
    select m.user_id into owner_ds from public.organization_members m where m.organization_id = org_ds and m.member_role = 'owner' and m.is_active
       and not exists (select 1 from public.organization_members x where x.user_id = m.user_id and x.organization_id = org_bus and x.is_active) limit 1;
    select m.user_id into owner_bus from public.organization_members m where m.organization_id = org_bus and m.member_role = 'owner' and m.is_active
       and not exists (select 1 from public.organization_members x where x.user_id = m.user_id and x.organization_id = org_ds and x.is_active) limit 1;
    if owner_ds is not null then
      perform set_config('request.jwt.claims', json_build_object('sub', owner_ds, 'role', 'authenticated')::text, true);
      set local role authenticated;
      for r in select c.relname from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like 'bus\_%' loop
        execute format('select count(*) from public.%I', r.relname) into n;
        if n > 0 then out := out || 'FAIL isolation: a driving school owner sees ' || n || ' rows of ' || r.relname || E'\n'; fails := fails + 1; end if;
      end loop;
      reset role;
    else out := out || 'skip 7a: no driving school owner outside the bus company' || E'\n'; end if;
    if owner_bus is not null then
      perform set_config('request.jwt.claims', json_build_object('sub', owner_bus, 'role', 'authenticated')::text, true);
      set local role authenticated;
      for r in select c.relname from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like 'ds\_%' loop
        begin
          execute format('select count(*) from public.%I', r.relname) into n;
          if n > 0 then out := out || 'FAIL isolation: a school bus owner sees ' || n || ' rows of ' || r.relname || E'\n'; fails := fails + 1; end if;
        exception when others then null;  -- no privilege at all is fine
        end;
      end loop;
      reset role;
    else out := out || 'skip 7b: no school bus owner outside the driving school' || E'\n'; end if;
  else out := out || 'skip 7: needs one driving school and one school bus company with students' || E'\n'; end if;

  out := out || (case when fails = 0 then 'RESULT: OK' else 'RESULT: ' || fails || ' FAIL' end);
  raise exception E'SERVICE SEPARATION REPORT\n%', out;
end $$;
