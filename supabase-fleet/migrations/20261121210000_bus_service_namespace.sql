-- Fleet: the school bus service gets its own name space (2026-11-21), phase 1 of the service separation.
--
-- Rule from now on: every table belongs to ONE service and says so in its name.
--     ds_   driving school        bus_   school bus (school transport)
--     (no prefix) = shared by every service: organizations, vehicles, routes, shifts, fuel, ...
-- `routes` stays shared on purpose: it holds the dispatch routes of fleets AND the school runs; its policies
-- already tell them apart by route_type (fn_route_feature_ok). Details: docs/SERVICE_MAP.md.
--
-- 1. the school bus tables are renamed (indexes, foreign keys, triggers, policies, Realtime follow by themselves);
-- 2. the functions that mention them are rewritten (a function body is plain text, it does not follow a rename);
-- 3. the bus tables that were not checked against the school bus plan feature now are;
-- 4. the school bus service has no branches yet: creating one is refused instead of half working;
-- 5. every service table carries a comment with its service, so the tests can check them all.
--
-- Safe to run once: it stops (and rolls back) by itself if any function still mentions an old name.
-- Names of columns, RPCs and JSON keys that the apps read do NOT change.

create temp table _bus_rename (old text primary key, new text not null) on commit drop;
insert into _bus_rename values
  ('students',                 'bus_students'),
  ('route_stops',              'bus_route_stops'),
  ('route_runs',               'bus_route_runs'),
  ('route_stop_events',        'bus_route_stop_events'),
  ('route_crew_overrides',     'bus_route_crew_overrides'),
  ('ridership_events',         'bus_ridership_events'),
  ('school_sites',             'bus_sites'),
  ('school_guardians',         'bus_guardians'),
  ('school_bus_clients',       'bus_clients'),
  ('student_guardians',        'bus_student_guardians'),
  ('student_ride_notices',     'bus_ride_notices'),
  ('student_stop_assignments', 'bus_stop_assignments'),
  ('guardian_invites',         'bus_guardian_invites');

-- 1. tables ---------------------------------------------------------------------------------------------
do $$
declare m record; p record;
begin
  for m in select * from _bus_rename order by old loop
    if to_regclass('public.' || m.old) is null then raise exception 'table public.% not found', m.old; end if;
    if to_regclass('public.' || m.new) is not null then raise exception 'table public.% already exists', m.new; end if;
    execute format('alter table public.%I rename to %I', m.old, m.new);
    -- policies carry the table name: students_select_admin -> bus_students_select_admin
    for p in select policyname from pg_policies
              where schemaname = 'public' and tablename = m.new and policyname like m.old || '\_%' loop
      execute format('alter policy %I on public.%I rename to %I', p.policyname, m.new,
                     m.new || substr(p.policyname, length(m.old) + 1));
    end loop;
  end loop;
end $$;

-- 2. functions: table names inside their bodies -----------------------------------------------------------
-- Only table positions are rewritten (from / join / update / into / public.<name>, and the table name a trigger
-- function compares with TG_TABLE_NAME). JSON keys such as 'students' that the apps read are left alone.
do $$
declare f record; m record; d text; nd text; n int := 0;
begin
  for f in
    select p.oid, p.proname from pg_proc p
     where p.pronamespace = 'public'::regnamespace and p.prokind in ('f', 'p')
       and exists (select 1 from _bus_rename r where p.prosrc ~* ('\y' || r.old || '\y'))
  loop
    d := pg_get_functiondef(f.oid);
    nd := d;
    for m in select * from _bus_rename order by length(old) desc loop
      nd := regexp_replace(nd, '(\y(?:from|join|update|into|table)\s+)(?:public\.)?' || m.old || '\y', '\1public.' || m.new, 'gi');
      nd := regexp_replace(nd, '\ypublic\.' || m.old || '\y', 'public.' || m.new, 'gi');
      nd := regexp_replace(nd, '(TG_TABLE_NAME\s*=\s*)''' || m.old || '''', '\1''' || m.new || '''', 'gi');
    end loop;
    if nd <> d then
      execute nd;
      n := n + 1;
    end if;
  end loop;
  raise notice 'rewrote % functions', n;

  -- nothing may be left behind
  for f in
    select p.proname, r.old from pg_proc p cross join _bus_rename r
     where p.pronamespace = 'public'::regnamespace and p.prokind in ('f', 'p')
       and (p.prosrc ~* ('\y(?:from|join|update|into|table)\s+(?:public\.)?' || r.old || '\y')
         or p.prosrc ~* ('\ypublic\.' || r.old || '\y')
         or p.prosrc ~* ('TG_TABLE_NAME\s*=\s*''' || r.old || ''''))
  loop
    raise exception 'function % still mentions the old table %', f.proname, f.old;
  end loop;
end $$;

-- 3. the school bus plan feature on the bus tables that had no check -------------------------------------
-- A school without the school bus service sees none of these, whatever the role.
do $$
declare t text;
begin
  foreach t in array array['bus_guardians', 'bus_clients', 'bus_student_guardians', 'bus_ride_notices', 'bus_guardian_invites'] loop
    execute format('drop policy if exists %I on public.%I', t || '_service_gate', t);
    execute format(
      'create policy %I on public.%I as restrictive for all to authenticated using (public.fn_org_feature_internal(organization_id, %L))',
      t || '_service_gate', t, 'school');
  end loop;
end $$;

-- 4. no branches for the school bus service (yet) ---------------------------------------------------------
create or replace function public.fn_branches_service_check() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if exists (select 1 from public.organizations o where o.id = new.organization_id and o.industry_template = 'school_transport') then
    raise exception 'Branches are not available for the school bus service yet.' using errcode = 'P0001';
  end if;
  return new;
end $$;
revoke execute on function public.fn_branches_service_check() from public, anon, authenticated;
drop trigger if exists tr_branches_service_check on public.branches;
create trigger tr_branches_service_check before insert on public.branches
  for each row execute function public.fn_branches_service_check();

-- 5. every service table says which service it belongs to ------------------------------------------------
do $$
declare r record;
begin
  for r in select c.relname from pg_class c
            where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like 'bus\_%'
              and obj_description(c.oid, 'pg_class') is null loop
    execute format('comment on table public.%I is %L', r.relname, 'service=school_bus');
  end loop;
  for r in select c.relname from pg_class c
            where c.relnamespace = 'public'::regnamespace and c.relkind = 'r' and c.relname like 'ds\_%'
              and obj_description(c.oid, 'pg_class') is null loop
    execute format('comment on table public.%I is %L', r.relname, 'service=driving_school');
  end loop;
  comment on table public.routes is 'service=shared (fleet dispatch routes and school bus runs, told apart by route_type)';
end $$;

-- 6. the domain registry follows the rename, and the guard is switched on in Fleet ------------------------
-- ops.domain_tables says which service owns each table; ops.v_domain_coupling / ops.domain_violations() read it
-- (docs/CORE_CONTRACT.md). It must hold the NEW names or the guard stops seeing the bus tables.
update ops.domain_tables d set tbl = r.new from _bus_rename r where d.tbl = r.old;

-- registered now: the table and the triggers added by the branch / schedule work of 2026-11-19 and 20, which the
-- guard reported as unregistered (rules R3 and R6).
insert into ops.domain_tables (tbl, domain)
select 'schedule_event_dismissals', 'driving_school'
 where not exists (select 1 from ops.domain_tables where tbl = 'schedule_event_dismissals');
insert into ops.domain_triggers (tbl, tg, domain, guard)
select v.tbl, v.tg, v.domain, v.guard
  from (values
    ('sessions',             'tr_sessions_check_pickup',  'driving_school', 'pickup_block_id IS NOT NULL'),
    ('vehicles',             'tr_vehicles_autoassign',    'driving_school', 'organization_id IS NOT NULL'),
    ('vehicles',             'tr_vehicles_fill_branch',   'core',           null),
    ('organization_members', 'tr_members_branch_guard',   'core',           null),
    ('branches',             'tr_first_branch_adopts',    'core',           null),
    ('branches',             'tr_branches_service_check', 'core',           null)
  ) as v(tbl, tg, domain, guard)
 where not exists (select 1 from ops.domain_triggers r where r.tbl = v.tbl and r.tg = v.tg);

-- Gig has had this event trigger since 2026-10-23; Fleet did not. From now on creating a table, function or
-- trigger that breaks a rule, or a table nobody registered, is refused with the rule's name.
drop event trigger if exists domain_guard;
create event trigger domain_guard on ddl_command_end
  when tag in ('CREATE FUNCTION', 'ALTER FUNCTION', 'CREATE TRIGGER', 'CREATE TABLE')
  execute function ops.fn_domain_guard();

-- the migration must leave the guard clean
do $$
declare v text;
begin
  select string_agg(x.rule || ' ' || x.object || ': ' || x.detail, E'\n') into v from ops.domain_violations() x;
  if v is not null then raise exception E'domain guard is not clean after this migration:\n%', v; end if;
end $$;
