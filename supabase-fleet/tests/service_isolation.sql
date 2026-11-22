-- Fleet: a user of one service must not see anything of another service (service isolation check, 2026-11-22).
--
-- HOW TO RUN: paste it into the Fleet project's SQL editor (or execute_sql). It NEVER changes anything: it always
-- ends with an error whose text is the report, which rolls back everything it tried. A healthy report ends with
-- "RESULT: OK" and has no "FAIL" line.
--
-- It needs real users: the test accounts alsoler26+<ds|bus|fleet>-<admin|driver>@gmail.com (docs/SERVICE_MAP.md),
-- but it takes ANY active admin / operator / driver who belongs to the organizations of ONE service only.
-- Acting as each of them (set role authenticated + their id):
--   1. every table with an organization_id shows no row of any other organization (so nothing of another service);
--   2. organizations and organization_members show only their own organization;
--   3. bus_route_needs refuses everybody who is not staff of that school bus fleet or the crew of that route, and
--      bus_seed_need_catalog refuses other services (the staff of the bus fleet is the positive control);
--   4. a driver never reads the bus need tables directly (needs come only through bus_route_needs);
--   5. positive control: they do see their own organization.
-- Found with it on 2026-11-22: bus_route_needs let anybody in when the route had no monitor (a NULL guard).

do $$
declare
  out text := ''; fails int := 0; checked int := 0; skipped int := 0;
  a record; t text; tbls text[]; n bigint; j jsonb;
  bus_org uuid; bus_route uuid;
begin
  select array_agg(c.relname::text order by c.relname) into tbls
    from pg_class c
    join pg_attribute at on at.attrelid = c.oid and at.attname = 'organization_id' and not at.attisdropped
   where c.relnamespace = 'public'::regnamespace and c.relkind = 'r';
  select o.id into bus_org from public.organizations o where o.industry_template = 'school_transport'
     and exists (select 1 from public.routes r where r.organization_id = o.id and r.route_type in ('school_am', 'school_pm')) limit 1;
  select r.id into bus_route from public.routes r where r.organization_id = bus_org and r.route_type in ('school_am', 'school_pm') limit 1;

  for a in
    select m.user_id, m.member_role, o.industry_template tpl, o.id org, p.email
      from public.organization_members m
      join public.organizations o on o.id = m.organization_id
      join public.profiles p on p.id = m.user_id
     where m.is_active and m.member_role in ('admin', 'operator', 'driver')
       and not exists (select 1 from public.organization_members x join public.organizations ox on ox.id = x.organization_id
                        where x.user_id = m.user_id and x.is_active and ox.industry_template <> o.industry_template)
     order by o.industry_template, m.member_role, p.email
  loop
    checked := checked + 1;
    perform set_config('request.jwt.claims', json_build_object('sub', a.user_id, 'role', 'authenticated')::text, true);
    set local role authenticated;

    -- 1. rows of any other organization, in every table that has an organization_id
    foreach t in array tbls loop
      begin
        execute format('select count(*) from public.%I where organization_id <> %L', t, a.org) into n;
        if n > 0 then out := out || 'FAIL ' || a.email || ' (' || a.tpl || ' ' || a.member_role || ') sees ' || n || ' rows of other schools in ' || t || E'\n'; fails := fails + 1; end if;
      exception when insufficient_privilege then null;  -- no privilege at all is fine
      end;
    end loop;

    -- 2. the school list and its members
    select count(*) into n from public.organizations where id <> a.org;
    if n > 0 then out := out || 'FAIL ' || a.email || ' sees ' || n || ' other organizations' || E'\n'; fails := fails + 1; end if;
    select count(*) into n from public.organization_members where organization_id <> a.org;
    if n > 0 then out := out || 'FAIL ' || a.email || ' sees ' || n || ' members of other organizations' || E'\n'; fails := fails + 1; end if;

    -- 3. functions of the school bus service
    if bus_route is not null and not (a.tpl = 'school_transport' and a.member_role in ('admin', 'operator')) then
      begin
        perform public.bus_route_needs(bus_route);
        out := out || 'FAIL ' || a.email || ' (' || a.tpl || ' ' || a.member_role || ') can read bus_route_needs of a bus route they do not crew' || E'\n'; fails := fails + 1;
      exception when others then null;
      end;
    end if;
    if a.tpl <> 'school_transport' and bus_org is not null then
      begin
        perform public.bus_seed_need_catalog(bus_org);
        out := out || 'FAIL ' || a.email || ' (' || a.tpl || ') can seed the need codes of a school bus fleet' || E'\n'; fails := fails + 1;
      exception when others then null;
      end;
    end if;
    if a.tpl = 'school_transport' and a.member_role in ('admin', 'operator') and bus_route is not null then
      begin
        j := public.bus_route_needs(bus_route);
        if j is null then out := out || 'FAIL ' || a.email || ' (admin of the bus fleet) gets nothing from bus_route_needs' || E'\n'; fails := fails + 1; end if;
      exception when others then
        out := out || 'FAIL ' || a.email || ' (admin of the bus fleet) cannot read bus_route_needs: ' || sqlerrm || E'\n'; fails := fails + 1;
      end;
    end if;

    -- 4. a driver never reads the bus need tables directly
    if a.member_role = 'driver' then
      begin
        select count(*) into n from public.bus_need_catalog;
        if n > 0 then out := out || 'FAIL ' || a.email || ' (driver) reads ' || n || ' rows of bus_need_catalog' || E'\n'; fails := fails + 1; end if;
        select count(*) into n from public.bus_student_needs;
        if n > 0 then out := out || 'FAIL ' || a.email || ' (driver) reads ' || n || ' rows of bus_student_needs' || E'\n'; fails := fails + 1; end if;
      exception when insufficient_privilege then null;
      end;
    end if;

    -- 5. positive control: they do see their own organization
    select count(*) into n from public.organizations where id = a.org;
    if n <> 1 then out := out || 'FAIL ' || a.email || ' cannot see their own organization' || E'\n'; fails := fails + 1; end if;

    reset role;
    out := out || 'ok   ' || rpad(a.email, 36) || a.tpl || ' / ' || a.member_role || E'\n';
  end loop;

  if checked = 0 then out := out || 'skip: no admin, operator or driver that belongs to one service only' || E'\n'; skipped := 1; end if;
  out := out || 'actors checked: ' || checked || ' (tables with organization_id: ' || cardinality(tbls) || ')' || E'\n';
  out := out || (case when fails = 0 and skipped = 0 then 'RESULT: OK' when fails = 0 then 'RESULT: nothing to check' else 'RESULT: ' || fails || ' FAIL' end);
  raise exception E'SERVICE ISOLATION REPORT\n%', out;
end $$;
