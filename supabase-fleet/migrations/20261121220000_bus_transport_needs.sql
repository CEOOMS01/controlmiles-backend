-- School bus: transport needs of each student, with an editable code catalog per school (2026-11-21).
--
-- Why: a bus driver and aide must know, per stop, what each student needs (help to board, a vest, a
-- wheelchair lift, an aide, how the student communicates). City Schools writes these as short codes
-- (MA2, SV, WA, NV, ...) on the driver's route sheet. Here each school has its own catalog of codes, so
-- another district with other codes only edits the catalog.
--
-- What is NOT stored: the disability category or any diagnosis (FERPA / IDEA). Only the transport need.
--
-- School bus service only (bus_* tables, plan feature 'school'). Nothing here touches driving school or
-- fleet tables; the driver reads it only through bus_route_needs(route), for the students of that route.

-- 1. register the tables first: the domain guard refuses an unregistered table ----------------------------
insert into ops.domain_tables (tbl, domain)
select v.tbl, 'school_bus' from (values ('bus_need_catalog'), ('bus_student_needs')) v(tbl)
 where not exists (select 1 from ops.domain_tables d where d.tbl = v.tbl);

-- 2. the catalog -----------------------------------------------------------------------------------------
create table public.bus_need_catalog (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  grp text not null check (grp in ('program', 'equipment', 'communication', 'mobility')),
  code text not null check (code ~ '^[A-Za-z0-9]{1,8}$'),
  label text not null check (char_length(btrim(label)) between 1 and 80),
  sort integer not null default 0,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  unique (organization_id, code)
);
comment on table public.bus_need_catalog is 'service=school_bus: the school''s own codes (program, equipment and staff, communication, mobility assistance)';
create index bus_need_catalog_org_idx on public.bus_need_catalog (organization_id, grp, sort);

-- 3. what each student needs -----------------------------------------------------------------------------
create table public.bus_student_needs (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  student_id uuid not null references public.bus_students(id) on delete cascade,
  need_id uuid not null references public.bus_need_catalog(id) on delete cascade,
  created_at timestamptz not null default now(),
  unique (student_id, need_id)
);
comment on table public.bus_student_needs is 'service=school_bus: transport needs of a student (a code of the school''s catalog); never a diagnosis';
create index bus_student_needs_student_idx on public.bus_student_needs (student_id);

alter table public.bus_students
  add column if not exists program_need_id uuid references public.bus_need_catalog(id) on delete set null,
  add column if not exists transport_note text check (transport_note is null or char_length(transport_note) <= 200);

-- the student, the code and the row must belong to the same school
create or replace function public.fn_bus_needs_same_org() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_table_name = 'bus_student_needs' then
    if not exists (select 1 from public.bus_students s where s.id = new.student_id and s.organization_id = new.organization_id)
       or not exists (select 1 from public.bus_need_catalog c where c.id = new.need_id and c.organization_id = new.organization_id) then
      raise exception 'The student and the code must belong to the same school';
    end if;
  elsif tg_table_name = 'bus_students' and new.program_need_id is not null then
    if not exists (select 1 from public.bus_need_catalog c where c.id = new.program_need_id and c.organization_id = new.organization_id and c.grp = 'program') then
      raise exception 'The program must be a program code of the same school';
    end if;
  end if;
  return new;
end $$;
revoke execute on function public.fn_bus_needs_same_org() from public, anon, authenticated;
create trigger trg_bus_student_needs_same_org before insert or update on public.bus_student_needs
  for each row execute function public.fn_bus_needs_same_org();
create trigger trg_bus_students_program_same_org before insert or update of program_need_id on public.bus_students
  for each row when (new.program_need_id is not null) execute function public.fn_bus_needs_same_org();

-- 4. who can read and write ------------------------------------------------------------------------------
-- Operators and above manage them from the web. Drivers and aides never read these tables: they get the
-- needs of their own route through bus_route_needs().
alter table public.bus_need_catalog enable row level security;
alter table public.bus_student_needs enable row level security;
revoke all on public.bus_need_catalog, public.bus_student_needs from anon;

create policy bus_need_catalog_staff on public.bus_need_catalog for all to authenticated
  using (public.is_org_operator_or_above(organization_id))
  with check (public.is_org_operator_or_above(organization_id));
create policy bus_student_needs_staff on public.bus_student_needs for all to authenticated
  using (public.is_org_operator_or_above(organization_id))
  with check (public.is_org_operator_or_above(organization_id));
-- a school without the school bus service sees nothing, whatever the role
create policy bus_need_catalog_service_gate on public.bus_need_catalog as restrictive for all to authenticated
  using (public.fn_org_feature_internal(organization_id, 'school'));
create policy bus_student_needs_service_gate on public.bus_student_needs as restrictive for all to authenticated
  using (public.fn_org_feature_internal(organization_id, 'school'));

-- 5. the Baltimore City model (from the City Schools "School Route Codes" training sheet) ----------------
create or replace function public.fn_bus_seed_need_catalog(p_org uuid, p_template text) returns integer
language plpgsql security definer set search_path = public as $$
declare v_n integer;
begin
  if p_template is distinct from 'baltimore_city' then raise exception 'Unknown template'; end if;
  insert into public.bus_need_catalog (organization_id, grp, code, label, sort)
  select p_org, t.grp, t.code, t.label, t.sort
    from (values
      ('program', 'AD', 'All day', 10), ('program', 'AM', 'Morning', 20), ('program', 'PM', 'Afternoon (mid-day)', 30),
      ('program', 'WL', 'Week long', 40), ('program', '5DR', '5-day resident', 50), ('program', 'YD', 'Year-round all day', 60),
      ('equipment', 'MB', 'Ambulatory', 10), ('equipment', 'NO', 'None', 20), ('equipment', 'WC', 'Wheelchair', 30),
      ('equipment', 'WE', 'Wheelchair and EMT', 40), ('equipment', 'WN', 'Wheelchair and nurse', 50),
      ('equipment', 'WA', 'Wheelchair and 1:1 aide', 60), ('equipment', 'PI', 'PIES program', 70),
      ('equipment', 'EM', 'Emergency medical tech', 80), ('equipment', 'RN', 'Registered nurse', 90),
      ('equipment', 'OT', 'Other', 100), ('equipment', 'OX', 'Oxygen', 110), ('equipment', 'CS', 'Car seat', 120),
      ('equipment', 'SV', 'Safety vest', 130), ('equipment', 'VE', 'Vest', 140), ('equipment', 'A1', 'One-on-one aide', 150),
      ('communication', 'VB', 'Verbal', 10), ('communication', 'NV', 'Non-verbal', 20),
      ('communication', 'OE', 'Other than English', 30), ('communication', 'CE', 'Communication in English', 40),
      ('communication', 'SL', 'Sign language', 50), ('communication', 'CD', 'Augmentative communication device', 60),
      ('mobility', 'MA1', 'Walks to bus independently', 10), ('mobility', 'MA2', 'Walks to bus with supervision', 20),
      ('mobility', 'MA3', 'Walks on bus independently', 30), ('mobility', 'MA4', 'Walks to seat independently', 40),
      ('mobility', 'MA5', 'Needs assistance to board bus', 50), ('mobility', 'MA6', 'Needs assistance to find seat', 60),
      ('mobility', 'MA7', 'Uses crutches', 70), ('mobility', 'MA8', 'Uses walker', 80), ('mobility', 'MA9', 'Must hold hand', 90)
    ) as t(grp, code, label, sort)
  on conflict (organization_id, code) do nothing;
  get diagnostics v_n = row_count;
  return v_n;
end $$;
revoke execute on function public.fn_bus_seed_need_catalog(uuid, text) from public, anon, authenticated;

-- what the web calls: only an owner or an admin of a school bus fleet, only for their own school
create or replace function public.bus_seed_need_catalog(p_org uuid, p_template text default 'baltimore_city') returns integer
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_org_admin_or_owner(p_org) then raise exception 'Only an admin or the owner can load the codes'; end if;
  perform public.fn_require_org_feature(p_org, 'school');
  return public.fn_bus_seed_need_catalog(p_org, p_template);
end $$;
revoke execute on function public.bus_seed_need_catalog(uuid, text) from public, anon;

-- 6. what the driver and the aide read: the needs of the students of THIS route, today --------------------
create or replace function public.bus_route_needs(p_route_id uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v_org uuid; v_crew record; v_res jsonb;
begin
  select organization_id into v_org from public.routes where id = p_route_id;
  if v_org is null then raise exception 'ROUTE_NOT_FOUND'; end if;
  perform public.fn_require_org_feature(v_org, 'school');
  select * into v_crew from public.fn_route_crew(p_route_id, public.fn_org_today(v_org));
  if not (public.is_org_operator_or_above(v_org) or v_crew.driver_id = auth.uid() or v_crew.monitor_id = auth.uid()) then
    raise exception 'NOT_AUTHORIZED';
  end if;
  with riders as (select distinct a.student_id from public.bus_stop_assignments a where a.route_id = p_route_id),
  needs as (
    select n.student_id, c.code, c.label, c.grp, c.sort
      from public.bus_student_needs n
      join public.bus_need_catalog c on c.id = n.need_id and c.is_active
     where n.student_id in (select student_id from riders)
  ),
  progs as (
    select s.id as student_id, c.code, c.label
      from public.bus_students s
      join public.bus_need_catalog c on c.id = s.program_need_id
     where s.id in (select student_id from riders)
  )
  select jsonb_build_object(
    -- only the codes used on this route: the driver sees what he needs, not the whole catalog
    'legend', coalesce((select jsonb_agg(jsonb_build_object('code', l.code, 'label', l.label, 'group', l.grp) order by l.grp, l.code)
                          from (select distinct code, label, grp from needs
                                union select distinct code, label, 'program' from progs) l), '[]'::jsonb),
    'students', coalesce((select jsonb_object_agg(r.student_id::text, jsonb_build_object(
                  'codes', coalesce((select jsonb_agg(n.code order by n.sort, n.code) from needs n where n.student_id = r.student_id), '[]'::jsonb),
                  'program', (select p.code from progs p where p.student_id = r.student_id),
                  'note', (select s.transport_note from public.bus_students s where s.id = r.student_id)))
                  from riders r), '{}'::jsonb))
    into v_res;
  return v_res;
end $$;
revoke execute on function public.bus_route_needs(uuid) from public, anon;

-- 7. the Baltimore City model for the school bus fleets that already exist ---------------------------------
select public.fn_bus_seed_need_catalog(o.id, 'baltimore_city')
  from public.organizations o where o.industry_template = 'school_transport';

-- the migration must leave the guard clean
do $$
declare v text;
begin
  select string_agg(x.rule || ' ' || x.object || ': ' || x.detail, E'\n') into v from ops.domain_violations() x;
  if v is not null then raise exception E'domain guard is not clean after this migration:\n%', v; end if;
end $$;
