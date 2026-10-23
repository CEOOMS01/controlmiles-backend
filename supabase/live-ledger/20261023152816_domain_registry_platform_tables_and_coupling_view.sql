-- Core contract, step 2 (2026-10-23).
-- The tenant tables (organizations, organization_members, branches,
-- branch_moves, fleet_type_changes) are the platform every service stands
-- on, not part of "fleet". Labelled fleet, every driving-school and
-- school-bus function looked like a cross-domain mix. They are core now;
-- their triggers are registered (rule R3). All are tenant-configuration
-- triggers that only fire on UPDATE OF specific columns of the tenant
-- tables (org settings, plan, branch limits), so they are registered as
-- core: a non-core trigger must carry a WHEN guard (domain_triggers_check).
update ops.domain_tables set domain = 'core'
 where tbl in ('organizations', 'organization_members', 'branches', 'branch_moves', 'fleet_type_changes');

insert into ops.domain_triggers (tbl, tg, domain, guard) values
  ('organizations', 'trg_guard_org_billing_columns',                 'core', null),
  ('organizations', 'tr_organizations_validate_timezone',            'core', null),
  ('organizations', 'tr_organizations_touch_updated_at',             'core', null),
  ('organizations', 'tr_organizations_fleet_template',               'core', null),
  ('organizations', 'trg_enforce_org_feature_switches',              'core', null),
  ('organizations', 'tr_organizations_enforce_assignment_mode_tier', 'core', null),
  ('organizations', 'tr_org_driving_school_cycle',                   'core', null),
  ('branches',      'tr_branches_plan_limit',                        'core', null)
on conflict (tbl, tg) do update set domain = excluded.domain, guard = excluded.guard;

-- Which public functions touch which domains' tables (same text scan the
-- domain guard uses). One row per function; the core tables a service
-- reaches are its real contract with the platform.
create or replace view ops.v_domain_coupling as
with f as (
  select p.proname::text as fn, p.prosrc
    from pg_proc p
   where p.pronamespace = 'public'::regnamespace and p.prokind = 'f'
     and not exists (select 1 from pg_depend e where e.classid = 'pg_proc'::regclass and e.objid = p.oid and e.deptype = 'e')
), hits as (
  select f.fn, d.tbl, d.domain
    from f join ops.domain_tables d
      on f.prosrc ~* ('(^|[^a-z0-9_])(public\.)?' || d.tbl || '([^a-z0-9_]|$)')
)
select fn as function_name,
       string_agg(distinct domain, ' + ' order by domain) as domains,
       string_agg(distinct tbl, ', ' order by tbl) filter (where domain = 'core') as core_tables,
       string_agg(distinct tbl, ', ' order by tbl) filter (where domain <> 'core') as service_tables
  from hits
 group by fn;
revoke all on ops.v_domain_coupling from public, anon, authenticated;
