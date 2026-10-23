-- Domain registry, fleet type on vehicles, and a guard that checks every
-- migration (2026-10-22). Source: ControlMiles-app
-- supabase/migrations/20261022140000_domain_registry_and_guard.sql
set local lock_timeout = '5s';
create schema if not exists ops;
revoke all on schema ops from public, anon, authenticated;
create table if not exists ops.domain_tables (
  tbl text primary key,
  domain text not null check (domain in ('core', 'gig', 'fleet', 'school_bus', 'driving_school'))
);
create table if not exists ops.domain_triggers (
  tbl text not null,
  tg text not null,
  domain text not null check (domain in ('core', 'gig', 'fleet', 'school_bus', 'driving_school')),
  guard text,
  primary key (tbl, tg),
  check (domain = 'core' or guard is not null)
);
create table if not exists ops.domain_allowed_functions (
  fn text primary key,
  reason text not null
);
insert into ops.domain_tables (tbl, domain) values
  ('profiles', 'core'), ('sessions', 'core'), ('session_sections', 'core'),
  ('session_gps_breadcrumbs', 'core'), ('vehicles', 'core'), ('audit_events', 'core'),
  ('reports', 'core'), ('vehicle_maintenance_records', 'core'),
  ('vehicle_odometer_checkpoints', 'core'), ('user_onboarding', 'core'),
  ('driver_safety_events', 'core'), ('vehicle_inspections', 'core'), ('trip_incidents', 'core'),
  ('edge_function_rate_limits', 'core'), ('auth_signup_errors', 'core'),
  ('pdf_export_log', 'core'), ('report_access_attempts', 'core'),
  ('gig_apps', 'gig'), ('gig_app_packages', 'gig'), ('play_subscriptions', 'gig'),
  ('subscriptions', 'gig'), ('subscription_events', 'gig'),
  ('organizations', 'fleet'), ('organization_members', 'fleet'), ('branches', 'fleet'),
  ('branch_moves', 'fleet'), ('driver_invites', 'fleet'), ('driver_workdays', 'fleet'),
  ('fleet_driver_slots', 'fleet'), ('driver_slot_claim_attempts', 'fleet'),
  ('fleet_type_changes', 'fleet'), ('fuel_purchases', 'fleet'), ('fuel_anomalies', 'fleet'),
  ('vehicle_geofences', 'fleet'), ('vehicle_geofence_alerts', 'fleet'),
  ('trip_approvals', 'fleet'), ('driver_notifications', 'fleet'), ('shifts', 'fleet'),
  ('shift_blocks', 'fleet'), ('routes', 'fleet'),
  ('ifta_fuel_tax_rates', 'fleet'), ('ifta_us_state_boundaries', 'fleet'),
  ('route_stops', 'school_bus'), ('route_runs', 'school_bus'), ('route_stop_events', 'school_bus'),
  ('route_crew_overrides', 'school_bus'), ('students', 'school_bus'),
  ('student_stop_assignments', 'school_bus'), ('ridership_events', 'school_bus'),
  ('school_sites', 'school_bus'),
  ('ds_students', 'driving_school'), ('ds_student_private', 'driving_school'),
  ('ds_programs', 'driving_school'), ('ds_packages', 'driving_school'),
  ('ds_student_packages', 'driving_school'), ('ds_skills', 'driving_school'),
  ('ds_evaluations', 'driving_school'), ('ds_evaluation_scores', 'driving_school'),
  ('ds_certificates', 'driving_school'), ('ds_availability', 'driving_school'),
  ('ds_time_off', 'driving_school'), ('ds_settings', 'driving_school'),
  ('ds_portal_links', 'driving_school'), ('ds_public_pages', 'driving_school'),
  ('ds_enrollment_requests', 'driving_school'), ('ds_slot_notices', 'driving_school'),
  ('ds_reminders_sent', 'driving_school')
on conflict (tbl) do update set domain = excluded.domain;
insert into ops.domain_triggers (tbl, tg, domain, guard) values
  ('sessions', 'sessions_notify_trip_safety', 'fleet', 'organization_id IS NOT NULL'),
  ('sessions', 'sessions_vehicle_active_trip', 'core', null),
  ('sessions', 'tr_sessions_block_cross_app_open_trip', 'core', null),
  ('sessions', 'tr_sessions_enforce_active_org_membership', 'fleet', 'organization_id IS NOT NULL'),
  ('sessions', 'tr_sessions_enforce_trial', 'gig', 'organization_id IS NULL'),
  ('sessions', 'tr_sessions_guard_tenant', 'core', null),
  ('sessions', 'tr_sessions_link_shift_block', 'fleet', 'shift_block_id IS NOT NULL'),
  ('sessions', 'tr_sessions_touch_updated_at', 'core', null),
  ('sessions', 'trg_discard_zero_mile_trip', 'core', null),
  ('sessions', 'trg_freeze_closed_session', 'core', null),
  ('sessions', 'trg_session_miles_from_sections', 'core', null),
  ('vehicles', 'tr_vehicles_0_fleet_template', 'core', null),
  ('vehicles', 'tr_vehicles_block_switch_during_session', 'core', null),
  ('vehicles', 'tr_vehicles_driving_school_cycle', 'driving_school', 'fleet_template = ''driving_school'''),
  ('vehicles', 'tr_vehicles_enforce_count_limit', 'gig', 'organization_id IS NULL'),
  ('vehicles', 'tr_vehicles_enforce_odometer_cycle_tier', 'gig', 'organization_id IS NULL'),
  ('vehicles', 'tr_vehicles_enforce_odometer_floor', 'core', null),
  ('vehicles', 'tr_vehicles_school_limit', 'driving_school', 'fleet_template = ''driving_school'''),
  ('vehicles', 'tr_vehicles_set_cycle_anchor', 'core', null),
  ('vehicles', 'tr_vehicles_touch_updated_at', 'core', null),
  ('vehicles', 'trg_assign_vehicle_display_id', 'core', null),
  ('vehicles', 'trg_freeze_vehicle_display_id', 'core', null),
  ('vehicles', 'trg_vehicles_route_run_stops', 'school_bus', 'fleet_template = ''school_transport'''),
  ('profiles', 'tr_enforce_fleet_org', 'fleet', 'account_type = ANY'),
  ('profiles', 'tr_profiles_assign_display_id', 'core', null),
  ('profiles', 'tr_profiles_touch_updated_at', 'core', null),
  ('profiles', 'trg_delete_personal_rows_on_profile_delete', 'core', null),
  ('profiles', 'trg_freeze_profile_display_id', 'core', null),
  ('profiles', 'trg_guard_profile_protected_columns', 'core', null),
  ('session_sections', 'tr_session_sections_inherit_tenant', 'core', null),
  ('session_sections', 'tr_session_sections_touch_updated_at', 'core', null),
  ('session_sections', 'trg_freeze_closed_session_section', 'core', null),
  ('audit_events', 'tr_audit_events_inherit_tenant', 'core', null),
  ('vehicle_maintenance_records', 'tr_maintenance_guard_tenant', 'core', null),
  ('user_onboarding', 'tr_user_onboarding_touch_updated_at', 'core', null)
on conflict (tbl, tg) do update set domain = excluded.domain, guard = excluded.guard;
insert into ops.domain_allowed_functions (fn, reason) values
  ('delete_organization', 'removes an organization and everything under it'),
  ('fn_delete_personal_rows_on_profile_delete', 'account deletion reaches personal rows of every table')
on conflict (fn) do update set reason = excluded.reason;

alter table public.vehicles add column if not exists fleet_template text;
create or replace function public.fn_vehicles_fleet_template()
returns trigger language plpgsql security definer set search_path to 'public' as $f$
begin
  if new.organization_id is null then
    new.fleet_template := null;
  else
    select industry_template into new.fleet_template
      from public.organizations where id = new.organization_id;
  end if;
  return new;
end $f$;
revoke execute on function public.fn_vehicles_fleet_template() from public, anon, authenticated;
create or replace trigger tr_vehicles_0_fleet_template
  before insert or update of organization_id, fleet_template on public.vehicles
  for each row
  execute function public.fn_vehicles_fleet_template();
create or replace function public.fn_org_fleet_template_to_vehicles()
returns trigger language plpgsql security definer set search_path to 'public' as $f$
begin
  update public.vehicles set fleet_template = new.industry_template
   where organization_id = new.id and fleet_template is distinct from new.industry_template;
  return null;
end $f$;
revoke execute on function public.fn_org_fleet_template_to_vehicles() from public, anon, authenticated;
create or replace trigger tr_organizations_fleet_template
  after update of industry_template on public.organizations
  for each row
  when (new.industry_template is distinct from old.industry_template)
  execute function public.fn_org_fleet_template_to_vehicles();
update public.vehicles v set fleet_template = o.industry_template
  from public.organizations o
 where o.id = v.organization_id and v.fleet_template is distinct from o.industry_template;
create or replace trigger tr_vehicles_driving_school_cycle
  before insert or update of organization_id on public.vehicles
  for each row
  when (new.fleet_template = 'driving_school')
  execute function public.fn_vehicles_driving_school_cycle();
create or replace trigger tr_vehicles_school_limit
  before insert or update of is_archived, organization_id on public.vehicles
  for each row
  when (new.fleet_template = 'driving_school')
  execute function public.fn_vehicles_school_limit();
create or replace trigger trg_vehicles_route_run_stops
  after update of last_latitude, last_longitude on public.vehicles
  for each row
  when (
    new.fleet_template = 'school_transport'
    and (new.last_latitude is distinct from old.last_latitude
         or new.last_longitude is distinct from old.last_longitude)
  )
  execute function public.fn_route_run_track_stops();
create or replace trigger tr_enforce_fleet_org
  after insert or update of account_type on public.profiles
  for each row
  when (new.account_type in ('fleet_admin', 'fleet_driver'))
  execute function public.enforce_fleet_org_membership();

create or replace function ops.domain_violations(
  p_full boolean default true, p_fn oid default null, p_tg oid default null, p_tbl oid default null
)
returns table (rule text, object text, detail text)
language plpgsql stable set search_path to 'pg_catalog' as $f$
begin
  return query
  with fns as (
    select p.oid, p.proname::text as fn, p.prosrc,
           regexp_replace(regexp_replace(p.prosrc, '--[^\n]*', '', 'g'), '''[^'']*''', '', 'g') as code
      from pg_proc p
     where p.pronamespace = 'public'::regnamespace
       and p.prokind = 'f'
       and not exists (select 1 from pg_depend e where e.classid = 'pg_proc'::regclass and e.objid = p.oid and e.deptype = 'e')
       and p.proname not in (select a.fn from ops.domain_allowed_functions a)
       and (p_full or p.oid = p_fn)
  ),
  touches as (
    select f.fn, array_agg(distinct d.domain order by d.domain) as domains
      from fns f
      join ops.domain_tables d
        on f.code ~* ('(^|[^a-z0-9_])(public\.)?' || d.tbl || '([^a-z0-9_]|$)')
     group by f.fn
  ),
  core_triggers as (
    select t.oid, c.relname::text as tbl, t.tgname::text as tg
      from pg_trigger t
      join pg_class c on c.oid = t.tgrelid and c.relnamespace = 'public'::regnamespace
      join ops.domain_tables d on d.tbl = c.relname and d.domain = 'core'
     where not t.tgisinternal and (p_full or t.oid = p_tg)
  )
  select 'R1', x.fn, array_to_string(x.domains, ', ')
    from touches x
   where 'gig' = any(x.domains) and x.domains && array['fleet', 'school_bus', 'driving_school']
  union all
  select 'R2', x.fn, array_to_string(x.domains, ', ')
    from touches x
   where x.domains @> array['school_bus', 'driving_school']
  union all
  select 'R3', ct.tbl || '.' || ct.tg, 'trigger on a core table is not in ops.domain_triggers'
    from core_triggers ct
   where not exists (select 1 from ops.domain_triggers r where r.tbl = ct.tbl and r.tg = ct.tg)
  union all
  select 'R4', ct.tbl || '.' || ct.tg, r.domain || ' trigger needs WHEN (' || r.guard || ')'
    from core_triggers ct
    join ops.domain_triggers r on r.tbl = ct.tbl and r.tg = ct.tg
   where r.guard is not null
     and position(upper(r.guard) in upper(pg_get_triggerdef(ct.oid))) = 0
  union all
  select 'R5', f.fn, 'builds SQL at run time; allow it in ops.domain_allowed_functions with a reason'
    from fns f
   where f.prosrc ~* '(^|[^a-z0-9_])execute\s+(?!function|procedure)'
  union all
  select 'R6', c.relname::text, 'table is not in ops.domain_tables'
    from pg_class c
   where c.relnamespace = 'public'::regnamespace
     and c.relkind in ('r', 'p')
     and not c.relispartition
     and not exists (select 1 from pg_depend e where e.classid = 'pg_class'::regclass and e.objid = c.oid and e.deptype = 'e')
     and not exists (select 1 from ops.domain_tables d where d.tbl = c.relname)
     and (p_full or c.oid = p_tbl);
end $f$;
revoke execute on function ops.domain_violations(boolean, oid, oid, oid) from public, anon, authenticated;

create or replace function ops.fn_domain_guard()
returns event_trigger language plpgsql set search_path to 'pg_catalog' as $f$
declare
  v text;
begin
  if current_user <> 'postgres' or coalesce(current_setting('cm.skip_domain_check', true), '') = 'on' then
    return;
  end if;
  begin
    select string_agg(x.rule || '  ' || x.object || ': ' || x.detail, E'\n')
      into v
      from pg_event_trigger_ddl_commands() c
      cross join lateral ops.domain_violations(
        false,
        case when c.classid = 'pg_proc'::regclass then c.objid end,
        case when c.classid = 'pg_trigger'::regclass then c.objid end,
        case when c.classid = 'pg_class'::regclass then c.objid end
      ) x
     where c.command_tag in ('CREATE FUNCTION', 'ALTER FUNCTION', 'CREATE TRIGGER', 'CREATE TABLE')
       and c.classid in ('pg_proc'::regclass, 'pg_trigger'::regclass, 'pg_class'::regclass);
  exception when others then
    raise warning 'domain guard skipped: %', sqlerrm;
    return;
  end;
  if v is not null then
    raise exception 'Domain boundary check failed'
      using detail = v,
            hint = 'Register the table or trigger in ops.domain_tables / ops.domain_triggers before creating it, '
                   'add the WHEN guard, or allow the function in ops.domain_allowed_functions. '
                   'See supabase/checks/domain_boundaries.sql.';
  end if;
end $f$;
revoke execute on function ops.fn_domain_guard() from public, anon, authenticated;

create event trigger domain_guard on ddl_command_end
  when tag in ('CREATE FUNCTION', 'ALTER FUNCTION', 'CREATE TRIGGER', 'CREATE TABLE')
  execute function ops.fn_domain_guard();
