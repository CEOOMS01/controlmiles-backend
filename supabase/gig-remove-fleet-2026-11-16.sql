-- Gig project (zuujwmcftycmdaxesdya): remove everything that belongs to ControlMiles Fleet (2026-11-16).
-- Fleet now lives in its own project (oweekkdectvsigspyafu) and has its own copy of all this data.
-- Backup taken before: Desktop\gig_backups\2026-11-16 (schema + data).
-- Run as ONE transaction. Kept on purpose because gig code reaches them:
--   subscriptions, subscription_events (recompute_personal_entitlements), plan_feature_rules (RLS helpers),
--   retired_display_ids, platform_id_policy (display-id triggers), trip_vehicle_assignments (assign_trips_to_vehicle).

do $$
declare
  keep text[] := array['app_versions','audit_events','auth_signup_errors','device_permission_status','diagnostic_logs',
    'driver_safety_events','edge_function_rate_limits','gig_app_packages','gig_app_suggestions','gig_apps','gig_clients',
    'ifta_us_state_boundaries','odometer_ocr_feedback','organization_members','organizations','pdf_export_log',
    'play_subscriptions','profiles','regular_trips','report_access_attempts','reports','session_gps_breadcrumbs',
    'session_sections','sessions','trip_classification_settings','user_onboarding','vehicle_maintenance_records',
    'vehicle_odometer_checkpoints','vehicles','subscriptions','subscription_events','plan_feature_rules',
    'retired_display_ids','platform_id_policy','trip_vehicle_assignments'];
  orgs uuid[];
  t text; r record; dropped text[] := '{}'; fdropped text[] := '{}';
begin
  select array_agg(id) into orgs from public.organizations;
  raise notice 'organizations to remove: %', coalesce(array_length(orgs, 1), 0);

  -- 0. Account-deletion mode lets the freeze guards allow deleting closed trips.
  perform set_config('cm.account_deletion', 'on', true);
  perform set_config('cm.shift_block_rpc', 'on', true);

  -- 1. Cron: Fleet jobs out.
  for r in select jobname from cron.job where jobname in ('class-reminders-hourly','driver-safety-summaries','ds-client-tokens-purge',
      'ds-enrollment-requests-purge','ds-guardian-links-daily','fuel-anomalies-nightly','ifta-quarterly-rate-sync') loop
    perform cron.unschedule(r.jobname);
  end loop;

  -- 2. Triggers that only serve Fleet.
  drop trigger if exists sessions_notify_trip_safety on public.sessions;
  drop trigger if exists tr_sessions_link_shift_block on public.sessions;
  drop trigger if exists trg_vehicles_route_run_stops on public.vehicles;
  drop trigger if exists tr_vehicles_plan_limit on public.vehicles;
  for r in select tgname from pg_trigger where tgrelid = 'public.organizations'::regclass and tgname like 'tr_org_svc_%' loop
    execute format('drop trigger %I on public.organizations', r.tgname);
  end loop;

  -- 3. Rewrite the three functions gig still needs, without Fleet tables.
  create or replace function public.close_abandoned_trips(p_idle interval default '12:00:00'::interval)
   returns integer language plpgsql security definer set search_path to 'public' as $f$
  declare
    r record;
    v_closed integer := 0;
  begin
    for r in
      select s.id,
             greatest(
               s.start_time,
               s.updated_at,
               (select max(b.recorded_at) from public.session_gps_breadcrumbs b where b.session_id = s.id),
               (select max(x.updated_at) from public.session_sections x where x.session_id = s.id)
             ) as last_activity
      from public.sessions s
      where not coalesce(s.is_closed, false)
    loop
      continue when r.last_activity is null or r.last_activity > now() - p_idle;

      update public.session_sections
         set section_status = 'closed',
             end_time = coalesce(end_time, r.last_activity)
       where session_id = r.id
         and section_status in ('active', 'paused');

      update public.sessions s
         set is_closed = true,
             session_status = 'closed',
             end_time = coalesce(s.end_time, r.last_activity),
             total_miles = greatest(
               coalesce(s.total_miles, 0),
               coalesce((select sum(x.total_miles) from public.session_sections x where x.session_id = s.id), 0)
             )
       where s.id = r.id;

      v_closed := v_closed + 1;
    end loop;
    return v_closed;
  end;
  $f$;

  create or replace function public.fn_delete_personal_rows_on_profile_delete()
   returns trigger language plpgsql security definer set search_path to 'public' as $f$
  begin
    perform set_config('cm.account_deletion', 'on', true);
    delete from public.session_gps_breadcrumbs where user_id = old.id and organization_id is null;
    return old;
  end $f$;

  create or replace function public.update_vehicle_location(p_vehicle_id uuid, p_latitude double precision,
      p_longitude double precision, p_speed double precision default null::double precision)
   returns void language plpgsql security definer set search_path to 'public' as $f$
  declare
    v_org uuid;
    v_assigned_driver uuid;
    v_authorized boolean;
  begin
    if auth.uid() is null then
      raise exception 'Not authenticated';
    end if;
    select organization_id, assigned_driver_id into v_org, v_assigned_driver
    from public.vehicles where id = p_vehicle_id;
    if not found or v_org is null then
      return;
    end if;
    v_authorized := (v_assigned_driver = auth.uid())
      or exists (
        select 1 from public.sessions s
        where s.vehicle_id = p_vehicle_id and s.user_id = auth.uid() and not coalesce(s.is_closed, false)
      )
      or public.is_org_admin_or_owner(v_org);
    if not v_authorized then
      raise exception 'Not authorized to update this vehicle location';
    end if;
    if public.fn_org_feature_internal(v_org, 'live_map') then
      update public.vehicles
      set last_latitude = p_latitude, last_longitude = p_longitude, last_speed = p_speed, last_location_at = now()
      where id = p_vehicle_id;
    end if;
  end;
  $f$;

  -- 4. Fleet tables first (they hold foreign keys into vehicles, sessions, organizations).
  for t in select c.relname from pg_class c where c.relnamespace = 'public'::regnamespace and c.relkind = 'r'
           and c.relname <> all(keep) order by 1 loop
    execute format('drop table public.%I cascade', t);
    dropped := dropped || t;
  end loop;
  raise notice 'dropped % tables: %', array_length(dropped, 1), dropped;

  -- 5. Fleet data. Children first; sessions.organization_id is ON DELETE SET NULL, so Fleet trips must be
  --    deleted explicitly or they would turn into personal gig trips.
  delete from public.session_gps_breadcrumbs where organization_id = any(orgs);
  delete from public.vehicle_odometer_checkpoints where organization_id = any(orgs);
  delete from public.vehicle_maintenance_records where organization_id = any(orgs);
  delete from public.audit_events where organization_id = any(orgs);
  delete from public.driver_safety_events where organization_id = any(orgs);
  delete from public.reports where organization_id = any(orgs);
  delete from public.session_sections where organization_id = any(orgs);
  delete from public.sessions where organization_id = any(orgs);
  delete from public.vehicles where organization_id = any(orgs);
  delete from public.organization_members where organization_id = any(orgs);
  update public.profiles set default_org_id = null where default_org_id = any(orgs);
  delete from public.organizations where id = any(orgs);

  -- 6. Functions that still name a dropped table are dead now: drop them (no cascade: a dependency would stop us).
  for r in select p.oid::regprocedure as sig from pg_proc p
           where p.pronamespace = 'public'::regnamespace and p.prokind = 'f'
             and exists (select 1 from unnest(dropped) d where pg_get_functiondef(p.oid) ~* ('\m' || d || '\M')) loop
    fdropped := fdropped || r.sig::text;
    execute format('drop function %s', r.sig);
  end loop;
  raise notice 'dropped % functions', array_length(fdropped, 1);

  -- 7. The domain registry must describe only what is left.
  delete from ops.domain_tables where tbl = any(dropped);
  delete from ops.domain_triggers where tbl = any(dropped) or tg like 'tr_org_svc_%'
    or tg in ('sessions_notify_trip_safety', 'tr_sessions_link_shift_block', 'trg_vehicles_route_run_stops', 'tr_vehicles_plan_limit');
  delete from ops.domain_allowed_functions
   where fn in (select split_part(trim(both '"' from f), '(', 1) from unnest(fdropped) f);
  -- DRYRUN_MARKER
end $$;

-- Applied right after the script above (2026-11-16): account deletion failed for users with several odometer points
-- on one vehicle (cascade rechecks the vehicle foreign key). Not caused by the cleanup, found while testing it.
create or replace function public.fn_delete_personal_rows_on_profile_delete()
 returns trigger language plpgsql security definer set search_path to 'public' as $f$
begin
  perform set_config('cm.account_deletion', 'on', true);
  delete from public.vehicle_odometer_checkpoints c using public.vehicles v
   where c.vehicle_id = v.id and v.owner_user_id = old.id and v.organization_id is null;
  delete from public.session_gps_breadcrumbs where user_id = old.id and organization_id is null;
  return old;
end $f$;
