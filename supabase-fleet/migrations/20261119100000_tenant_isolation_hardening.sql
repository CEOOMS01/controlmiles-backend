-- Fleet: tenant isolation hardening (2026-11-19, owner request: "one organization or user must not be able to
-- read or write another organization").
--
-- AUDIT RESULT. Table access was already sound: every public table has row level security, and a test as a
-- member of one school (driver and owner) found no way to read, update, delete or insert rows of another school.
-- The gaps were in the FUNCTIONS: Postgres lets everyone execute a function unless told otherwise, and Supabase
-- exposes every function as an API call, so ~200 SECURITY DEFINER functions (they run with the owner's rights,
-- bypassing row level security) could be called by anyone, even without logging in. Found with a real two-school test:
--   * support_change_fleet_type(org, type, reason)  -- any user could change ANY school's fleet type.
--   * close_abandoned_trips / fn_send_safety_summaries / ds_due_class_reminders -- job functions anyone could run.
--   * guardian_login_user, fn_invite_unconfirmed_user -- account lookups meant for the server only.
--   * fn_ds_portal_payload / fn_ds_student_snapshot / fn_ds_balance / fn_ds_free_slots ... -- helpers that return a
--     student's data or a school's availability by id, with no check of who asks.
--   * update_vehicle_location -- its permission test evaluated to NULL (not false) for a car with no assigned
--     driver, so the "not authorized" error never fired and any user could move any such car.
--
-- THE RULE FROM NOW ON
--   1. Nobody anonymous can call a function, except the public pages' token / slug functions listed below.
--   2. A logged-in user can call only what an app or the web panel calls. Helpers, job functions and
--      server-only functions are callable only by the database itself (postgres) and the service role
--      (edge functions). Trigger functions are not callable by anyone.
--   3. NEW FUNCTIONS: a function created from now on is not executable by anonymous users. If it is only a helper
--      for other functions, also `revoke execute ... from authenticated`.

-- 1. Nothing is executable by default for the public or anonymous -------------------------------------------------
revoke execute on all functions in schema public from public, anon;
do $$
begin
  execute 'alter default privileges for role postgres in schema public revoke execute on functions from public, anon';
exception when others then
  raise notice 'default privileges not changed: %', sqlerrm;
end $$;

-- 2. The public pages: functions guarded by a secret token or a public slug, by design --------------------------
do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure as sig
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.prokind = 'f'
       and p.proname = any (array[
         'ds_portal_book', 'ds_portal_cancel', 'ds_portal_certificate', 'ds_portal_set_sms', 'ds_portal_slots',
         'ds_portal_view', 'ds_public_enroll', 'ds_public_order', 'ds_public_order_status', 'ds_public_origins',
         'ds_public_page', 'ds_public_slug_for_host', 'get_trip_map', 'redeem_report_access_code',
         'resolve_driver_invite', 'resolve_guardian_invite', 'public_pricing_catalog', 'check_rate_limit',
         'ds_client_home', 'ds_client_book', 'ds_client_cancel', 'ds_client_slots', 'ds_client_student_view',
         'ds_client_certificate', 'ds_client_set_sms', 'ds_client_add_child', 'ds_client_open_link',
         'ds_client_link_info', 'ds_client_request_links', 'ds_client_sign_out'])
  loop
    execute format('grant execute on function %s to anon', r.sig);
  end loop;
end $$;

-- 3. Helpers, job and server-only functions: not callable by logged-in users either -------------------------------
do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure as sig
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.prokind = 'f'
       and (
         pg_get_function_result(p.oid) = 'trigger'
         or p.proname = any (array[
           -- jobs (pg_cron runs them as postgres; edge functions as the service role)
           'close_abandoned_trips', 'fn_send_safety_summaries', 'ds_due_class_reminders', 'ds_due_slot_notices',
           'fn_ds_purge_client_tokens', 'fn_ds_purge_enrollment_requests', 'fn_reevaluate_recent_fuel_purchases',
           'fn_ds_alert_unclaimed_classes', 'fn_ds_close_guardian_links',
           -- server only: payments, support, account lookups, billing
           'fn_ds_provider_secrets', 'fn_ds_provider_store', 'fn_ds_provider_error', 'fn_ds_provider_remove',
           'fn_ds_order_paid_provider', 'support_change_fleet_type', 'guardian_login_user', 'fn_invite_unconfirmed_user',
           'fn_org_billable_vehicles', 'fn_org_feature_list_internal', 'fn_org_tier_internal',
           'fn_org_enterprise_internal', 'fn_org_branch_allowance_internal', 'fn_org_effective_tier',
           -- helpers called only by other functions: they take an id and do not check who asks
           'fn_ds_assign_vehicles', 'fn_ds_balance', 'fn_ds_class_numbers', 'fn_ds_client_session',
           'fn_ds_client_student', 'fn_ds_conflict', 'fn_ds_free_slots', 'fn_ds_instructor_conflict', 'fn_ds_is_minor',
           'fn_ds_link_client', 'fn_ds_link_counts', 'fn_ds_member', 'fn_ds_portal_book_for', 'fn_ds_portal_cancel_for',
           'fn_ds_portal_certificate_for', 'fn_ds_portal_link', 'fn_ds_portal_payload', 'fn_ds_portal_set_sms_for',
           'fn_ds_portal_slots_for', 'fn_ds_release_range', 'fn_ds_slot_grid', 'fn_ds_student_address',
           'fn_ds_student_snapshot', 'fn_ds_upsert_client', 'fn_ds_vehicle_free', 'fn_evaluate_fuel_purchase',
           'fn_fold_empty_trip_sections', 'fn_my_crew_run', 'fn_my_open_run', 'fn_org_local_today', 'fn_plan_features',
           'fn_require_org_feature', 'fn_ride_notice_applies', 'fn_ride_notice_role', 'fn_rider_status',
           'fn_rode_am_today', 'fn_route_crew', 'fn_route_run_mark_current_stops', 'fn_safety_score', 'fn_stop_due',
           'fn_display_id_blocked'])
       )
  loop
    execute format('revoke execute on function %s from authenticated', r.sig);
  end loop;
end $$;

-- 4. update_vehicle_location: the permission test must be false, never NULL ------------------------------------------
do $$
declare d text;
begin
  select pg_get_functiondef(p.oid) into d
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
   where n.nspname = 'public' and p.proname = 'update_vehicle_location';
  if d not like '%v_authorized := (v_assigned_driver = auth.uid())%' or d not like '%or public.is_org_admin_or_owner(v_org);%' then
    raise exception 'update_vehicle_location changed: review the authorization test by hand';
  end if;
  d := replace(d, 'v_authorized := (v_assigned_driver = auth.uid())', 'v_authorized := coalesce((v_assigned_driver = auth.uid())');
  d := replace(d, 'or public.is_org_admin_or_owner(v_org);', 'or public.is_org_admin_or_owner(v_org), false);');
  execute d;
end $$;

-- 5. support_change_fleet_type: also refuse anyone but the database and the service role ------------------------------
create or replace function public.support_change_fleet_type(p_organization_id uuid, p_industry_template text, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_old text;
begin
  if current_user not in ('postgres', 'supabase_admin', 'service_role') then
    raise exception 'Not authorized';
  end if;
  if not coalesce(public.fn_valid_fleet_profile(p_industry_template), false) then
    raise exception 'Unknown fleet type: %', p_industry_template;
  end if;
  if coalesce(btrim(p_reason), '') = '' then
    raise exception 'A reason is required';
  end if;

  select industry_template into v_old from public.organizations where id = p_organization_id for update;
  if not found then
    raise exception 'Organization not found';
  end if;

  update public.organizations
     set industry_template = p_industry_template,
         require_pretrip_inspection = public.fn_profile_requires_pretrip(p_industry_template),
         fleet_type_confirmed_at = now()
   where id = p_organization_id;

  insert into public.fleet_type_changes (organization_id, from_type, to_type, source, reason)
  values (p_organization_id, v_old, p_industry_template, 'support', p_reason);
end;
$$;
revoke execute on function public.support_change_fleet_type(uuid, text, text) from public, anon, authenticated;
