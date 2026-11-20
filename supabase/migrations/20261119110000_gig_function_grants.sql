-- Gig: the same function lock-down the Fleet database got (2026-11-19, owner request: no user may reach what is not theirs).
--
-- Postgres lets everyone run a function unless told otherwise, and the API exposes every function. In Gig:
--   * tables were already all protected by row level security (35 of 35) -- nothing to change there;
--   * a signed-in user could still run job and server-only functions: expire_lapsed_play_subscriptions and
--     close_abandoned_trips (jobs), recompute_personal_entitlements(any user) (called by the payment webhooks
--     with the service role), fn_invite_unconfirmed_user (looks an email up) and the school-only leftovers
--     (ds_* / fn_ds_*, fn_org_* helpers) that came with the shared baseline;
--   * anonymous visitors could run ~14 functions, of which only two (a shared trip map and the tax-report code
--     redeem, both token-guarded) are meant for visitors.
-- The Gig app calls only: accept_legal_terms, apply_regular_trip_to_past, assign_trips_to_vehicle,
-- check_and_log_pdf_export, compute_state_mileage, delete_trip_section, report_permission_status,
-- set_active_vehicle, submit_vehicle_odometer_checkpoint, suggest_regular_trip -- all stay callable.
-- Jobs run as postgres and the edge functions with the service role, so neither is affected.

revoke execute on all functions in schema public from public, anon;
do $$
begin
  execute 'alter default privileges for role postgres in schema public revoke execute on functions from public, anon';
exception when others then
  raise notice 'default privileges not changed: %', sqlerrm;
end $$;

do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.prokind = 'f' and p.proname in ('get_trip_map', 'redeem_report_access_code')
  loop
    execute format('grant execute on function %s to anon', r.sig);
  end loop;

  for r in
    select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.prokind = 'f'
       and (pg_get_function_result(p.oid) = 'trigger'
            or p.proname like 'ds\_%' or p.proname like 'fn\_ds\_%'
            or p.proname in ('expire_lapsed_play_subscriptions', 'close_abandoned_trips', 'recompute_personal_entitlements',
                             'fn_invite_unconfirmed_user', 'fn_org_billable_vehicles', 'fn_org_enterprise_internal',
                             'fn_org_feature_list_internal', 'fn_org_tier_internal', 'fn_plan_features',
                             'fn_require_org_feature', 'fn_org_local_today', 'fn_fold_empty_trip_sections',
                             'fn_display_id_blocked', 'check_rate_limit'))
  loop
    execute format('revoke execute on function %s from authenticated', r.sig);
  end loop;
end $$;
