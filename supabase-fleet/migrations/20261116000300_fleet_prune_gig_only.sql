-- Fleet project only: remove what exists just for the Gig app (Gig and Fleet share nothing).
-- Kept on purpose: gig_apps / gig_app_packages (the Fleet app model still reads them),
-- vehicle_maintenance_records and pdf_export_log (used by Fleet web/app), app_versions.

-- 1. Triggers on kept tables that call Gig-only functions
drop trigger if exists tr_sessions_block_cross_app_open_trip on public.sessions;
drop trigger if exists trg_classify_section_on_close on public.session_sections;
drop trigger if exists tr_profiles_gig_client on public.profiles;

-- 2. Gig-only functions (nothing else calls them; checked before writing this file)
drop function if exists public.apply_regular_trip_to_past(uuid, boolean);
drop function if exists public.suggest_regular_trip(uuid);
drop function if exists public.fn_regular_trip_covers(public.regular_trips, double precision, double precision, double precision, double precision);
drop function if exists public.fn_classify_section_on_close();
drop function if exists public.fn_block_cross_app_open_trip();
drop function if exists public.fn_sync_gig_client();
drop function if exists public.expire_lapsed_play_subscriptions();
drop function if exists public.recompute_personal_entitlements(uuid);
drop function if exists public.report_permission_status(text, text, text, text, boolean, boolean, boolean, boolean, boolean, boolean, boolean);

-- 3. Gig-only tables (none is the parent of a kept table's foreign key)
drop table public.regular_trips;
drop table public.trip_classification_settings;
drop table public.odometer_ocr_feedback;
drop table public.gig_app_suggestions;
drop table public.gig_clients;
drop table public.diagnostic_logs;
drop table public.device_permission_status;
drop table public.play_subscriptions;

-- 4. Domain registry must describe only what is left
delete from ops.domain_tables where tbl in ('regular_trips', 'trip_classification_settings', 'odometer_ocr_feedback',
  'gig_app_suggestions', 'gig_clients', 'diagnostic_logs', 'device_permission_status', 'play_subscriptions');
delete from ops.domain_triggers where tbl in ('regular_trips', 'trip_classification_settings', 'odometer_ocr_feedback',
  'gig_app_suggestions', 'gig_clients', 'diagnostic_logs', 'device_permission_status', 'play_subscriptions')
  or tg in ('tr_sessions_block_cross_app_open_trip', 'trg_classify_section_on_close', 'tr_profiles_gig_client');
delete from ops.domain_allowed_functions where fn in ('apply_regular_trip_to_past', 'suggest_regular_trip',
  'fn_regular_trip_covers', 'fn_classify_section_on_close', 'fn_block_cross_app_open_trip', 'fn_sync_gig_client',
  'expire_lapsed_play_subscriptions', 'recompute_personal_entitlements', 'report_permission_status');
