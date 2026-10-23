-- Service guards on shared-table triggers (2026-10-22). See
-- supabase/migrations/20261022120000_trigger_domain_guards.sql in ControlMiles-app.
set local lock_timeout = '5s';

create or replace trigger sessions_notify_trip_safety
  after update of is_closed on public.sessions
  for each row
  when (new.organization_id is not null)
  execute function public.fn_notify_trip_safety();

create or replace trigger tr_sessions_enforce_active_org_membership
  before insert on public.sessions
  for each row
  when (new.organization_id is not null)
  execute function public.fn_enforce_active_org_membership();

create or replace trigger tr_sessions_enforce_trial
  before insert on public.sessions
  for each row
  when (new.organization_id is null)
  execute function public.fn_enforce_trial_or_subscription();

create or replace trigger tr_sessions_link_shift_block
  after insert on public.sessions
  for each row
  when (new.shift_block_id is not null)
  execute function public.fn_link_session_to_shift_block();

create or replace trigger tr_vehicles_driving_school_cycle
  before insert or update of organization_id on public.vehicles
  for each row
  when (new.organization_id is not null)
  execute function public.fn_vehicles_driving_school_cycle();

create or replace trigger tr_vehicles_enforce_count_limit
  before insert on public.vehicles
  for each row
  when (new.organization_id is null)
  execute function public.fn_enforce_vehicle_count_limit();

create or replace trigger tr_vehicles_enforce_odometer_cycle_tier
  before insert or update of odometer_cycle on public.vehicles
  for each row
  when (new.organization_id is null and new.odometer_cycle is distinct from 'weekly')
  execute function public.fn_enforce_odometer_cycle_tier();

create or replace trigger tr_vehicles_school_limit
  before insert or update of is_archived, organization_id on public.vehicles
  for each row
  when (new.organization_id is not null)
  execute function public.fn_vehicles_school_limit();

create or replace trigger trg_vehicles_route_run_stops
  after update of last_latitude, last_longitude on public.vehicles
  for each row
  when (
    new.organization_id is not null
    and (new.last_latitude is distinct from old.last_latitude
         or new.last_longitude is distinct from old.last_longitude)
  )
  execute function public.fn_route_run_track_stops();
