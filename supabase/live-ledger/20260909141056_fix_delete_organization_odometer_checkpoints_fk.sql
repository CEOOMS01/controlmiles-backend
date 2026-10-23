-- Real bug found live (2026-09-09), caught auditing the schema before
-- exposing a "delete organization" button in the web Settings page:
-- delete_organization() deletes vehicle_inspections/maintenance_records/
-- geofences/geofence_alerts/gps_breadcrumbs/trip_incidents before
-- deleting the org row -- all of those have a direct organization_id FK
-- with ON DELETE NO ACTION (confirmed via pg_constraint.confdeltype),
-- so leaving any behind blocks the delete. vehicle_odometer_checkpoints
-- has the exact same NO ACTION FK shape but was never added to this
-- cleanup list -- meaning delete_organization would hard-fail with a
-- foreign-key violation for any real fleet org, since weekly odometer
-- checkpoints are core, routine functionality (every driver's mobile
-- app submits one). Never triggered before because no UI has ever
-- called this RPC -- the web Settings page never had a delete button,
-- and the mobile app's own call site was flagged in an earlier session
-- as calling an RPC that didn't even exist yet in this repo. This fixes
-- it at the root rather than working around it in the UI.

create or replace function public.delete_organization(p_org_id uuid)
returns void
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_caller uuid := auth.uid();
  v_is_owner boolean;
begin
  if v_caller is null then
    raise exception 'Not authenticated';
  end if;

  select exists(
    select 1 from public.organization_members
    where organization_id = p_org_id and user_id = v_caller
      and member_role = 'owner' and is_active = true
  ) into v_is_owner;

  if not v_is_owner then
    raise exception 'Only the organization owner can delete it';
  end if;

  update public.profiles
  set account_type = 'gig', default_org_id = null
  where default_org_id = p_org_id;

  delete from public.vehicle_geofence_alerts where organization_id = p_org_id;
  delete from public.vehicle_geofences where organization_id = p_org_id;
  delete from public.vehicle_inspections where organization_id = p_org_id;
  delete from public.vehicle_maintenance_records where organization_id = p_org_id;
  delete from public.vehicle_odometer_checkpoints where organization_id = p_org_id;
  delete from public.session_gps_breadcrumbs where organization_id = p_org_id;
  delete from public.trip_incidents where organization_id = p_org_id;

  delete from public.organizations where id = p_org_id;
end;
$function$;
