-- Real gap closed (explicit user ask, mobile Settings): an org owner
-- could rename their org (organizations_update_admin already allowed a
-- plain UPDATE for owner/admin) but had no way to delete it at all.
-- A raw `DELETE FROM organizations` would be a landmine: 6 child tables
-- (vehicle_geofence_alerts/vehicle_geofences/vehicle_inspections/
-- vehicle_maintenance_records/session_gps_breadcrumbs/trip_incidents)
-- have NO ACTION on organization_id, so the delete would simply fail
-- with a raw FK violation for any org with real fleet activity; for an
-- org WITHOUT any of those rows it would silently CASCADE through
-- vehicles/organization_members/routes/fleet_driver_slots instead --
-- inconsistent and dangerous either way. This RPC does it properly and
-- atomically: explicitly clears the NO-ACTION tables in dependency-safe
-- order, resets every member's account_type/default_org_id BEFORE their
-- organization_members row disappears (otherwise a driver is left with
-- account_type still 'fleet_driver' and a default_org_id about to go
-- NULL -- a real desync that would break their own app routing), then
-- deletes the org itself. Personal trip evidence (sessions/
-- session_sections/audit_events/reports) deliberately SURVIVES --
-- organization_id already SET NULL by its own existing FK -- since
-- that's the driver's own IRS-deduction record, not fleet-specific data,
-- same philosophy already applied everywhere else in this schema.
create or replace function public.delete_organization(p_org_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
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
  delete from public.session_gps_breadcrumbs where organization_id = p_org_id;
  delete from public.trip_incidents where organization_id = p_org_id;

  delete from public.organizations where id = p_org_id;
end;
$$;

revoke all on function public.delete_organization(uuid) from public;
revoke all on function public.delete_organization(uuid) from anon;
grant execute on function public.delete_organization(uuid) to authenticated;
