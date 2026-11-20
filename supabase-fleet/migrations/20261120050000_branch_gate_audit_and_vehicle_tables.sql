-- Fleet: audit pass on "can anyone spy on a school's numbers" (2026-11-20).
--  1. the remaining tables that hold a car's, a trip's or a driver's numbers get the branch fence too
--     (audit log, safety events, inspections, maintenance, odometer checkpoints, geofences, reports, shifts...);
--  2. the audit log and the mileage reports are no longer readable by every member of the school: only the person
--     they belong to and operators/admins/owner (inside their branch);
--  3. a receipt photo is only shown to the admins of the receipt's own branch;
--  4. visitors without a session have no table access at all (row security already hid everything; this removes
--     the permission itself, as a second lock). Only the public reference data stays readable.

do $$
declare r record;
begin
  for r in select * from (values
    ('audit_events', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_member_gate(organization_id, user_id)'),
    ('driver_safety_events', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_actor_gate(organization_id, vehicle_id, user_id)'),
    ('driver_workdays', 'all', 'coalesce(driver_id = auth.uid(), false) or public.fn_member_gate(organization_id, driver_id)'),
    ('ds_availability', 'all', 'coalesce(instructor_id = auth.uid(), false) or public.fn_member_gate(organization_id, instructor_id)'),
    ('reports', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_actor_gate(organization_id, vehicle_id, user_id)'),
    ('session_sections', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_actor_gate(organization_id, null, user_id)'),
    ('shifts', 'all', 'coalesce(driver_id = auth.uid(), false) or (public.fn_member_gate(organization_id, driver_id) and public.fn_vehicle_gate(vehicle_id))'),
    ('trip_approvals', 'all', 'public.fn_session_gate(session_id)'),
    ('trip_incidents', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_actor_gate(organization_id, vehicle_id, user_id)'),
    ('vehicle_geofence_alerts', 'all', 'public.fn_vehicle_gate(vehicle_id)'),
    ('vehicle_geofences', 'all', 'public.fn_vehicle_gate(vehicle_id)'),
    ('vehicle_inspections', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_vehicle_gate(vehicle_id)'),
    ('vehicle_maintenance_records', 'all', 'coalesce(user_id = auth.uid(), false) or public.fn_vehicle_gate(vehicle_id)'),
    ('vehicle_odometer_checkpoints', 'all', 'public.fn_vehicle_gate(vehicle_id)')
  ) as t(tbl, cmd, expr) loop
    execute format('drop policy if exists %I on public.%I', r.tbl || '_branch_gate', r.tbl);
    execute format('create policy %I on public.%I as restrictive for %s to authenticated using (%s)',
                   r.tbl || '_branch_gate', r.tbl, r.cmd, r.expr);
  end loop;
end $$;

-- the audit log: yours, or (operator/admin/owner of a school that has the activity log) the school's
drop policy if exists audit_select on public.audit_events;
create policy audit_select on public.audit_events for select to authenticated using (
  user_id = auth.uid()
  or (organization_id is not null and public.is_org_operator_or_above(organization_id)
      and public.fn_org_has_feature(organization_id, 'activity_log'))
);

-- mileage reports: yours, or the school's operators/admins/owner
drop policy if exists reports_select_own on public.reports;
create policy reports_select_own on public.reports for select to authenticated using (
  user_id = auth.uid() or (organization_id is not null and public.is_org_operator_or_above(organization_id))
);

-- receipt photos: the person who took it, or an admin of the receipt's branch
drop policy if exists fuel_receipts_select_org_admin on storage.objects;
create policy fuel_receipts_select_org_admin on storage.objects for select to authenticated using (
  bucket_id = 'fuel_receipts' and exists (
    select 1 from public.fuel_purchases fp
     where fp.receipt_path = objects.name and fp.organization_id is not null
       and public.is_org_admin_or_owner(fp.organization_id) and public.fn_purchase_gate(fp.id))
);

-- visitors: no table access at all, except the public reference data
revoke all on all tables in schema public from anon;
grant select on public.ifta_us_state_boundaries, public.ifta_fuel_tax_rates, public.app_versions to anon;
alter default privileges for role postgres in schema public revoke all on tables from anon;
