
-- Explicit user requirement: a fleet driver must never see another
-- driver's inspection history -- only (a) their own past submissions,
-- and (b) the SINGLE most recent inspection for the vehicle they're
-- currently assigned to (so they can check what the last driver
-- reported before their own shift), never that vehicle's older
-- history. Org admin keeps full visibility (already built for
-- /admin/reviews). The "latest only" restriction is enforced as a
-- real RLS boundary (a scalar subquery comparing against MAX(created_at)
-- per vehicle), not just a client-side LIMIT 1 that a raw query could
-- bypass.
drop policy vehicle_inspections_select on public.vehicle_inspections;

create policy vehicle_inspections_select_own on public.vehicle_inspections
for select to authenticated
using (user_id = auth.uid());

create policy vehicle_inspections_select_assigned_vehicle_latest on public.vehicle_inspections
for select to authenticated
using (
  vehicle_id in (select id from public.vehicles where assigned_driver_id = auth.uid())
  and id = (
    select vi2.id from public.vehicle_inspections vi2
    where vi2.vehicle_id = vehicle_inspections.vehicle_id
    order by vi2.created_at desc
    limit 1
  )
);

create policy vehicle_inspections_select_admin on public.vehicle_inspections
for select to authenticated
using (organization_id is not null and is_org_admin_or_owner(organization_id));
