
-- Real bug caught live: a self-referencing subquery inside an RLS USING
-- clause on the SAME table causes infinite recursion (Postgres
-- re-evaluates the policy for the subquery's own access). Standard fix:
-- wrap the lookup in a SECURITY DEFINER function, which bypasses RLS
-- internally and breaks the recursion.
drop policy vehicle_inspections_select_assigned_vehicle_latest on public.vehicle_inspections;

create or replace function public.fn_latest_inspection_id(p_vehicle_id uuid)
returns uuid
language sql
security definer
stable
set search_path = public
as $$
  select id from public.vehicle_inspections
  where vehicle_id = p_vehicle_id
  order by created_at desc
  limit 1;
$$;

revoke all on function public.fn_latest_inspection_id(uuid) from public;
revoke all on function public.fn_latest_inspection_id(uuid) from anon;
grant execute on function public.fn_latest_inspection_id(uuid) to authenticated;

create policy vehicle_inspections_select_assigned_vehicle_latest on public.vehicle_inspections
for select to authenticated
using (
  vehicle_id in (select id from public.vehicles where assigned_driver_id = auth.uid())
  and id = public.fn_latest_inspection_id(vehicle_id)
);
