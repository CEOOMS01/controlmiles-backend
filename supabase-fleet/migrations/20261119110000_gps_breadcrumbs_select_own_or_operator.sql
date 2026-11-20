-- Fleet: the GPS points of a trip are read by their driver and by the school's owner/admins/operators only
-- (2026-11-19, tenant isolation review). Before, ANY member of the school (another instructor, a monitor...) could
-- read every colleague's GPS trail. No driver-side code reads other people's points (they are written by the
-- ingest function and read by the admin panel and the tax-report page), so nothing changes for the apps.
--
-- Left as it is on purpose: sessions and fuel_purchases stay readable by every member of the school, because the
-- app needs it (a driver sees which cars are in use and a car's total miles across drivers). Narrowing those
-- needs a product decision and an app change, not just a policy.

drop policy if exists session_gps_breadcrumbs_select on public.session_gps_breadcrumbs;
create policy session_gps_breadcrumbs_select on public.session_gps_breadcrumbs for select to authenticated
  using ((user_id = auth.uid()) or ((organization_id is not null) and public.is_org_operator_or_above(organization_id)));
