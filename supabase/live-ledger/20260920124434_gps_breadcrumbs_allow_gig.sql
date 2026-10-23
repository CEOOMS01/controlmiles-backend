alter table public.session_gps_breadcrumbs
  alter column organization_id drop not null;

drop policy if exists session_gps_breadcrumbs_select on public.session_gps_breadcrumbs;
create policy session_gps_breadcrumbs_select
on public.session_gps_breadcrumbs
for select
using (
  user_id = auth.uid()
  or (organization_id is not null and public.is_org_member(organization_id))
);

drop policy if exists session_gps_breadcrumbs_insert on public.session_gps_breadcrumbs;
create policy session_gps_breadcrumbs_insert
on public.session_gps_breadcrumbs
for insert
with check (
  user_id = auth.uid()
  and (organization_id is null or public.is_org_member(organization_id))
);
