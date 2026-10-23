drop policy if exists sessions_delete on public.sessions;
create policy sessions_delete on public.sessions
  for delete to authenticated
  using (
    (organization_id is null and user_id = auth.uid())
    or (organization_id is not null and public.is_org_admin_or_owner(organization_id))
    or (
      organization_id is not null
      and user_id = auth.uid()
      and not coalesce(is_closed, false)
      and not exists (
        select 1 from public.session_gps_breadcrumbs b where b.session_id = sessions.id
      )
    )
  );

drop policy if exists sections_delete on public.session_sections;
create policy sections_delete on public.session_sections
  for delete to authenticated
  using (
    (organization_id is null and user_id = auth.uid())
    or (organization_id is not null and public.is_org_admin_or_owner(organization_id))
  );
