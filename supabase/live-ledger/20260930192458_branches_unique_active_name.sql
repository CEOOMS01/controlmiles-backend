alter table public.branches drop constraint if exists branches_organization_id_name_key;
create unique index branches_org_active_name_key on public.branches (organization_id, lower(name)) where not is_archived;
