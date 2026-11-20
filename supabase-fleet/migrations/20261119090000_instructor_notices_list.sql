-- Driving school: several reminders for the instructors, shown one after another on the app's home
-- (2026-11-19, owner request). Replaces the single organizations.instructor_notice of the previous migration.
--
-- Admins and operators write them on the web dashboard; every active member of the school reads them.
-- A notice can be switched off without deleting it, and can end on a date (the app hides it after that day).

create table if not exists public.instructor_notices (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  body text not null check (char_length(btrim(body)) between 1 and 300),
  is_active boolean not null default true,
  ends_on date,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists instructor_notices_org_idx on public.instructor_notices (organization_id, created_at);

alter table public.instructor_notices enable row level security;
drop policy if exists instructor_notices_select on public.instructor_notices;
create policy instructor_notices_select on public.instructor_notices for select to authenticated
  using (public.is_org_member(organization_id));
drop policy if exists instructor_notices_write on public.instructor_notices;
create policy instructor_notices_write on public.instructor_notices for all to authenticated
  using (public.is_org_operator_or_above(organization_id))
  with check (public.is_org_operator_or_above(organization_id));

insert into ops.domain_tables (tbl, domain) values ('instructor_notices', 'driving_school') on conflict do nothing;

-- The single reminder written earlier becomes the first notice of the list.
insert into public.instructor_notices (organization_id, body)
select id, left(btrim(instructor_notice), 300) from public.organizations
 where nullif(btrim(coalesce(instructor_notice, '')), '') is not null;

alter table public.organizations drop constraint if exists organizations_instructor_notice_len;
alter table public.organizations drop column if exists instructor_notice;
alter table public.organizations drop column if exists instructor_notice_updated_at;
