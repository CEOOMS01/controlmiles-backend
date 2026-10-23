-- Verified Android package-name catalog for foreground-app gig
-- detection, per the user's own explicit caution: never hardcode/guess
-- package names into the client, keep them backend-configurable so a
-- wrong or changed id can be fixed without an app release. gig_app_id
-- matches GigAppCatalog's existing ids (lib/models/gig_app.dart) --
-- no new gig-app ids invented here.
--
-- Deliberately dev-maintained only: RLS allows SELECT to any
-- authenticated user (non-sensitive static reference data), but NO
-- insert/update/delete policy exists -- changes only ever go through a
-- new migration, never a client write, matching the "don't invent
-- package names" discipline for who can populate this table too.
create table public.gig_app_packages (
  id uuid primary key default gen_random_uuid(),
  gig_app_id text not null,
  os text not null default 'android' check (os = 'android'),
  package_name text not null,
  created_at timestamptz not null default now(),
  unique (os, package_name)
);
comment on table public.gig_app_packages is 'Verified Android package names for foreground-app gig detection (auto trip detection premium feature). Dev-maintained via migration only.';

alter table public.gig_app_packages enable row level security;

create policy gig_app_packages_select_all on public.gig_app_packages
for select to authenticated using (true);

-- Verified live via WebSearch against current Play Store listings
-- before inserting, not from memory. Uber's single driver app covers
-- both rides and Uber Eats deliveries (same package) -- mapped to
-- 'uber' only; the confirmation screen still lets the driver switch to
-- Uber Eats manually if that's what they were actually doing, matching
-- "auxiliary suggestion, never ground truth."
insert into public.gig_app_packages (gig_app_id, package_name) values
  ('uber', 'com.ubercab.driver'),
  ('lyft', 'com.lyft.android.driver'),
  ('doordash', 'com.doordash.driverapp'),
  ('instacart', 'com.instacart.shopper'),
  ('amazon', 'com.amazon.rabbit'),
  ('amazon', 'com.amazon.flex.rabbit');
