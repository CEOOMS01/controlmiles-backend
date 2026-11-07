-- Diagnostic log the driver can send from Settings (cold-start / background tracking
-- investigation, 2026-11-06). Applied to production with apply_migration.
insert into ops.domain_tables (tbl, domain) values ('diagnostic_logs', 'core');

create table public.diagnostic_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  app_version text,
  device text,
  content text not null check (length(content) <= 600000)
);

alter table public.diagnostic_logs enable row level security;
create policy diagnostic_logs_insert_own on public.diagnostic_logs
  for insert to authenticated with check (user_id = auth.uid());
create policy diagnostic_logs_select_own on public.diagnostic_logs
  for select to authenticated using (user_id = auth.uid());
