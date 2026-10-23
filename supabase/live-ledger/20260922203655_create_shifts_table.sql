create table public.shifts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  driver_id uuid not null references public.profiles(id) on delete cascade,
  vehicle_id uuid references public.vehicles(id) on delete set null,
  day_of_week smallint not null check (day_of_week between 0 and 6),
  start_time time not null,
  end_time time not null,
  is_active boolean not null default true,
  notes text,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (driver_id, day_of_week, start_time)
);

create index shifts_org_idx on public.shifts (organization_id);
create index shifts_driver_idx on public.shifts (driver_id);

alter table public.shifts enable row level security;

create policy shifts_select on public.shifts
  for select using (public.is_org_member(organization_id));

create policy shifts_insert on public.shifts
  for insert with check (public.is_org_operator_or_above(organization_id));

create policy shifts_update on public.shifts
  for update using (public.is_org_operator_or_above(organization_id));

create policy shifts_delete on public.shifts
  for delete using (public.is_org_operator_or_above(organization_id));

create trigger shifts_touch_updated_at
  before update on public.shifts
  for each row execute function public.fn_touch_updated_at();
