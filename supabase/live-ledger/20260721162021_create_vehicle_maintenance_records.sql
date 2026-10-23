-- NUEVO: módulo de mantenimiento de vehículo (cambio de aceite, etc.).
-- v1 = solo registro/historial + cálculo de "próximo" para mostrar en
-- pantalla. Sin notificaciones automáticas todavía (un recordatorio por
-- millaje requeriría vigilar el odómetro en vivo, no es un simple push
-- programado por fecha como los que ya existen en NotificationService).
create table public.vehicle_maintenance_records (
  id                  uuid primary key default gen_random_uuid(),
  vehicle_id          uuid not null references public.vehicles(id) on delete cascade,
  user_id             uuid not null references public.profiles(id) on delete cascade,
  type                text not null,
  performed_at        date not null,
  odometer_at_service numeric,
  next_due_odometer   numeric,
  next_due_date       date,
  cost                numeric,
  notes               text,
  created_at          timestamptz not null default now(),
  constraint chk_maintenance_type_valid check (
    type = any (array[
      'oil_change', 'tire_rotation', 'brake_service',
      'inspection', 'registration', 'battery', 'other'
    ])
  )
);

comment on table public.vehicle_maintenance_records is
  'Historial de mantenimiento por vehículo (cambio de aceite, etc.). Ligado a vehicles con ON DELETE CASCADE porque un vehículo nunca se borra físicamente (se archiva) — este cascade solo aplicaría en un borrado manual directo en DB, no desde la app.';

create index idx_vehicle_maintenance_records_vehicle_id
  on public.vehicle_maintenance_records (vehicle_id);

alter table public.vehicle_maintenance_records enable row level security;

create policy vehicle_maintenance_records_select
  on public.vehicle_maintenance_records for select
  using (user_id = auth.uid());

create policy vehicle_maintenance_records_insert
  on public.vehicle_maintenance_records for insert
  with check (user_id = auth.uid());

create policy vehicle_maintenance_records_update
  on public.vehicle_maintenance_records for update
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

create policy vehicle_maintenance_records_delete
  on public.vehicle_maintenance_records for delete
  using (user_id = auth.uid());
