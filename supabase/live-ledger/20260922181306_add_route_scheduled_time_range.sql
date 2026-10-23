alter table public.routes
  add column if not exists scheduled_start_time time,
  add column if not exists scheduled_end_time time;
