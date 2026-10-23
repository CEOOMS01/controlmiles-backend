alter table public.driver_safety_events
  add column if not exists speed_limit_mps double precision,
  add column if not exists speed_limit_source text
    check (speed_limit_source is null or speed_limit_source in ('osm', 'fixed_fallback'));
