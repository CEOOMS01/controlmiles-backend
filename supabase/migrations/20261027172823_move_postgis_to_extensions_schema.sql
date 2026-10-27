-- PostGIS lived in `public`, which left its table public.spatial_ref_sys writable by anon and
-- authenticated through the API (Supabase alert rls_disabled_in_public, 2026-10-25) and not
-- fixable by us (the table belongs to supabase_admin; earlier REVOKEs did not stick).
-- Reinstalling the extension in the `extensions` schema (not exposed by the API) removes the
-- table from public.
-- The only user data that depends on PostGIS is ifta_us_state_boundaries.geom: it is converted
-- to bytea (lossless EWKB) before the extension is dropped and back to geometry afterwards.
-- Rehearsed in a rolled-back transaction: identical geometry hash and identical state lookups.
drop index public.ifta_us_state_boundaries_geom_idx;
alter table public.ifta_us_state_boundaries alter column geom type bytea using ST_AsEWKB(geom);
drop extension postgis;
create extension postgis with schema extensions;
alter table public.ifta_us_state_boundaries alter column geom type extensions.geometry using extensions.ST_GeomFromEWKB(geom);
create index ifta_us_state_boundaries_geom_idx on public.ifta_us_state_boundaries using gist (geom);
-- Functions that call ST_* by bare name need the schema on their search_path.
alter function public.compute_idle_events(uuid,date,date) set search_path = public, extensions;
alter function public.compute_ifta_vehicle_state_miles(uuid,date,date) set search_path = public, extensions;
alter function public.compute_state_mileage(uuid,date,date,uuid) set search_path = public, extensions;
alter function public.fn_evaluate_fuel_purchase(uuid) set search_path = public, extensions;
alter function public.ifta_state_at_point(double precision,double precision) set search_path = public, extensions;
