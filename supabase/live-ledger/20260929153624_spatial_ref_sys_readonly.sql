-- spatial_ref_sys belongs to PostGIS (owner supabase_admin), so RLS can't be
-- enabled from here. Clients never need to write it: make it read-only.
revoke insert, update, delete, truncate on table public.spatial_ref_sys from anon, authenticated;
