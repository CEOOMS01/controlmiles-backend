
-- Real gap caught before it could ship silently broken: neither table
-- was in the supabase_realtime publication, which means the new
-- Realtime subscription in fleet_live_map_screen.dart would have
-- connected successfully (no error) but NEVER received a single
-- event -- Supabase requires each table to be explicitly opted into
-- the publication, it isn't automatic just because RLS/a client
-- subscribes to it.
alter publication supabase_realtime add table public.vehicles;
alter publication supabase_realtime add table public.vehicle_geofence_alerts;
