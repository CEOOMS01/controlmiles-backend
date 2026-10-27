-- No effect: the grants on public.spatial_ref_sys come from supabase_admin and cannot be revoked
-- by postgres. Superseded by 20261027172823_move_postgis_to_extensions_schema.
revoke insert, update, delete, truncate, references, trigger on public.spatial_ref_sys from anon, authenticated;
