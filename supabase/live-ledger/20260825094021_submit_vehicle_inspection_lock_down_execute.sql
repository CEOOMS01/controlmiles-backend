
-- Phase 2 found that Supabase auto-grants EXECUTE to `anon` directly,
-- separate from PUBLIC. Here the opposite gap: standard Postgres grants
-- EXECUTE to PUBLIC on every new function by default, and anon inherits
-- through PUBLIC membership even with no explicit anon grant of its own.
-- REVOKE FROM anon alone was therefore a no-op -- confirmed via proacl
-- showing `=X/postgres` (the PUBLIC entry) with no anon-specific entry.
-- Revoking from both, then granting only to authenticated explicitly.
REVOKE EXECUTE ON FUNCTION public.submit_vehicle_inspection(uuid, text, jsonb, numeric) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.submit_vehicle_inspection(uuid, text, jsonb, numeric) FROM anon;
GRANT EXECUTE ON FUNCTION public.submit_vehicle_inspection(uuid, text, jsonb, numeric) TO authenticated;
