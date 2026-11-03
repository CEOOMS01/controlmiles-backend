-- Olympus Mont Systems LLC - ControlMiles
-- Adding a vehicle failed for every signed-in user with
-- "permission denied for function fn_display_id_blocked" (found 2026-11-03,
-- first reported by a tester adding her car).
--
-- Cause: 20261027062352_wider_ids_and_retired_id_registry revoked EXECUTE on
-- fn_display_id_blocked from anon/authenticated (it reads the internal
-- retired-ID registry), but the four ID generators that call it were left as
-- SECURITY INVOKER, so they run as the caller and can no longer call it.
-- Vehicles, guardians and driver slots created from a user session all hit it
-- (profiles kept working because they are inserted from a definer trigger).
--
-- Fix: the generators run as their owner (they already pin search_path), so
-- the registry stays private and the callers keep no new privileges.
alter function public.fn_assign_vehicle_display_id() security definer;
alter function public.fn_assign_driver_slot_display_id() security definer;
alter function public.fn_assign_guardian_display_id() security definer;
alter function public.fn_assign_profile_display_id() security definer;

-- Trigger functions are never called directly.
revoke execute on function public.fn_assign_vehicle_display_id() from public, anon, authenticated;
revoke execute on function public.fn_assign_driver_slot_display_id() from public, anon, authenticated;
revoke execute on function public.fn_assign_guardian_display_id() from public, anon, authenticated;
revoke execute on function public.fn_assign_profile_display_id() from public, anon, authenticated;
