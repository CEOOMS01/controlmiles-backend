-- Fleet project (2026-11-16): deleting an account failed for users with several odometer points on one vehicle
-- ("insert or update on vehicle_odometer_checkpoints violates foreign key ... vehicle_id"): the cascade deletes the
-- vehicle and updates the same points (captured_by -> null) in one statement. Delete the points first.
-- Found while testing the gig cleanup (same function there); applied to both projects.
create or replace function public.fn_delete_personal_rows_on_profile_delete()
 returns trigger language plpgsql security definer set search_path to 'public' as $f$
begin
  perform set_config('cm.account_deletion', 'on', true);
  delete from public.vehicle_odometer_checkpoints c using public.vehicles v
   where c.vehicle_id = v.id and v.owner_user_id = old.id;
  delete from public.vehicle_inspections where user_id = old.id and organization_id is null;
  delete from public.trip_incidents where user_id = old.id and organization_id is null;
  delete from public.fuel_purchases where user_id = old.id and organization_id is null;
  delete from public.session_gps_breadcrumbs where user_id = old.id and organization_id is null;
  return old;
end $f$;
