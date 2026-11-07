-- Olympus Mont Systems LLC - ControlMiles (Gig)
-- The purpose of a trip can be set and corrected after the trip closes
-- (2026-11-05): General trips started by the phone itself have no purpose yet
-- (the app asks "What was this trip for?" afterwards) and a driver can pick a
-- wrong one by mistake. Everything else about a closed section stays frozen:
-- miles, times, coordinates, app and owner.
-- (Applied in production as two steps: fill-once first, then editable.)

create or replace function public.fn_freeze_closed_session_section()
returns trigger
language plpgsql
set search_path to 'public'
as $$
begin
  if OLD.section_status = 'closed' then
    if NEW.total_miles is distinct from OLD.total_miles
      or NEW.total_duration_seconds is distinct from OLD.total_duration_seconds
      or NEW.start_time is distinct from OLD.start_time
      or NEW.end_time is distinct from OLD.end_time
      or NEW.gig_app is distinct from OLD.gig_app
      -- irs_purpose is deliberately NOT here: the driver can change it
      or NEW.start_latitude is distinct from OLD.start_latitude
      or NEW.start_longitude is distinct from OLD.start_longitude
      or NEW.end_latitude is distinct from OLD.end_latitude
      or NEW.end_longitude is distinct from OLD.end_longitude
      or NEW.session_id is distinct from OLD.session_id
      or NEW.user_id is distinct from OLD.user_id
      or NEW.organization_id is distinct from OLD.organization_id
      -- the route drawing can be filled once after the close, never replaced
      or (OLD.route_polyline is not null and NEW.route_polyline is distinct from OLD.route_polyline)
    then
      raise exception 'Cannot modify a closed trip section''s recorded data';
    end if;
  end if;
  return NEW;
end;
$$;
