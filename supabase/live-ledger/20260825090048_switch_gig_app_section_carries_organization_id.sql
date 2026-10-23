-- Fleet Phase 3: session_sections created via switch_gig_app_section() (mid-
-- trip gig-app switches) never carried organization_id, unlike the first
-- section of a trip (created directly by the client, which now sets it --
-- see tracking_controller.dart startNewSection). Without this, a fleet
-- admin could see a driver's overall session but not a section created
-- after a mid-trip switch (sections_select RLS checks organization_id on
-- the SECTION row itself, not inherited from the parent session).
--
-- Reads organization_id from the session row itself rather than taking it
-- as a new client-supplied parameter -- one source of truth (the session
-- it already belongs to), and no client-side state to keep threading
-- through every switchSection() call.
CREATE OR REPLACE FUNCTION public.switch_gig_app_section(p_session_id uuid, p_old_section_id uuid, p_new_section_id uuid, p_new_gig_app text, p_new_irs_purpose text, p_old_total_miles double precision, p_old_total_duration_seconds integer, p_old_end_latitude double precision, p_old_end_longitude double precision)
RETURNS SETOF session_sections
LANGUAGE plpgsql
SET search_path TO 'public'
AS $function$
declare
  v_org_id uuid;
begin
  select organization_id into v_org_id from public.sessions where id = p_session_id;

  if p_old_section_id is not null then
    update session_sections
    set section_status = 'switched',
        end_time = now(),
        total_miles = coalesce(p_old_total_miles, total_miles),
        total_duration_seconds = coalesce(p_old_total_duration_seconds, total_duration_seconds),
        end_latitude = p_old_end_latitude,
        end_longitude = p_old_end_longitude
    where id = p_old_section_id
      and user_id = auth.uid()
      and section_status in ('active', 'paused');
  end if;

  return query
  insert into session_sections (
    id, session_id, user_id, organization_id, gig_app, irs_purpose,
    section_status, total_miles, total_duration_seconds, start_time
  )
  values (
    p_new_section_id, p_session_id, auth.uid(), v_org_id, p_new_gig_app,
    case when p_new_gig_app = 'custom' then p_new_irs_purpose else null end,
    'active', 0, 0, now()
  )
  returning *;
end;
$function$
