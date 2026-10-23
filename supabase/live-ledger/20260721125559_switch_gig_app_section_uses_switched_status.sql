
-- Ajuste al RPC del fix #2: la sección vieja cerrada por un cambio de gig
-- app se marca 'switched' (no 'closed'), distinguiéndola de un cierre real
-- de viaje (endCurrentSection, sigue usando 'closed'). El schema ya
-- contemplaba este status (chk section_status IN (...,'switched')) y el
-- modelo Dart SessionSection.isClosed ya lo trataba como terminado — solo
-- faltaba que algún código lo escribiera realmente. reports_screen.dart se
-- actualizó en paralelo para filtrar por isClosed en vez de solo 'closed'.
create or replace function public.switch_gig_app_section(
  p_session_id uuid,
  p_old_section_id uuid,
  p_new_section_id uuid,
  p_new_gig_app text,
  p_new_irs_purpose text,
  p_old_total_miles double precision,
  p_old_total_duration_seconds integer,
  p_old_end_latitude double precision,
  p_old_end_longitude double precision
)
returns setof session_sections
language plpgsql
security invoker
set search_path = public
as $$
begin
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
    id, session_id, user_id, gig_app, irs_purpose,
    section_status, total_miles, total_duration_seconds, start_time
  )
  values (
    p_new_section_id, p_session_id, auth.uid(), p_new_gig_app,
    case when p_new_gig_app = 'custom' then p_new_irs_purpose else null end,
    'active', 0, 0, now()
  )
  returning *;
end;
$$;
