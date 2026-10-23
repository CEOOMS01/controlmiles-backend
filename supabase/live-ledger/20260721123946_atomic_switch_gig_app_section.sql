
-- BUG FIX #2 (switch de gig app no atómico): antes el cliente cerraba la
-- sección vieja y creaba la nueva en dos llamadas de red separadas
-- (endCurrentSection + insert). Esto dejaba una ventana real sin ninguna
-- sección activa (un tick GPS ahí mataba el tracking en silencio) y, si el
-- cierre de la vieja fallaba, la excepción se tragaba y quedaban DOS
-- secciones 'active' para la misma sesión (huérfana + nueva), sin ningún
-- constraint de DB que lo impidiera.
--
-- Esta función hace ambos pasos en una sola transacción: todo o nada.
-- security invoker (default) para respetar RLS igual que cualquier query
-- normal del usuario — nada de bypass de permisos.
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
    set section_status = 'closed',
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

grant execute on function public.switch_gig_app_section(
  uuid, uuid, uuid, text, text, double precision, integer, double precision, double precision
) to authenticated;

-- Candado a nivel de schema: sin importar qué código lo escriba, nunca
-- puede haber dos secciones active/paused para la misma sesión. Protege
-- también el insert directo que usa startTripFlow (primera sección de un
-- viaje), no solo el switch.
create unique index if not exists uq_session_sections_one_open_per_session
on public.session_sections (session_id)
where section_status in ('active', 'paused');
