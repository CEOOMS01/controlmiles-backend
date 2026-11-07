-- Applied 2026-11-07. Gig history lock, one open personal trip, one-mile minimum in every mode.
-- Amplía reglas que ya existen; no crea funciones ni triggers nuevos.

-- 1. Un solo viaje personal abierto por usuario. fn_block_cross_app_open_trip sigue
--    separando Gig de Fleet; esto cierra la carrera entre motores, que un trigger no puede.
create unique index if not exists uq_sessions_one_open_personal_trip
  on public.sessions (user_id)
  where organization_id is null and is_closed is not true;

-- 2. Congelar también los tramos cerrados por switch, y dejar los tramos gig
--    personales sin edición. Borrar sigue permitido: este trigger es solo BEFORE UPDATE.
create or replace function public.fn_freeze_closed_session_section()
returns trigger
language plpgsql
set search_path to 'public'
as $$
begin
  if OLD.section_status in ('closed', 'switched') then
    if NEW.total_miles is distinct from OLD.total_miles
      or NEW.total_duration_seconds is distinct from OLD.total_duration_seconds
      or NEW.start_time is distinct from OLD.start_time
      or NEW.end_time is distinct from OLD.end_time
      or NEW.gig_app is distinct from OLD.gig_app
      or NEW.start_latitude is distinct from OLD.start_latitude
      or NEW.start_longitude is distinct from OLD.start_longitude
      or NEW.end_latitude is distinct from OLD.end_latitude
      or NEW.end_longitude is distinct from OLD.end_longitude
      or NEW.session_id is distinct from OLD.session_id
      or NEW.user_id is distinct from OLD.user_id
      or NEW.organization_id is distinct from OLD.organization_id
      or (OLD.route_polyline is not null and NEW.route_polyline is distinct from OLD.route_polyline)
    then
      raise exception 'Cannot modify a closed trip section''s recorded data';
    end if;
    -- Gig history: the phone may fill an empty address once, and the driver may correct
    -- where the trip ended (its last segment, the only one left 'closed'). Nothing else.
    if OLD.organization_id is null and OLD.gig_app <> 'custom' and (
      NEW.irs_purpose is distinct from OLD.irs_purpose
      or NEW.notes is distinct from OLD.notes
      or (OLD.start_address is not null and NEW.start_address is distinct from OLD.start_address)
      or (OLD.section_status = 'switched' and (
        NEW.address_edited is distinct from OLD.address_edited
        or (OLD.end_address is not null and NEW.end_address is distinct from OLD.end_address)
      ))
    ) then
      raise exception 'Gig trip history cannot be edited';
    end if;
  end if;
  return NEW;
end;
$$;

-- 3. Ningún viaje de menos de 1 milla se guarda, en General, Apps ni Fleet. Solo aplica
--    a viajes que cierren desde ahora.
create or replace function public.fn_discard_zero_mile_trip()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if coalesce(new.total_miles, 0) < 1
     and coalesce((select sum(ss.total_miles) from public.session_sections ss
                   where ss.session_id = new.id), 0) < 1 then
    delete from public.sessions where id = new.id;
  else
    perform public.fn_fold_empty_trip_sections(new.id);
  end if;
  return null;
end;
$$;

-- 4. Nadie agrega tramos a un viaje ya cerrado.
create or replace function public.fn_inherit_session_tenant()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  s record;
begin
  select user_id, organization_id, is_closed into s from public.sessions where id = new.session_id;
  if not found or s.user_id is distinct from new.user_id then
    raise exception 'TRIP_NOT_YOURS' using errcode = 'P0001';
  end if;
  if tg_op = 'INSERT' and s.is_closed is true then
    raise exception 'TRIP_ALREADY_CLOSED' using errcode = 'P0001';
  end if;
  new.organization_id := s.organization_id;
  return new;
end $$;
