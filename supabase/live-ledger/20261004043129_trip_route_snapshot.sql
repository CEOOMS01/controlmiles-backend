alter table public.session_sections add column if not exists route_polyline text;
alter table public.session_sections drop constraint if exists session_sections_route_polyline_len;
alter table public.session_sections add constraint session_sections_route_polyline_len
  check (route_polyline is null or length(route_polyline) <= 20000);

alter table public.sessions add column if not exists map_token uuid not null default gen_random_uuid();

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
      or NEW.irs_purpose is distinct from OLD.irs_purpose
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
  end if;
  return NEW;
end;
$$;

create or replace function public.get_trip_map(p_session_id uuid, p_token uuid)
returns jsonb
language sql
stable
security definer
set search_path to 'public'
as $$
  select jsonb_build_object(
    'closed', coalesce(s.is_closed, false),
    'sections', coalesce((
      select jsonb_agg(jsonb_build_object(
        'gig_app', ss.gig_app,
        'polyline', ss.route_polyline,
        'points', case when ss.route_polyline is null then (
            select jsonb_agg(jsonb_build_array(round(b.latitude::numeric, 5), round(b.longitude::numeric, 5))
                             order by b.recorded_at)
              from public.session_gps_breadcrumbs b
             where b.section_id = ss.id
          ) end,
        'start', case when ss.start_latitude is not null
          then jsonb_build_array(ss.start_latitude, ss.start_longitude) end,
        'end', case when ss.end_latitude is not null
          then jsonb_build_array(ss.end_latitude, ss.end_longitude) end
      ) order by ss.start_time)
      from public.session_sections ss
      where ss.session_id = s.id
    ), '[]'::jsonb)
  )
  from public.sessions s
  where s.id = p_session_id and s.map_token = p_token;
$$;

revoke execute on function public.get_trip_map(uuid, uuid) from public;
grant execute on function public.get_trip_map(uuid, uuid) to anon, authenticated;
