create or replace function public.get_trip_map(p_session_id uuid, p_token uuid)
returns jsonb
language sql
stable
security definer
set search_path to 'public'
as $$
  select jsonb_build_object(
    'closed', coalesce(s.is_closed, false)
      and (not exists (select 1 from public.session_sections x
                        where x.session_id = s.id and x.route_polyline is null)
           or coalesce(s.end_time, s.updated_at) < now() - interval '1 hour'),
    'sections', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', ss.id,
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
