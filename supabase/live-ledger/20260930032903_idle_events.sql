CREATE OR REPLACE FUNCTION public.compute_idle_events(
  p_organization_id uuid,
  p_start_date date,
  p_end_date date
)
RETURNS TABLE(
  session_id uuid,
  vehicle_id uuid,
  user_id uuid,
  started_at timestamptz,
  minutes double precision,
  latitude double precision,
  longitude double precision,
  kind text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'Not authorized for this organization';
  end if;

  return query
  with o as (
    select
      b.session_id as sid, b.section_id as sec, b.vehicle_id as vid, b.user_id as uid,
      b.recorded_at, b.latitude as lat, b.longitude as lng,
      lag(b.recorded_at) over w as prev_at,
      lag(b.latitude) over w as prev_lat,
      lag(b.longitude) over w as prev_lng,
      lag(b.section_id) over w as prev_sec
    from public.session_gps_breadcrumbs b
    where b.organization_id = p_organization_id
      and b.recorded_at >= p_start_date::timestamptz
      and b.recorded_at < (p_end_date + 1)::timestamptz
    window w as (partition by b.session_id order by b.recorded_at)
  ),
  stops as (
    select
      o.sid, o.vid, o.uid, o.prev_at, o.prev_lat, o.prev_lng,
      (extract(epoch from o.recorded_at - o.prev_at) - 60) / 60.0 as mins
    from o
    where o.prev_at is not null
      and o.sec is not distinct from o.prev_sec
      and o.recorded_at - o.prev_at >= interval '4 minutes'
      and ST_DistanceSphere(ST_MakePoint(o.lng, o.lat), ST_MakePoint(o.prev_lng, o.prev_lat)) <= 200
  )
  select s.sid, s.vid, s.uid, s.prev_at, s.mins::double precision, s.prev_lat, s.prev_lng,
         case when s.mins >= 60 then 'long_stop' else 'idle' end
  from stops s
  where s.mins >= 3
  order by s.prev_at;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.compute_idle_events(uuid, date, date) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.compute_idle_events(uuid, date, date) TO authenticated;
