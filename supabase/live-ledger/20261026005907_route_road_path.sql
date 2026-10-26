-- Road path of a school route (2026-10-25). The stops of a route are joined by
-- the real road path computed by OUR OWN routing server (Valhalla, see
-- infra/valhalla), once when the stops are saved, and stored here: the map only
-- reads it. Planned path only; the GPS trail of a trip is a different thing.
-- Student homes are the stops, so the routing server is ours and nothing about
-- them goes to a third party. Additive: nothing existing changes.
alter table public.routes
  add column if not exists path_polyline text check (path_polyline is null or char_length(path_polyline) <= 250000),
  add column if not exists path_distance_m integer check (path_distance_m is null or path_distance_m >= 0),
  add column if not exists path_duration_s integer check (path_duration_s is null or path_duration_s >= 0),
  add column if not exists path_computed_at timestamptz,
  add column if not exists path_signature text;

alter table public.route_stops
  add column if not exists leg_distance_m integer check (leg_distance_m is null or leg_distance_m >= 0),
  add column if not exists leg_duration_s integer check (leg_duration_s is null or leg_duration_s >= 0);

comment on column public.routes.path_polyline is 'Road path through the route stops in order, Valhalla polyline6 (computed by our own routing server when the stops are saved; null when not computed). Planned path only, never a GPS trail.';
comment on column public.routes.path_signature is 'Hash of the stops (order and coordinates) the path was computed for, to know when it is stale.';
comment on column public.route_stops.leg_duration_s is 'Driving seconds from the previous stop (null for the first stop or when the path is not computed).';
