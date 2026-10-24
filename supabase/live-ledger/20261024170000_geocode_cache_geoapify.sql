-- Geoapify becomes the place-search fallback (schools, stops; never students' homes).
alter table public.geocode_cache drop constraint if exists geocode_cache_provider_check;
alter table public.geocode_cache add constraint geocode_cache_provider_check
  check (provider in ('census', 'nominatim', 'geoapify'));
