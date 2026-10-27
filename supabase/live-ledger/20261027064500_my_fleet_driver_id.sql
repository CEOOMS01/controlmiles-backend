-- The invite success page tells a new driver the user ID they sign in with. Drivers cannot
-- read fleet_driver_slots (admin-only policies), so the page never showed it. This returns
-- only the caller's own ID. (Applied to production 2026-10-27 as 'my_fleet_driver_id'.)
create or replace function public.my_fleet_driver_id()
returns text
language sql
stable
security definer
set search_path to 'public'
as $$
  select s.display_id
    from public.fleet_driver_slots s
   where s.claimed_by = auth.uid()
   order by s.claimed_at desc nulls last
   limit 1;
$$;
revoke execute on function public.my_fleet_driver_id() from public, anon;
grant execute on function public.my_fleet_driver_id() to authenticated;
