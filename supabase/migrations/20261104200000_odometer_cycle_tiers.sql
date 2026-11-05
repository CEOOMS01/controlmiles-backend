-- Olympus Mont Systems LLC - ControlMiles (Gig)
-- Odometer cycle tiers (2026-11-04, explicit decision):
--   annual       -> every personal account (the default for new vehicles)
--   monthly      -> Premium, optional
--   semimonthly  -> Premium, optional (the 1st and the 15th)
-- Until now monthly was free for everyone. Vehicles that already run on a
-- monthly cycle keep it: the check only looks at a CHANGE of the cycle, so an
-- update that leaves the value as it is never fails.

create or replace function public.fn_enforce_odometer_cycle_tier()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $fn$
declare
  v_premium boolean;
  v_exempt boolean;
begin
  if new.organization_id is not null then
    return new;
  end if;

  if new.odometer_cycle = 'annual' then
    return new;
  end if;

  -- Not a change: leave a vehicle on the cycle it already has.
  if tg_op = 'UPDATE' and new.odometer_cycle is not distinct from old.odometer_cycle then
    return new;
  end if;

  -- Older app versions insert without a cycle, so the column default
  -- ('weekly') arrives here. Keep accepting that on INSERT only.
  if tg_op = 'INSERT' and new.odometer_cycle = 'weekly' then
    return new;
  end if;

  select premium_entitled, tier_enforcement_exempt
    into v_premium, v_exempt
    from public.profiles
    where id = new.owner_user_id;

  if coalesce(v_exempt, false) or coalesce(v_premium, false) then
    return new;
  end if;

  raise exception 'PREMIUM_REQUIRED_FOR_ODOMETER_CYCLE';
end;
$fn$;
