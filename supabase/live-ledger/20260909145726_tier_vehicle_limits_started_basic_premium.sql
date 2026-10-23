-- Explicit user requirement (2026-09-09): three-tier division --
-- Started (the existing 30-day free trial, no new state needed -- see
-- fn_enforce_trial_or_subscription, already exactly this), Basic
-- (base_entitled), Premium (premium_entitled). Vehicle caps: Started and
-- Basic get 1 vehicle each (was 2 for Basic), Premium gets 5 (was
-- unlimited). Real gap closed here: Premium had NO cap at all before this
-- (the trigger returned immediately on v_premium=true) -- inconsistent
-- with the user's explicit "premium 5" requirement and with treating
-- Premium as a bounded tier rather than unlimited.

create or replace function public.fn_enforce_vehicle_count_limit()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_base boolean;
  v_premium boolean;
  v_account_type text;
  v_exempt boolean;
  v_max int;
  v_current_count int;
begin
  select base_entitled, premium_entitled, account_type, tier_enforcement_exempt
    into v_base, v_premium, v_account_type, v_exempt
    from public.profiles
    where id = new.owner_user_id;

  if v_exempt is true then
    return new;
  end if;

  if new.owner_user_id is null or v_account_type is distinct from 'gig' then
    return new;
  end if;

  v_max := case when v_premium is true then 5 else 1 end;

  select count(*) into v_current_count
  from public.vehicles
  where owner_user_id = new.owner_user_id
    and is_archived = false;

  if v_current_count >= v_max then
    raise exception 'VEHICLE_LIMIT_REACHED:%', v_max;
  end if;

  return new;
end;
$function$;
