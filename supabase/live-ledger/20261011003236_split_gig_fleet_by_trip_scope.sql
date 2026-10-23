create or replace function public.fn_enforce_trial_or_subscription()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_created_at timestamptz;
  v_base boolean;
  v_premium boolean;
  v_exempt boolean;
begin
  -- Fleet trip: membership is checked by tr_sessions_enforce_active_org_membership.
  if new.organization_id is not null then
    return new;
  end if;

  select created_at, base_entitled, premium_entitled, tier_enforcement_exempt
    into v_created_at, v_base, v_premium, v_exempt
    from public.profiles
    where id = new.user_id;

  if v_exempt is true then
    return new;
  end if;

  if v_base is true or v_premium is true then
    return new;
  end if;

  if v_created_at is not null and now() - v_created_at > interval '15 days' then
    raise exception 'FREE_TRIAL_EXPIRED';
  end if;

  return new;
end;
$$;

create or replace function public.fn_enforce_vehicle_count_limit()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_base boolean;
  v_premium boolean;
  v_exempt boolean;
  v_max int;
  v_current_count int;
begin
  -- Fleet vehicles (including a driver-owned truck registered with a fleet)
  -- don't count against the personal plan.
  if new.owner_user_id is null or new.organization_id is not null then
    return new;
  end if;

  select base_entitled, premium_entitled, tier_enforcement_exempt
    into v_base, v_premium, v_exempt
    from public.profiles
    where id = new.owner_user_id;

  if v_exempt is true then
    return new;
  end if;

  v_max := case when v_premium is true then 5 else 1 end;

  select count(*) into v_current_count
  from public.vehicles
  where owner_user_id = new.owner_user_id
    and organization_id is null
    and is_archived = false;

  if v_current_count >= v_max then
    raise exception 'VEHICLE_LIMIT_REACHED:%', v_max;
  end if;

  return new;
end;
$$;

create or replace function public.fn_block_cross_app_open_trip()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if new.is_closed is distinct from true and exists (
    select 1 from public.sessions s
    where s.user_id = new.user_id
      and s.is_closed is distinct from true
      and s.id <> new.id
      and (s.organization_id is null) <> (new.organization_id is null)
  ) then
    if new.organization_id is null then
      raise exception 'ACTIVE_FLEET_TRIP';
    else
      raise exception 'ACTIVE_PERSONAL_TRIP';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists tr_sessions_block_cross_app_open_trip on public.sessions;
create trigger tr_sessions_block_cross_app_open_trip
  before insert on public.sessions
  for each row execute function public.fn_block_cross_app_open_trip();
