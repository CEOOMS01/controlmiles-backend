-- Gig odometer rule: two photos a year on every plan. Only Premium may change the cycle,
-- and losing Premium goes back to annual. Fleet keeps its own rules (organization_id set).

create or replace function public.fn_enforce_odometer_cycle_tier()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_premium boolean;
  v_exempt boolean;
begin
  if new.organization_id is not null then
    return new;
  end if;

  -- Natively annual, whatever the plan: Premium changes it afterwards.
  if tg_op = 'INSERT' then
    new.odometer_cycle := 'annual';
    return new;
  end if;

  if new.odometer_cycle = 'annual' or new.odometer_cycle is not distinct from old.odometer_cycle then
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
$$;

-- The old WHEN skipped 'weekly', so anyone could choose it.
drop trigger tr_vehicles_enforce_odometer_cycle_tier on public.vehicles;
create trigger tr_vehicles_enforce_odometer_cycle_tier
  before insert or update of odometer_cycle on public.vehicles
  for each row when (new.organization_id is null)
  execute function public.fn_enforce_odometer_cycle_tier();

create or replace function public.recompute_personal_entitlements(p_user uuid)
returns void
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_base boolean;
  v_premium boolean;
begin
  with sources as (
    select tier from public.play_subscriptions
     where user_id = p_user
       and expiry_time > now()
       and state in ('SUBSCRIPTION_STATE_ACTIVE',
                     'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                     'SUBSCRIPTION_STATE_CANCELED')
    union all
    select coalesce(tier, 'premium') from public.subscriptions
     where user_id = p_user
       and status in ('active', 'trialing')
       and (current_period_end is null or current_period_end > now())
  )
  select count(*) > 0, bool_or(tier = 'premium')
    into v_base, v_premium
    from sources;

  update public.profiles
     set base_entitled = coalesce(v_base, false),
         premium_entitled = coalesce(v_premium, false)
   where id = p_user;

  -- Weekly and monthly photos are a Premium choice: without Premium, back to annual.
  if not coalesce(v_premium, false) then
    update public.vehicles v
       set odometer_cycle = 'annual'
     where v.owner_user_id = p_user
       and v.organization_id is null
       and v.odometer_cycle <> 'annual'
       and not exists (select 1 from public.profiles p where p.id = p_user and p.tier_enforcement_exempt);
  end if;
end;
$$;

update public.vehicles v
   set odometer_cycle = 'annual'
  from public.profiles p
 where p.id = v.owner_user_id
   and v.organization_id is null
   and v.odometer_cycle <> 'annual'
   and not p.premium_entitled
   and not p.tier_enforcement_exempt;
