-- Gig: fixed Premium for the owner's and the testers' accounts (2026-11-19, owner request).
--
-- Google Play license-testing purchases are cancelled by Google after about 6 accelerated renewals (a "month" is
-- 5 minutes, a "year" 30 minutes), so every tester lost the plan within an hour. profiles.premium_override keeps
-- Premium on for those accounts no matter what Google says; recompute_personal_entitlements() now honours it.
-- Only the service role / SQL can set it (guarded like the other entitlement columns).

alter table public.profiles add column if not exists premium_override boolean not null default false;

create or replace function public.fn_guard_profile_protected_columns() returns trigger
language plpgsql set search_path = public as $$
begin
  if current_user in ('authenticated', 'anon') then
    if new.id                     is distinct from old.id
       or new.display_id          is distinct from old.display_id
       or new.email               is distinct from old.email
       or new.account_type        is distinct from old.account_type
       or new.is_active           is distinct from old.is_active
       or new.default_org_id      is distinct from old.default_org_id
       or new.base_entitled       is distinct from old.base_entitled
       or new.premium_entitled    is distinct from old.premium_entitled
       or new.premium_override    is distinct from old.premium_override
       or new.multi_org_entitled  is distinct from old.multi_org_entitled
       or new.tier_enforcement_exempt is distinct from old.tier_enforcement_exempt
       or new.created_at          is distinct from old.created_at
       or new.legal_accepted_at   is distinct from old.legal_accepted_at
       or new.legal_terms_version is distinct from old.legal_terms_version
    then
      raise exception 'PROTECTED_PROFILE_COLUMN: this field cannot be changed directly';
    end if;
  end if;
  return new;
end;
$$;

create or replace function public.recompute_personal_entitlements(p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_base boolean;
  v_premium boolean;
  v_override boolean;
begin
  select coalesce(premium_override, false) into v_override from public.profiles where id = p_user;

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
     set base_entitled = coalesce(v_base, false) or v_override,
         premium_entitled = coalesce(v_premium, false) or v_override
   where id = p_user;

  -- Weekly and monthly photos are a Premium choice: without Premium, back to annual.
  if not (coalesce(v_premium, false) or v_override) then
    update public.vehicles v
       set odometer_cycle = 'annual'
     where v.owner_user_id = p_user
       and v.organization_id is null
       and v.odometer_cycle <> 'annual'
       and not exists (select 1 from public.profiles p where p.id = p_user and p.tier_enforcement_exempt);
  end if;
end;
$$;

-- The owner's accounts and the testers who bought through Google Play license testing.
update public.profiles set premium_override = true
 where id in (
   '4594289a-9b7e-4b2b-a177-b9eab3c3525c', -- CM-Q233028 (owner)
   '275d9bb0-ef55-4b01-9116-b91c802dc4bc', -- CM-T615543 (owner, second account)
   '0cb5b290-4ccb-46ee-a912-c052ad8faf43', -- CM-E802323 (tester)
   '8b463fef-d7c9-446d-80f5-e47ad895079f', -- CM-M276281 (tester)
   '90f960bd-aca2-43e7-8c61-5b8c781e9c4b', -- CM-N264610 (tester)
   '4c32f84a-5b8b-4ffd-86c6-210bb52f5fbb'  -- CM-T486475 (tester)
 );

do $$
declare r record;
begin
  for r in select id from public.profiles where premium_override loop
    perform public.recompute_personal_entitlements(r.id);
  end loop;
end $$;
