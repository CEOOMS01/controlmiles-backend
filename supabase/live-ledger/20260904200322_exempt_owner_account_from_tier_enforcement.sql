-- Explicit user requirement (2026-09-04): the owner's own dev/test
-- account must stay exempt from the new tier enforcement (trial expiry,
-- vehicle count, PDF export limit) that everyone else gets -- a dedicated
-- flag rather than hardcoding the UUID inline in 3 different functions,
-- so future exempt accounts (another admin, a QA account) are a one-row
-- UPDATE, not a code change.
alter table public.profiles
  add column if not exists tier_enforcement_exempt boolean not null default false;

update public.profiles
  set tier_enforcement_exempt = true
  where email = 'alsoler26@gmail.com';

-- Re-create all 3 enforcement points to check the exemption first.

create or replace function public.fn_enforce_trial_or_subscription()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_created_at timestamptz;
  v_base boolean;
  v_premium boolean;
  v_account_type text;
  v_exempt boolean;
begin
  select created_at, base_entitled, premium_entitled, account_type, tier_enforcement_exempt
    into v_created_at, v_base, v_premium, v_account_type, v_exempt
    from public.profiles
    where id = new.user_id;

  if v_exempt is true then
    return new;
  end if;

  if v_account_type is distinct from 'gig' then
    return new;
  end if;

  if v_base is true or v_premium is true then
    return new;
  end if;

  if v_created_at is not null and now() - v_created_at > interval '30 days' then
    raise exception 'FREE_TRIAL_EXPIRED';
  end if;

  return new;
end;
$$;

create or replace function public.fn_enforce_vehicle_count_limit()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
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

  if v_premium is true then
    return new;
  end if;

  v_max := case when v_base is true then 2 else 1 end;

  select count(*) into v_current_count
  from public.vehicles
  where owner_user_id = new.owner_user_id
    and is_archived = false;

  if v_current_count >= v_max then
    raise exception 'VEHICLE_LIMIT_REACHED:%', v_max;
  end if;

  return new;
end;
$$;

create or replace function public.check_and_log_pdf_export()
returns table(allowed boolean, exports_this_month int, monthly_limit int)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller uuid := auth.uid();
  v_base boolean;
  v_premium boolean;
  v_exempt boolean;
  v_month_start timestamptz;
  v_count int;
begin
  if v_caller is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  select base_entitled, premium_entitled, tier_enforcement_exempt
    into v_base, v_premium, v_exempt
    from public.profiles where id = v_caller;

  if v_premium is true or v_exempt is true then
    insert into public.pdf_export_log (user_id) values (v_caller);
    return query select true, null::int, null::int;
    return;
  end if;

  v_month_start := date_trunc('month', now());

  select count(*) into v_count
  from public.pdf_export_log
  where user_id = v_caller and exported_at >= v_month_start;

  if v_count >= 2 then
    return query select false, v_count, 2;
    return;
  end if;

  insert into public.pdf_export_log (user_id) values (v_caller);
  return query select true, v_count + 1, 2;
end;
$$;
