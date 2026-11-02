-- Odometer evidence: annual cycle for everyone (explicit user request, 2026-11-01).
--
-- Two photos a year for every Gig driver: one when the car is added / the year
-- starts, one at year end. As with the other cycles, the "end" photo of a year
-- is the first photo of the next one (the roll-forward that
-- submit_vehicle_odometer_checkpoint already does).
--
--   annual       -> default for NEW personal vehicles (the app sends it)   free
--   monthly      -> 1st of each month                                       free
--   semimonthly  -> 1st and 15th                                            Premium
--   weekly/biweekly -> Fleet organisation vehicles; for personal vehicles
--                      only the legacy default on INSERT is still accepted,
--                      switching to it later needs Premium                  Premium
--   daily        -> reserved, not offered in the app yet                    Premium
--
-- Existing vehicles keep their current cycle (nothing is rewritten here).
--
-- In an annual year ANY checkpoint of that calendar year counts as the year's
-- photo: a vehicle that already has readings dated e.g. 2026-10-01 (monthly
-- before) must not be asked for a "start of year" photo again.

-- 1. New values.
alter table public.vehicles drop constraint if exists vehicles_odometer_cycle_check;
alter table public.vehicles add constraint vehicles_odometer_cycle_check
  check (odometer_cycle in ('weekly', 'biweekly', 'monthly', 'semimonthly', 'annual', 'daily'));

-- 2. Period math.
create or replace function public.fn_odometer_period_start(
  p_cycle text, p_date date, p_anchor date
) returns date
language sql
stable
set search_path to 'public'
as $fn$
  select case p_cycle
    when 'annual' then date_trunc('year', p_date)::date
    when 'daily' then p_date
    when 'monthly' then date_trunc('month', p_date)::date
    when 'semimonthly' then
      case when extract(day from p_date) >= 15
           then date_trunc('month', p_date)::date + 14
           else date_trunc('month', p_date)::date end
    when 'weekly' then p_date - (extract(isodow from p_date)::int - 1)
    else
      (p_anchor - (extract(isodow from p_anchor)::int - 1))
      + (floor(
          ((p_date - (extract(isodow from p_date)::int - 1))
           - (p_anchor - (extract(isodow from p_anchor)::int - 1))) / 14.0
        )::int * 14)
  end
$fn$;

-- 3. Tier gate. Fleet organisation vehicles are never gated here.
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

  if new.odometer_cycle in ('annual', 'monthly') then
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

-- 4. Checkpoint RPC: same as 20261030024841, plus the annual rule.
create or replace function public.submit_vehicle_odometer_checkpoint(
  p_vehicle_id uuid,
  p_odometer_value numeric,
  p_odometer_image_url text,
  p_file_hash text default null,
  p_ocr_source boolean default false,
  p_ocr_confidence numeric default null,
  p_capture_date date default (timezone('utc', now()))::date
) returns vehicle_odometer_checkpoints
language plpgsql
security definer
set search_path to 'public'
as $fn$
declare
  v_vehicle record;
  v_caller uuid := auth.uid();
  v_week_start date;
  v_year_row_start date;
  v_prev_open record;
  v_prev_open_found boolean;
  v_current record;
  v_result public.vehicle_odometer_checkpoints;
begin
  if v_caller is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  if p_odometer_value is null or p_odometer_value < 0 then
    raise exception 'INVALID_ODOMETER_VALUE';
  end if;

  if p_capture_date is null
     or abs(p_capture_date - (timezone('utc', now()))::date) > 1 then
    raise exception 'INVALID_CAPTURE_DATE';
  end if;

  select * into v_vehicle from public.vehicles where id = p_vehicle_id;
  if v_vehicle is null then
    raise exception 'VEHICLE_NOT_FOUND';
  end if;

  if not (
    v_vehicle.owner_user_id = v_caller
    or v_vehicle.assigned_driver_id = v_caller
    or (v_vehicle.organization_id is not null and public.is_org_member(v_vehicle.organization_id))
  ) then
    raise exception 'NOT_AUTHORIZED';
  end if;

  if v_vehicle.odometer is not null and p_odometer_value < v_vehicle.odometer then
    raise exception 'ODOMETER_BELOW_REGISTERED:%', v_vehicle.odometer;
  end if;

  v_week_start := public.fn_odometer_cycle_start(p_vehicle_id, p_capture_date);

  -- Annual: any checkpoint already in this calendar year IS this year's row
  -- (the latest one), whatever date it carries.
  if v_vehicle.odometer_cycle = 'annual' then
    select week_start_date into v_year_row_start
    from public.vehicle_odometer_checkpoints
    where vehicle_id = p_vehicle_id
      and week_start_date >= date_trunc('year', p_capture_date)::date
      and week_start_date < (date_trunc('year', p_capture_date) + interval '1 year')::date
    order by week_start_date desc
    limit 1;
    if found then
      v_week_start := v_year_row_start;
    end if;
  end if;

  select * into v_prev_open
  from public.vehicle_odometer_checkpoints
  where vehicle_id = p_vehicle_id
    and week_start_date < v_week_start
    and start_odometer_value is not null
    and end_odometer_value is null
  order by week_start_date desc
  limit 1;
  v_prev_open_found := found;

  if v_prev_open_found then
    update public.vehicle_odometer_checkpoints
    set end_odometer_value = p_odometer_value,
        end_odometer_image_url = p_odometer_image_url,
        end_file_hash = p_file_hash,
        end_captured_by = v_caller,
        end_captured_at = now(),
        end_ocr_source = p_ocr_source,
        end_ocr_confidence = p_ocr_confidence,
        updated_at = now()
    where id = v_prev_open.id;
  end if;

  select * into v_current
  from public.vehicle_odometer_checkpoints
  where vehicle_id = p_vehicle_id and week_start_date = v_week_start;

  if v_current is null then
    insert into public.vehicle_odometer_checkpoints (
      vehicle_id, organization_id, week_start_date,
      start_odometer_value, start_odometer_image_url, start_file_hash,
      start_captured_by, start_captured_at, start_ocr_source, start_ocr_confidence
    ) values (
      p_vehicle_id, v_vehicle.organization_id, v_week_start,
      p_odometer_value, p_odometer_image_url, p_file_hash,
      v_caller, now(), p_ocr_source, p_ocr_confidence
    )
    returning * into v_result;
  elsif v_current.start_odometer_value is null then
    update public.vehicle_odometer_checkpoints
    set start_odometer_value = p_odometer_value,
        start_odometer_image_url = p_odometer_image_url,
        start_file_hash = p_file_hash,
        start_captured_by = v_caller,
        start_captured_at = now(),
        start_ocr_source = p_ocr_source,
        start_ocr_confidence = p_ocr_confidence,
        updated_at = now()
    where id = v_current.id
    returning * into v_result;
  elsif v_current.end_odometer_value is null then
    update public.vehicle_odometer_checkpoints
    set end_odometer_value = p_odometer_value,
        end_odometer_image_url = p_odometer_image_url,
        end_file_hash = p_file_hash,
        end_captured_by = v_caller,
        end_captured_at = now(),
        end_ocr_source = p_ocr_source,
        end_ocr_confidence = p_ocr_confidence,
        updated_at = now()
    where id = v_current.id
    returning * into v_result;
  else
    raise exception 'WEEK_ALREADY_CLOSED';
  end if;

  update public.vehicles
  set odometer = greatest(coalesce(odometer, 0), p_odometer_value),
      updated_at = now()
  where id = p_vehicle_id;

  return v_result;
end;
$fn$;
