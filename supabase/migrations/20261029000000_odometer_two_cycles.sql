-- Odometer evidence: two calendar-based cycles (explicit user request, 2026-10-29).
--
-- Gig drivers used to photograph the odometer weekly (Mon-Sun, start + forced
-- close) with biweekly/monthly as a Premium option. Now there are two cycles,
-- both tied to the calendar:
--   monthly      -> one reading on the 1st of each month
--   semimonthly  -> one reading on the 1st and one on the 15th (Premium)
-- The first reading of a period also closes the previous open period (the
-- roll-forward that submit_vehicle_odometer_checkpoint already did), so the
-- "end" photo of a period is simply the first photo of the next one.
--
-- 'weekly' and 'biweekly' stay valid values: Fleet organisation vehicles still
-- use them and the 6 existing personal rows below are moved off weekly.

-- 1. New value.
alter table public.vehicles drop constraint if exists vehicles_odometer_cycle_check;
alter table public.vehicles add constraint vehicles_odometer_cycle_check
  check (odometer_cycle in ('weekly', 'biweekly', 'monthly', 'semimonthly'));

-- 2. Pure period math, separated so it can be tested without a signed-in user.
create or replace function public.fn_odometer_period_start(
  p_cycle text, p_date date, p_anchor date
) returns date
language sql
stable
set search_path to 'public'
as $fn$
  select case p_cycle
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

revoke execute on function public.fn_odometer_period_start(text, date, date) from public;
revoke execute on function public.fn_odometer_period_start(text, date, date) from anon;
grant execute on function public.fn_odometer_period_start(text, date, date) to authenticated;

create or replace function public.fn_odometer_cycle_start(p_vehicle_id uuid, p_date date)
returns date
language plpgsql
stable security definer
set search_path to 'public'
as $fn$
declare
  v_vehicle record;
  v_anchor date;
begin
  select * into v_vehicle from public.vehicles where id = p_vehicle_id;
  if v_vehicle is null then
    return null;
  end if;

  if v_vehicle.owner_user_id is distinct from auth.uid()
     and v_vehicle.assigned_driver_id is distinct from auth.uid()
     and not (v_vehicle.organization_id is not null and public.is_org_member(v_vehicle.organization_id))
  then
    return null;
  end if;

  v_anchor := coalesce(
    v_vehicle.odometer_cycle_anchor,
    (v_vehicle.created_at::date) - (extract(isodow from v_vehicle.created_at::date)::int - 1)
  );

  return public.fn_odometer_period_start(
    coalesce(v_vehicle.odometer_cycle, 'weekly'), p_date, v_anchor
  );
end;
$fn$;

-- 3. Tier gate: monthly is for everyone, semimonthly (and the legacy biweekly)
--    is Premium. 'weekly' stays allowed so existing Fleet rows keep working.
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
  if new.odometer_cycle in ('weekly', 'monthly') or new.organization_id is not null then
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

-- 4. Personal (non-organisation) vehicles leave the weekly cycle.
update public.vehicles
set odometer_cycle = case odometer_cycle when 'biweekly' then 'semimonthly' else 'monthly' end
where organization_id is null
  and odometer_cycle in ('weekly', 'biweekly');

-- 5. The client now sends its own calendar date (a driver at 8 pm on the 14th
--    in the US is already on the 15th in UTC). Accept it only within one day
--    of the server's UTC date so it cannot be used to back-date evidence.
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

-- 6. OCR feedback (training data for the odometer reader): what the camera read
--    vs. what the driver finally confirmed. Numbers only, never the photo.
create table if not exists public.odometer_ocr_feedback (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  vehicle_id uuid references public.vehicles(id) on delete set null,
  ocr_value numeric,
  ocr_confidence numeric,
  final_value numeric not null,
  was_edited boolean not null,
  created_at timestamptz not null default now()
);

alter table public.odometer_ocr_feedback enable row level security;

create policy odometer_ocr_feedback_insert_own on public.odometer_ocr_feedback
  for insert to authenticated
  with check (user_id = auth.uid());

create policy odometer_ocr_feedback_select_own on public.odometer_ocr_feedback
  for select to authenticated
  using (user_id = auth.uid());
