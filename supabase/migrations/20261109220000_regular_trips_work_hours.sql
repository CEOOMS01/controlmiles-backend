-- Regular Trips and Work Hours (2026-11-09): General trips classify themselves when
-- they close. A regular trip matches by route, Work Hours by the time the trip
-- started, and a regular trip always wins (home to work inside work hours stays
-- whatever the driver said: commuting is personal for the IRS).
--
-- Classified in the database so it works however the trip closed (app open, app
-- closed, phone's own auto-close). Premium only; gig-app trips are never touched
-- (they are Business). With no regular trips and Work Hours off, nothing changes.

insert into ops.domain_tables (tbl, domain) values
  ('regular_trips', 'gig'),
  ('trip_classification_settings', 'gig');
insert into ops.domain_triggers (tbl, tg, domain, guard) values
  ('session_sections', 'trg_classify_section_on_close', 'gig', 'organization_id IS NULL');

alter table public.session_sections
  add column if not exists auto_purpose_source text
  check (auto_purpose_source in ('regular_trip', 'work_hours'));

create table if not exists public.regular_trips (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  start_any boolean not null default false,
  start_latitude double precision,
  start_longitude double precision,
  start_address text check (char_length(start_address) <= 300),
  end_latitude double precision not null,
  end_longitude double precision not null,
  end_address text check (char_length(end_address) <= 300),
  purpose text not null check (purpose in (
    'business', 'delivery', 'errand', 'client', 'travel',
    'work', 'medical', 'charitable', 'moving', 'education', 'personal'
  )),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (start_any or (start_latitude is not null and start_longitude is not null))
);
create index if not exists regular_trips_user_idx on public.regular_trips (user_id);

create table if not exists public.trip_classification_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  regular_enabled boolean not null default true,
  suggestions_enabled boolean not null default true,
  work_hours_inside boolean not null default false,
  work_hours_outside boolean not null default false,
  work_days integer[] not null default '{1,2,3,4,5}',
  work_start_minute integer not null default 540 check (work_start_minute between 0 and 1439),
  work_end_minute integer not null default 1080 check (work_end_minute between 0 and 1440),
  time_zone text not null default 'America/New_York' check (char_length(time_zone) <= 64),
  updated_at timestamptz not null default now()
);

alter table public.regular_trips enable row level security;
alter table public.trip_classification_settings enable row level security;

create policy regular_trips_own on public.regular_trips
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy trip_classification_settings_own on public.trip_classification_settings
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

revoke all on public.regular_trips from anon;
revoke all on public.trip_classification_settings from anon;

create trigger tr_regular_trips_touch_updated_at
  before update on public.regular_trips
  for each row execute function public.fn_touch_updated_at();
create trigger tr_trip_classification_settings_touch_updated_at
  before update on public.trip_classification_settings
  for each row execute function public.fn_touch_updated_at();

-- Meters between two points.
create or replace function public.fn_cm_distance_m(lat1 double precision, lng1 double precision, lat2 double precision, lng2 double precision)
returns double precision
language sql immutable
set search_path to 'public'
as $$
  select 6371000 * 2 * asin(least(1, sqrt(
    power(sin(radians(lat2 - lat1) / 2), 2)
    + cos(radians(lat1)) * cos(radians(lat2)) * power(sin(radians(lng2 - lng1) / 2), 2)
  )));
$$;

-- The rule's route covers these two ends: 150 m, the same as the parking fence.
create or replace function public.fn_regular_trip_covers(
  r public.regular_trips,
  start_lat double precision, start_lng double precision,
  end_lat double precision, end_lng double precision
)
returns boolean
language sql immutable
set search_path to 'public'
as $$
  select end_lat is not null and end_lng is not null
    and public.fn_cm_distance_m(r.end_latitude, r.end_longitude, end_lat, end_lng) <= 150
    and (r.start_any or (
      start_lat is not null and start_lng is not null
      and public.fn_cm_distance_m(r.start_latitude, r.start_longitude, start_lat, start_lng) <= 150
    ));
$$;

create or replace function public.fn_classify_section_on_close()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_settings public.trip_classification_settings%rowtype;
  v_has_settings boolean;
  v_rule_purpose text;
  v_local timestamp;
  v_minute integer;
  v_today integer;
  v_yesterday integer;
  v_inside boolean;
begin
  -- A person changing a closed trip's category takes it over from the rule.
  if OLD.section_status in ('closed', 'switched') then
    if NEW.irs_purpose is distinct from OLD.irs_purpose
       and NEW.auto_purpose_source is not distinct from OLD.auto_purpose_source then
      NEW.auto_purpose_source := null;
    end if;
    return NEW;
  end if;

  if NEW.section_status is distinct from 'closed'
     or NEW.gig_app is distinct from 'custom'
     or NEW.organization_id is not null
     or NEW.irs_purpose is not null then
    return NEW;
  end if;

  -- Classifying is a convenience: it must never stop a trip from closing.
  begin
    if not exists (select 1 from public.profiles p where p.id = NEW.user_id and p.premium_entitled) then
      return NEW;
    end if;

    select * into v_settings from public.trip_classification_settings s where s.user_id = NEW.user_id;
    v_has_settings := found;

    if not v_has_settings or v_settings.regular_enabled then
      select r.purpose into v_rule_purpose
      from public.regular_trips r
      where r.user_id = NEW.user_id
        and public.fn_regular_trip_covers(r, NEW.start_latitude, NEW.start_longitude, NEW.end_latitude, NEW.end_longitude)
      order by r.start_any, r.created_at desc
      limit 1;
      if v_rule_purpose is not null then
        NEW.irs_purpose := v_rule_purpose;
        NEW.auto_purpose_source := 'regular_trip';
        return NEW;
      end if;
    end if;

    if v_has_settings and (v_settings.work_hours_inside or v_settings.work_hours_outside) then
      v_local := NEW.start_time at time zone v_settings.time_zone;
      v_minute := extract(hour from v_local)::integer * 60 + extract(minute from v_local)::integer;
      v_today := extract(isodow from v_local)::integer;
      v_yesterday := case when v_today = 1 then 7 else v_today - 1 end;
      -- An end at or before the start runs past midnight, like the tracking hours.
      if v_settings.work_start_minute < v_settings.work_end_minute then
        v_inside := v_today = any(v_settings.work_days)
          and v_minute >= v_settings.work_start_minute and v_minute < v_settings.work_end_minute;
      else
        v_inside := (v_today = any(v_settings.work_days) and v_minute >= v_settings.work_start_minute)
          or (v_yesterday = any(v_settings.work_days) and v_minute < v_settings.work_end_minute);
      end if;
      if v_inside and v_settings.work_hours_inside then
        NEW.irs_purpose := 'business';
        NEW.auto_purpose_source := 'work_hours';
      elsif not v_inside and v_settings.work_hours_outside then
        NEW.irs_purpose := 'personal';
        NEW.auto_purpose_source := 'work_hours';
      end if;
    end if;
  exception when others then
    raise warning 'fn_classify_section_on_close failed for %: %', NEW.id, sqlerrm;
  end;
  return NEW;
end;
$$;

create trigger trg_classify_section_on_close
  before update on public.session_sections
  for each row when (new.organization_id is null)
  execute function public.fn_classify_section_on_close();

-- After the driver classifies a trip: the route to offer as a regular trip, when
-- this is at least the third trip on it with the same category. Null otherwise.
create or replace function public.suggest_regular_trip(p_section_id uuid)
returns jsonb
language plpgsql
stable
set search_path to 'public'
as $$
declare
  v public.session_sections%rowtype;
  v_count integer;
begin
  select * into v from public.session_sections s
  where s.id = p_section_id and s.user_id = auth.uid() and s.gig_app = 'custom'
    and s.organization_id is null and s.section_status = 'closed' and s.irs_purpose is not null
    and s.start_latitude is not null and s.end_latitude is not null;
  if not found then return null; end if;

  if not exists (select 1 from public.profiles p where p.id = auth.uid() and p.premium_entitled) then
    return null;
  end if;
  if exists (select 1 from public.trip_classification_settings c
             where c.user_id = auth.uid() and not (c.regular_enabled and c.suggestions_enabled)) then
    return null;
  end if;
  if exists (select 1 from public.regular_trips r
             where r.user_id = auth.uid()
               and public.fn_regular_trip_covers(r, v.start_latitude, v.start_longitude, v.end_latitude, v.end_longitude)) then
    return null;
  end if;

  select count(*) into v_count from public.session_sections s
  where s.user_id = auth.uid() and s.gig_app = 'custom' and s.organization_id is null
    and s.section_status = 'closed' and s.irs_purpose = v.irs_purpose
    and s.start_latitude is not null and s.end_latitude is not null
    and public.fn_cm_distance_m(s.start_latitude, s.start_longitude, v.start_latitude, v.start_longitude) <= 150
    and public.fn_cm_distance_m(s.end_latitude, s.end_longitude, v.end_latitude, v.end_longitude) <= 150;
  if v_count < 3 then return null; end if;

  return jsonb_build_object(
    'start_latitude', v.start_latitude, 'start_longitude', v.start_longitude, 'start_address', v.start_address,
    'end_latitude', v.end_latitude, 'end_longitude', v.end_longitude, 'end_address', v.end_address,
    'purpose', v.irs_purpose, 'count', v_count
  );
end;
$$;

-- Earlier General trips on this route that still have no category: how many, and
-- (when p_dry_run is false) classify them. Trips already categorized are left alone.
create or replace function public.apply_regular_trip_to_past(p_rule_id uuid, p_dry_run boolean default true)
returns integer
language plpgsql
set search_path to 'public'
as $$
declare
  r public.regular_trips%rowtype;
  v_count integer;
begin
  select * into r from public.regular_trips t where t.id = p_rule_id and t.user_id = auth.uid();
  if not found then return 0; end if;

  if p_dry_run then
    select count(*) into v_count from public.session_sections s
    where s.user_id = auth.uid() and s.gig_app = 'custom' and s.organization_id is null
      and s.section_status = 'closed' and s.irs_purpose is null
      and public.fn_regular_trip_covers(r, s.start_latitude, s.start_longitude, s.end_latitude, s.end_longitude);
    return v_count;
  end if;

  update public.session_sections s
  set irs_purpose = r.purpose, auto_purpose_source = 'regular_trip'
  where s.user_id = auth.uid() and s.gig_app = 'custom' and s.organization_id is null
    and s.section_status = 'closed' and s.irs_purpose is null
    and public.fn_regular_trip_covers(r, s.start_latitude, s.start_longitude, s.end_latitude, s.end_longitude);
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

revoke all on function public.suggest_regular_trip(uuid) from public, anon;
revoke all on function public.apply_regular_trip_to_past(uuid, boolean) from public, anon;
grant execute on function public.suggest_regular_trip(uuid) to authenticated;
grant execute on function public.apply_regular_trip_to_past(uuid, boolean) to authenticated;

-- Only ever runs as a trigger: nobody needs to call it.
revoke all on function public.fn_classify_section_on_close() from public, anon, authenticated;
