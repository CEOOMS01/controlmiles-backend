-- User IDs (2026-10-27).
--  1. New driver IDs are CM-D + 6 digits and new vehicle IDs CM-T + 6 digits (they were 4
--     digits: only 10,000 in the whole platform). Existing IDs keep working unchanged.
--  2. An ID that belonged to a deleted driver / vehicle / parent / profile is RETIRED and
--     never issued again, until ControlMiles sets the retention period for removing an ID
--     completely (platform_id_policy.reuse_after_days). While that is NULL no ID is reused.
--     Reports and audit trails therefore never point at a different person's old ID.
set local lock_timeout = '5s';

insert into ops.domain_tables (tbl, domain) values
  ('platform_id_policy', 'core'),
  ('retired_display_ids', 'core')
on conflict (tbl) do update set domain = excluded.domain;

-- Registered before the triggers exist (the domain guard checks core-table triggers).
insert into ops.domain_triggers (tbl, tg, domain, guard) values
  ('vehicles', 'trg_retire_vehicle_id', 'core', null),
  ('profiles', 'trg_retire_profile_id', 'core', null)
on conflict do nothing;

create table if not exists public.platform_id_policy (
  id boolean primary key default true check (id),
  -- NULL = a retired ID is never issued again. Set it (>= 30 days) once ControlMiles
  -- defines the period after which an ID is erased completely and may be reissued.
  reuse_after_days int check (reuse_after_days is null or reuse_after_days >= 30),
  updated_at timestamptz not null default now()
);
insert into public.platform_id_policy (id, reuse_after_days) values (true, null) on conflict (id) do nothing;

create table if not exists public.retired_display_ids (
  display_id text primary key,
  kind text not null,
  retired_at timestamptz not null default now()
);
alter table public.platform_id_policy enable row level security;
alter table public.retired_display_ids enable row level security;
revoke all on public.platform_id_policy, public.retired_display_ids from anon, authenticated;

create or replace function public.fn_display_id_blocked(p_id text)
returns boolean
language sql
stable
security definer
set search_path to 'public'
as $$
  select exists (
    select 1
      from public.retired_display_ids r
      cross join public.platform_id_policy pol
     where r.display_id = p_id
       and (pol.reuse_after_days is null
            or r.retired_at > now() - make_interval(days => pol.reuse_after_days))
  );
$$;
revoke execute on function public.fn_display_id_blocked(text) from public, anon, authenticated;

create or replace function public.fn_retire_display_id()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  if old.display_id is not null and btrim(old.display_id) <> '' then
    insert into public.retired_display_ids (display_id, kind) values (old.display_id, tg_argv[0])
    on conflict (display_id) do update set retired_at = now(), kind = excluded.kind;
  end if;
  return old;
end;
$$;
revoke execute on function public.fn_retire_display_id() from public, anon, authenticated;

drop trigger if exists trg_retire_driver_slot_id on public.fleet_driver_slots;
create trigger trg_retire_driver_slot_id after delete on public.fleet_driver_slots
  for each row when (old.display_id is not null) execute function public.fn_retire_display_id('driver');
drop trigger if exists trg_retire_vehicle_id on public.vehicles;
create trigger trg_retire_vehicle_id after delete on public.vehicles
  for each row when (old.display_id is not null) execute function public.fn_retire_display_id('vehicle');
drop trigger if exists trg_retire_guardian_id on public.school_guardians;
create trigger trg_retire_guardian_id after delete on public.school_guardians
  for each row when (old.display_id is not null) execute function public.fn_retire_display_id('guardian');
drop trigger if exists trg_retire_profile_id on public.profiles;
create trigger trg_retire_profile_id after delete on public.profiles
  for each row when (old.display_id is not null) execute function public.fn_retire_display_id('profile');

-- Generators: 6 digits for drivers and vehicles, and no retired ID is ever picked.
create or replace function public.fn_assign_driver_slot_display_id()
returns trigger language plpgsql set search_path to 'public' as $function$
declare
  v_new_id text;
  v_attempts int := 0;
begin
  if new.display_id is null or btrim(new.display_id) = '' then
    loop
      v_new_id := 'CM-D' || lpad(floor(random() * 1000000)::text, 6, '0');
      exit when not exists (select 1 from public.fleet_driver_slots where display_id = v_new_id)
            and not public.fn_display_id_blocked(v_new_id);
      v_attempts := v_attempts + 1;
      if v_attempts >= 200 then
        raise exception '[ControlMiles] Could not generate a unique driver ID after % attempts.', v_attempts;
      end if;
    end loop;
    new.display_id := v_new_id;
  end if;
  return new;
end;
$function$;

create or replace function public.fn_assign_vehicle_display_id()
returns trigger language plpgsql set search_path to 'public' as $function$
declare
  v_new_id text;
  v_attempts int := 0;
begin
  if new.display_id is null or btrim(new.display_id) = '' then
    loop
      v_new_id := 'CM-T' || lpad(floor(random() * 1000000)::text, 6, '0');
      exit when not exists (select 1 from public.vehicles where display_id = v_new_id)
            and not public.fn_display_id_blocked(v_new_id);
      v_attempts := v_attempts + 1;
      if v_attempts >= 200 then
        raise exception '[ControlMiles] Could not generate a unique vehicle ID after % attempts.', v_attempts;
      end if;
    end loop;
    new.display_id := v_new_id;
  end if;
  return new;
end;
$function$;

create or replace function public.fn_assign_guardian_display_id()
returns trigger language plpgsql set search_path to 'public' as $function$
declare
  v_new_id text;
  v_attempts int := 0;
begin
  if new.display_id is null or btrim(new.display_id) = '' then
    loop
      v_new_id := 'CM-' || lpad(floor(random() * 1000000)::text, 6, '0');
      exit when not exists (select 1 from public.school_guardians where display_id = v_new_id)
            and not public.fn_display_id_blocked(v_new_id);
      v_attempts := v_attempts + 1;
      if v_attempts >= 200 then
        raise exception '[ControlMiles] Could not generate a unique guardian ID after % attempts.', v_attempts;
      end if;
    end loop;
    new.display_id := v_new_id;
  end if;
  return new;
end;
$function$;

create or replace function public.fn_assign_profile_display_id()
returns trigger language plpgsql set search_path to 'public' as $function$
declare
  v_letter   char(1);
  v_digits   text;
  v_new_id   text;
  v_attempts int := 0;
  v_max      int := 200;
begin
  if new.display_id is null or btrim(new.display_id) = '' then
    loop
      v_letter := chr(65 + floor(random() * 26)::int);
      v_digits := lpad(floor(random() * 1000000)::text, 6, '0');
      v_new_id := 'CM-' || v_letter || v_digits;
      exit when not exists (select 1 from public.profiles where display_id = v_new_id)
            and not public.fn_display_id_blocked(v_new_id);
      v_attempts := v_attempts + 1;
      if v_attempts >= v_max then
        raise exception '[ControlMiles] Could not generate a unique CM User ID after % attempts.', v_max;
      end if;
    end loop;
    new.display_id := v_new_id;
  end if;
  return new;
end;
$function$;
