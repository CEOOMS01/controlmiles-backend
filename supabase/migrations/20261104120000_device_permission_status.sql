-- Olympus Mont Systems LLC - ControlMiles (Gig)
-- Which app permissions are ON for a user, so support can see why a phone
-- stops recording (a driver whose trips lose miles in the background) without
-- asking them to read out their settings.
--
-- Privacy by design:
--   * only on/off states and the coarse phone info already listed in the
--     privacy policy (device type, OS version, app version);
--   * no location, no contacts, no advertising or hardware identifiers;
--   * ONE row per user, overwritten each time (no history);
--   * written only through report_permission_status() for the caller's own
--     row; the user can read their own row, nobody else can (support reads it
--     with the service role);
--   * deleted together with the account (on delete cascade).

insert into ops.domain_tables (tbl, domain) values ('device_permission_status', 'core') on conflict do nothing;

create table if not exists public.device_permission_status (
  user_id uuid primary key references auth.users(id) on delete cascade,
  app_version text,
  os_version text,
  device_model text,
  location_state text check (location_state in ('precise', 'approximate', 'denied')),
  location_always boolean,
  notifications boolean,
  motion boolean,
  camera boolean,
  battery_unrestricted boolean,
  usage_access boolean,
  exact_alarm boolean,
  reported_at timestamptz not null default now()
);

alter table public.device_permission_status enable row level security;
create policy device_permission_status_select_own on public.device_permission_status
  for select to authenticated using (user_id = auth.uid());
revoke all on public.device_permission_status from anon, authenticated;
grant select on public.device_permission_status to authenticated;

create or replace function public.report_permission_status(
  p_app_version text,
  p_os_version text,
  p_device_model text,
  p_location_state text,
  p_location_always boolean,
  p_notifications boolean,
  p_motion boolean,
  p_camera boolean,
  p_battery_unrestricted boolean,
  p_usage_access boolean,
  p_exact_alarm boolean
) returns void
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;
  if p_location_state is not null and p_location_state not in ('precise', 'approximate', 'denied') then
    raise exception 'invalid location_state' using errcode = '22023';
  end if;

  insert into public.device_permission_status as d (
    user_id, app_version, os_version, device_model, location_state, location_always,
    notifications, motion, camera, battery_unrestricted, usage_access, exact_alarm, reported_at
  ) values (
    v_uid, left(p_app_version, 40), left(p_os_version, 40), left(p_device_model, 80), p_location_state,
    p_location_always, p_notifications, p_motion, p_camera, p_battery_unrestricted, p_usage_access,
    p_exact_alarm, now()
  )
  on conflict (user_id) do update set
    app_version = excluded.app_version,
    os_version = excluded.os_version,
    device_model = excluded.device_model,
    location_state = excluded.location_state,
    location_always = excluded.location_always,
    notifications = excluded.notifications,
    motion = excluded.motion,
    camera = excluded.camera,
    battery_unrestricted = excluded.battery_unrestricted,
    usage_access = excluded.usage_access,
    exact_alarm = excluded.exact_alarm,
    reported_at = now();
end;
$$;

revoke execute on function public.report_permission_status(text, text, text, text, boolean, boolean, boolean, boolean, boolean, boolean, boolean) from public, anon;
grant execute on function public.report_permission_status(text, text, text, text, boolean, boolean, boolean, boolean, boolean, boolean, boolean) to authenticated;
