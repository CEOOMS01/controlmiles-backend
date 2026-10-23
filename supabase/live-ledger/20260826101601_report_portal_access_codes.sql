-- ControlMiles Report Portal: driver-generated, short-lived access codes
-- for a read-only mileage report, redeemed by an unauthenticated third
-- party (tax preparer). Redesigns dormant scaffolding found already on
-- public.reports (qr_token/qr_expires_at/qr_uses/qr_max_uses, added in
-- an earlier session, never wired to any client) plus a validate_qr_code
-- RPC that existed but was incomplete: no search_path pin, no rate
-- limiting, no data-fetch path for an anon caller. Confirmed via grep
-- that nothing in the Flutter app references either.

comment on column public.reports.qr_token is 'SHA-256 hex hash of the access code shown to the driver. The plaintext code is never stored -- only returned once, at generation time.';
comment on column public.reports.qr_expires_at is 'Code becomes invalid after this time even if qr_uses < qr_max_uses.';
comment on column public.reports.qr_uses is 'How many times this code has been successfully redeemed.';
comment on column public.reports.qr_max_uses is 'Max successful redemptions before the code is dead, independent of expiry.';

create table if not exists public.report_access_attempts (
  id uuid primary key default gen_random_uuid(),
  ip_hash text not null,
  success boolean not null,
  report_id uuid references public.reports(id) on delete set null,
  attempted_at timestamptz not null default now()
);
comment on table public.report_access_attempts is 'Rate-limiting + audit log for report-portal code redemption attempts. IP is stored hashed, never raw. No client-facing RLS policy on purpose -- only SECURITY DEFINER functions touch this table.';

alter table public.report_access_attempts enable row level security;

create index if not exists idx_report_access_attempts_ip_time
  on public.report_access_attempts (ip_hash, attempted_at desc);

drop function if exists public.validate_qr_code(text);

create or replace function public.generate_report_access_code(
  p_start_date date,
  p_end_date date,
  p_vehicle_id uuid default null
)
returns table(code text, expires_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_recent_count int;
  v_plain_code text;
  v_alphabet text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  v_expires timestamptz := now() + interval '15 minutes';
  v_metadata jsonb;
  i int;
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  if p_end_date < p_start_date then
    raise exception 'Invalid date range';
  end if;

  select count(*) into v_recent_count
  from public.reports
  where user_id = v_user_id
    and generated_at > now() - interval '1 hour';

  if v_recent_count >= 5 then
    raise exception 'Too many report codes generated recently. Try again later.';
  end if;

  with vehicles_in_range as (
    select distinct v.id, v.nickname, v.make, v.model, v.year, v.plate
    from public.sessions s
    join public.vehicles v on v.id = s.vehicle_id
    where s.user_id = v_user_id
      and s.date_key between p_start_date and p_end_date
      and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
  ),
  purpose_breakdown as (
    select
      ss.gig_app,
      ss.irs_purpose,
      sum(ss.total_miles) as miles
    from public.session_sections ss
    join public.sessions s on s.id = ss.session_id
    where s.user_id = v_user_id
      and s.date_key between p_start_date and p_end_date
      and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
    group by ss.gig_app, ss.irs_purpose
  ),
  totals as (
    select
      coalesce(sum(s.total_miles), 0) as total_miles,
      count(distinct s.id) as total_sessions
    from public.sessions s
    where s.user_id = v_user_id
      and s.date_key between p_start_date and p_end_date
      and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
  )
  select jsonb_build_object(
    'driver_display_name', p.full_name,
    'driver_display_id', p.display_id,
    'start_date', p_start_date,
    'end_date', p_end_date,
    'generated_at', now(),
    'total_miles', t.total_miles,
    'total_sessions', t.total_sessions,
    'vehicles', coalesce((select jsonb_agg(jsonb_build_object(
        'nickname', vr.nickname, 'make', vr.make, 'model', vr.model,
        'year', vr.year, 'plate', vr.plate
      )) from vehicles_in_range vr), '[]'::jsonb),
    'gig_app_breakdown', coalesce((select jsonb_agg(jsonb_build_object(
        'gig_app', pb.gig_app, 'irs_purpose', pb.irs_purpose, 'miles', pb.miles
      )) from purpose_breakdown pb), '[]'::jsonb)
  )
  into v_metadata
  from public.profiles p, totals t
  where p.id = v_user_id;

  v_plain_code := '';
  for i in 1..8 loop
    v_plain_code := v_plain_code || substr(v_alphabet, 1 + floor(random() * length(v_alphabet))::int, 1);
  end loop;

  insert into public.reports (
    report_type, user_id, vehicle_id, start_date, end_date,
    total_miles, total_sessions, generated_by, metadata,
    qr_token, qr_expires_at, qr_uses, qr_max_uses
  ) values (
    'custom', v_user_id, p_vehicle_id, p_start_date, p_end_date,
    coalesce((v_metadata->>'total_miles')::float8, 0),
    coalesce((v_metadata->>'total_sessions')::int, 0),
    v_user_id, v_metadata,
    encode(digest(v_plain_code, 'sha256'), 'hex'), v_expires, 0, 2
  );

  return query select v_plain_code, v_expires;
end;
$$;

revoke all on function public.generate_report_access_code(date, date, uuid) from public;
grant execute on function public.generate_report_access_code(date, date, uuid) to authenticated;

create or replace function public.redeem_report_access_code(
  p_code text,
  p_ip_hash text
)
returns table(success boolean, message text, report jsonb)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_recent_failures int;
  v_hash text;
  v_report record;
begin
  select count(*) into v_recent_failures
  from public.report_access_attempts
  where ip_hash = p_ip_hash
    and success = false
    and attempted_at > now() - interval '15 minutes';

  if v_recent_failures >= 5 then
    return query select false, 'Too many attempts. Try again later.', null::jsonb;
    return;
  end if;

  v_hash := encode(digest(coalesce(p_code, ''), 'sha256'), 'hex');

  select * into v_report
  from public.reports
  where qr_token = v_hash
    and qr_expires_at > now()
    and qr_uses < qr_max_uses
  limit 1;

  if not found then
    insert into public.report_access_attempts (ip_hash, success, report_id)
    values (p_ip_hash, false, null);
    return query select false, 'Invalid or expired code.', null::jsonb;
    return;
  end if;

  update public.reports set qr_uses = qr_uses + 1 where id = v_report.id;

  insert into public.report_access_attempts (ip_hash, success, report_id)
  values (p_ip_hash, true, v_report.id);

  return query select true, 'ok', v_report.metadata;
end;
$$;

revoke all on function public.redeem_report_access_code(text, text) from public;
revoke all on function public.redeem_report_access_code(text, text) from authenticated;
grant execute on function public.redeem_report_access_code(text, text) to anon;
