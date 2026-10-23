create or replace function public.generate_report_access_code(
  p_start_date date,
  p_end_date date,
  p_vehicle_id uuid default null,
  p_weekly_checkpoints jsonb default '[]'::jsonb,
  p_target_user_id uuid default null
)
returns table(code text, expires_at timestamptz)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_caller uuid := auth.uid();
  v_user_id uuid;
  v_recent_count int;
  v_plain_code text;
  v_alphabet text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  v_expires timestamptz := now() + interval '15 minutes';
  v_metadata jsonb;
  v_deduction numeric;
  v_debug_exists boolean;
  i int;
begin
  if v_caller is null then
    raise exception 'Authentication required';
  end if;

  if p_target_user_id is null or p_target_user_id = v_caller then
    v_user_id := v_caller;
  else
    select exists (
      select 1
      from public.organization_members caller_m
      join public.organization_members target_m
        on target_m.organization_id = caller_m.organization_id
      where caller_m.user_id = v_caller
        and caller_m.member_role in ('owner', 'admin')
        and caller_m.is_active = true
        and target_m.user_id = p_target_user_id
        and target_m.is_active = true
    ) into v_debug_exists;

    if not v_debug_exists then
      raise exception 'Not authorized to generate a report for that driver';
    end if;
    v_user_id := p_target_user_id;
  end if;

  raise exception 'DEBUG: v_caller=%, p_target_user_id=%, v_user_id=%, v_debug_exists=%', v_caller, p_target_user_id, v_user_id, v_debug_exists;

  if p_end_date < p_start_date then
    raise exception 'Invalid date range';
  end if;

  select count(*) into v_recent_count
  from public.reports
  where generated_by = v_caller
    and generated_at > now() - interval '1 hour';

  if v_recent_count >= 5 then
    raise exception 'Too many report codes generated recently. Try again later.';
  end if;

  select coalesce(sum(
    case when s.date_key < date '2026-07-01'
      then s.total_miles * 72.5 / 100.0
      else s.total_miles * 76.0 / 100.0
    end
  ), 0) into v_deduction
  from public.sessions s
  where s.user_id = v_user_id
    and s.date_key between p_start_date and p_end_date
    and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id);

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
    'total_deduction_estimate', v_deduction,
    'vehicles', coalesce((select jsonb_agg(jsonb_build_object(
        'nickname', vr.nickname, 'make', vr.make, 'model', vr.model,
        'year', vr.year, 'plate', vr.plate
      )) from vehicles_in_range vr), '[]'::jsonb),
    'gig_app_breakdown', coalesce((select jsonb_agg(jsonb_build_object(
        'gig_app', pb.gig_app, 'irs_purpose', pb.irs_purpose, 'miles', pb.miles
      )) from purpose_breakdown pb), '[]'::jsonb),
    'weekly_checkpoints', coalesce(p_weekly_checkpoints, '[]'::jsonb)
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
    v_caller, v_metadata,
    encode(digest(v_plain_code, 'sha256'), 'hex'), v_expires, 0, 2
  );

  return query select v_plain_code, v_expires;
end;
$$;
