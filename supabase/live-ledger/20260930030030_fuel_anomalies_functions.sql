CREATE OR REPLACE FUNCTION public.fn_evaluate_fuel_purchase(p_purchase_id uuid)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  p public.fuel_purchases;
  v public.vehicles;
  found_kinds text[] := '{}';
  v_day_total numeric;
  v_dup boolean;
  v_points int;
  v_in_state boolean;
  v_states text;
  v_trips int;
  v_prev public.fuel_purchases;
  v_miles numeric;
  v_mpg numeric;
  v_baseline numeric;
  v_floor numeric;
  v_median_ppg numeric;
  v_samples int;
  v_checked_location boolean;
begin
  select * into p from public.fuel_purchases where id = p_purchase_id;
  if not found or p.organization_id is null then
    return;
  end if;
  select * into v from public.vehicles where id = p.vehicle_id;

  select exists (
    select 1 from public.fuel_purchases o
    where o.vehicle_id = p.vehicle_id and o.id <> p.id
      and (o.file_hash = p.file_hash
           or (o.purchase_date = p.purchase_date and abs(o.gallons - p.gallons) < 0.01))
  ) into v_dup;
  if v_dup then
    found_kinds := array_append(found_kinds, 'duplicate');
    insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
    values (p.organization_id, p.id, p.vehicle_id, 'duplicate', 'high',
      format('Looks like a duplicate: another receipt for this vehicle has the same %s.',
        case when exists (select 1 from public.fuel_purchases o where o.vehicle_id = p.vehicle_id and o.id <> p.id and o.file_hash = p.file_hash)
             then 'photo' else 'date and gallons' end),
      jsonb_build_object('gallons', p.gallons))
    on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
  end if;

  if v.fuel_tank_capacity_gal is not null then
    select sum(gallons) into v_day_total from public.fuel_purchases
    where vehicle_id = p.vehicle_id and purchase_date = p.purchase_date;
    if v_day_total > v.fuel_tank_capacity_gal * 1.05 then
      found_kinds := array_append(found_kinds, 'over_capacity');
      insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
      values (p.organization_id, p.id, p.vehicle_id, 'over_capacity', 'high',
        format('%s gal bought on %s, but the tank holds %s gal.',
          round(v_day_total, 1), p.purchase_date, round(v.fuel_tank_capacity_gal, 1)),
        jsonb_build_object('day_gallons', v_day_total, 'tank_gallons', v.fuel_tank_capacity_gal))
      on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
    end if;
  end if;

  v_checked_location := p.purchase_date < (now() at time zone 'utc')::date;
  if v_checked_location then
    select count(*) into v_points from public.session_gps_breadcrumbs b
    where b.vehicle_id = p.vehicle_id
      and b.recorded_at >= (p.purchase_date - 1)::timestamptz
      and b.recorded_at < (p.purchase_date + 2)::timestamptz;

    select count(*) into v_trips from public.sessions s
    where s.vehicle_id = p.vehicle_id
      and s.date_key between p.purchase_date - 1 and p.purchase_date + 1;

    if v_points = 0 and v_trips = 0 then
      found_kinds := array_append(found_kinds, 'no_trip');
      insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
      values (p.organization_id, p.id, p.vehicle_id, 'no_trip', 'medium',
        format('No trips were recorded for this vehicle between %s and %s.', p.purchase_date - 1, p.purchase_date + 1),
        '{}'::jsonb)
      on conflict (purchase_id, kind) do update set detail = excluded.detail;
    elsif v_points > 0 and p.state_code is not null then
      with pts as (
        select b.latitude, b.longitude,
               row_number() over (order by b.recorded_at) rn, count(*) over () n
        from public.session_gps_breadcrumbs b
        where b.vehicle_id = p.vehicle_id
          and b.recorded_at >= (p.purchase_date - 1)::timestamptz
          and b.recorded_at < (p.purchase_date + 2)::timestamptz
      ),
      sampled as (select * from pts where rn % greatest(1, n / 500) = 0),
      visited as (
        select distinct sb.state_code from sampled s
        join public.ifta_us_state_boundaries sb
          on ST_Contains(sb.geom, ST_SetSRID(ST_MakePoint(s.longitude, s.latitude), 4326))
      )
      select bool_or(state_code = p.state_code), string_agg(state_code, ', ' order by state_code)
      into v_in_state, v_states from visited;

      if v_states is not null and not coalesce(v_in_state, false) then
        found_kinds := array_append(found_kinds, 'location_mismatch');
        insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
        values (p.organization_id, p.id, p.vehicle_id, 'location_mismatch', 'high',
          format('Receipt says %s, but the vehicle''s GPS around %s was only in %s.', p.state_code, p.purchase_date, v_states),
          jsonb_build_object('receipt_state', p.state_code, 'gps_states', v_states))
        on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
      end if;
    end if;
  end if;

  select * into v_prev from public.fuel_purchases o
  where o.vehicle_id = p.vehicle_id and o.id <> p.id
    and (o.purchase_date < p.purchase_date
         or (o.purchase_date = p.purchase_date and o.created_at < p.created_at))
  order by o.purchase_date desc, o.created_at desc
  limit 1;

  if v_prev.id is not null and p.gallons >= 5 and v_checked_location then
    select coalesce(sum(s.total_miles), 0) into v_miles from public.sessions s
    where s.vehicle_id = p.vehicle_id
      and s.date_key > v_prev.purchase_date and s.date_key <= p.purchase_date;

    if v_miles < 1 and p.purchase_date > v_prev.purchase_date then
      found_kinds := array_append(found_kinds, 'no_miles');
      insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
      values (p.organization_id, p.id, p.vehicle_id, 'no_miles', 'high',
        format('%s gal bought, but no miles were driven since the last fill-up on %s.', round(p.gallons, 1), v_prev.purchase_date),
        jsonb_build_object('gallons', p.gallons, 'previous_purchase_date', v_prev.purchase_date))
      on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
    elsif v_miles >= 1 then
      v_mpg := v_miles / p.gallons;
      with fills as (
        select o.purchase_date, o.gallons,
               lag(o.purchase_date) over (order by o.purchase_date, o.created_at) prev_date
        from public.fuel_purchases o
        where o.vehicle_id = p.vehicle_id
          and o.purchase_date between p.purchase_date - 180 and p.purchase_date
          and o.id <> p.id
      ),
      intervals as (
        select (select sum(s.total_miles) from public.sessions s
                where s.vehicle_id = p.vehicle_id and s.date_key > f.prev_date and s.date_key <= f.purchase_date) / f.gallons as mpg
        from fills f
        where f.prev_date is not null and f.gallons >= 5
      )
      select percentile_cont(0.5) within group (order by mpg), count(*)
      into v_baseline, v_samples
      from intervals where mpg > 0;

      v_floor := case when coalesce(v.ifta_fuel_type, p.fuel_type) = 'gasoline' then 8 else 3.5 end;
      if (v_samples >= 3 and v_mpg < v_baseline * 0.6) or v_mpg < v_floor then
        found_kinds := array_append(found_kinds, 'low_mpg');
        insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
        values (p.organization_id, p.id, p.vehicle_id, 'low_mpg', 'medium',
          case when v_samples >= 3
            then format('%s MPG since the last fill-up (%s mi on %s gal) — this vehicle normally does %s MPG.',
                   round(v_mpg, 1), round(v_miles), round(p.gallons, 1), round(v_baseline, 1))
            else format('%s MPG since the last fill-up (%s mi on %s gal) — unusually low.',
                   round(v_mpg, 1), round(v_miles), round(p.gallons, 1))
          end,
          jsonb_build_object('mpg', round(v_mpg, 2), 'miles', round(v_miles, 1), 'gallons', p.gallons,
                             'baseline_mpg', round(v_baseline, 2), 'samples', v_samples))
        on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
      end if;
    end if;
  end if;

  if p.price_per_gallon_usd is not null and p.total_cost_usd is not null
     and abs(p.gallons * p.price_per_gallon_usd - p.total_cost_usd) > greatest(1, p.total_cost_usd * 0.02) then
    found_kinds := array_append(found_kinds, 'price_mismatch');
    insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
    values (p.organization_id, p.id, p.vehicle_id, 'price_mismatch', 'low',
      format('%s gal × $%s = $%s, but the receipt total is $%s.',
        round(p.gallons, 3), round(p.price_per_gallon_usd, 3),
        round(p.gallons * p.price_per_gallon_usd, 2), round(p.total_cost_usd, 2)),
      jsonb_build_object('expected_total', round(p.gallons * p.price_per_gallon_usd, 2), 'receipt_total', p.total_cost_usd))
    on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
  end if;

  if p.price_per_gallon_usd is not null then
    select percentile_cont(0.5) within group (order by o.price_per_gallon_usd), count(*)
    into v_median_ppg, v_samples
    from public.fuel_purchases o
    where o.organization_id = p.organization_id and o.id <> p.id
      and o.fuel_type = p.fuel_type and o.price_per_gallon_usd > 0
      and o.purchase_date between p.purchase_date - 60 and p.purchase_date + 60;
    if v_samples >= 5 and p.price_per_gallon_usd > v_median_ppg * 1.25 then
      found_kinds := array_append(found_kinds, 'price_high');
      insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
      values (p.organization_id, p.id, p.vehicle_id, 'price_high', 'low',
        format('$%s/gal, %s%% above the fleet''s usual $%s/gal for %s.',
          round(p.price_per_gallon_usd, 3), round((p.price_per_gallon_usd / v_median_ppg - 1) * 100),
          round(v_median_ppg, 3), p.fuel_type),
        jsonb_build_object('price', p.price_per_gallon_usd, 'median_price', round(v_median_ppg, 3)))
      on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
    end if;
  end if;

  delete from public.fuel_anomalies a
  where a.purchase_id = p.id and a.status = 'open' and not (a.kind = any (found_kinds));
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.fn_evaluate_fuel_purchase(uuid) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.fn_fuel_purchase_evaluate_trigger()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  v_next uuid;
begin
  perform public.fn_evaluate_fuel_purchase(new.id);
  select o.id into v_next from public.fuel_purchases o
  where o.vehicle_id = new.vehicle_id and o.id <> new.id
    and (o.purchase_date > new.purchase_date
         or (o.purchase_date = new.purchase_date and o.created_at > new.created_at))
  order by o.purchase_date, o.created_at
  limit 1;
  if v_next is not null then
    perform public.fn_evaluate_fuel_purchase(v_next);
  end if;
  return null;
end;
$function$;

create trigger fuel_purchases_evaluate
after insert or update of state_code, fuel_type, gallons on public.fuel_purchases
for each row execute function public.fn_fuel_purchase_evaluate_trigger();

CREATE OR REPLACE FUNCTION public.fn_reevaluate_recent_fuel_purchases()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  r record;
  n integer := 0;
begin
  for r in
    select id from public.fuel_purchases
    where organization_id is not null
      and purchase_date >= (now() at time zone 'utc')::date - 14
  loop
    perform public.fn_evaluate_fuel_purchase(r.id);
    n := n + 1;
  end loop;
  return n;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.fn_reevaluate_recent_fuel_purchases() FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public.review_fuel_anomaly(
  p_anomaly_id uuid,
  p_status text,
  p_note text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.fuel_anomalies where id = p_anomaly_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  if p_status not in ('open', 'dismissed', 'confirmed') then
    raise exception 'Unknown status: %', p_status;
  end if;
  update public.fuel_anomalies
  set status = p_status,
      review_note = nullif(btrim(p_note), ''),
      reviewed_by = case when p_status = 'open' then null else auth.uid() end,
      reviewed_at = case when p_status = 'open' then null else now() end
  where id = p_anomaly_id;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.review_fuel_anomaly(uuid, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.review_fuel_anomaly(uuid, text, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.set_vehicle_tank_capacity(p_vehicle_id uuid, p_gallons numeric)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.vehicles where id = p_vehicle_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  if p_gallons is not null and (p_gallons <= 0 or p_gallons > 1000) then
    raise exception 'Tank capacity must be between 1 and 1000 gallons';
  end if;
  update public.vehicles set fuel_tank_capacity_gal = p_gallons where id = p_vehicle_id;
  perform public.fn_evaluate_fuel_purchase(fp.id)
  from public.fuel_purchases fp
  where fp.vehicle_id = p_vehicle_id and fp.purchase_date >= current_date - 90;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.set_vehicle_tank_capacity(uuid, numeric) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.set_vehicle_tank_capacity(uuid, numeric) TO authenticated;
