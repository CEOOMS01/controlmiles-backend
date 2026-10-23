alter table public.ifta_fuel_tax_rates
  add column kind text not null default 'base' check (kind in ('base', 'surcharge'));
alter table public.ifta_fuel_tax_rates
  drop constraint if exists ifta_fuel_tax_rates_quarter_jurisdiction_code_fuel_type_key;
alter table public.ifta_fuel_tax_rates
  add constraint ifta_fuel_tax_rates_quarter_jurisdiction_fuel_kind_key
  unique (quarter, jurisdiction_code, fuel_type, kind);

alter table public.vehicles
  add column ifta_qualified boolean not null default false,
  add column ifta_fuel_type text not null default 'diesel'
    check (ifta_fuel_type in ('diesel', 'gasoline'));

alter table public.fuel_purchases
  add column vendor_name text,
  add column tax_paid boolean not null default true;
alter table public.fuel_purchases
  add constraint fuel_purchases_fuel_type_check check (fuel_type in ('diesel', 'gasoline'));

drop function if exists public.submit_fuel_purchase(uuid, date, numeric, text, numeric, numeric, text, text, text, boolean, numeric);

CREATE OR REPLACE FUNCTION public.submit_fuel_purchase(
  p_vehicle_id uuid,
  p_purchase_date date,
  p_gallons numeric,
  p_state_code text DEFAULT NULL,
  p_price_per_gallon_usd numeric DEFAULT NULL,
  p_total_cost_usd numeric DEFAULT NULL,
  p_fuel_type text DEFAULT 'diesel',
  p_receipt_image_url text DEFAULT NULL,
  p_file_hash text DEFAULT NULL,
  p_ocr_source boolean DEFAULT false,
  p_ocr_confidence numeric DEFAULT NULL,
  p_vendor_name text DEFAULT NULL
)
RETURNS public.fuel_purchases
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  v_owner uuid;
  v_org uuid;
  v_row public.fuel_purchases;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;
  if p_gallons is null or p_gallons <= 0 then
    raise exception 'Gallons must be greater than 0';
  end if;
  if p_receipt_image_url is null or p_file_hash is null then
    raise exception 'Receipt photo is required';
  end if;
  if coalesce(p_fuel_type, 'diesel') not in ('diesel', 'gasoline') then
    raise exception 'Unknown fuel type: %', p_fuel_type;
  end if;
  select owner_user_id, organization_id into v_owner, v_org
  from public.vehicles where id = p_vehicle_id;
  if not found then
    raise exception 'Vehicle not found';
  end if;
  if v_owner is distinct from auth.uid()
     and not (v_org is not null and public.is_org_member(v_org)) then
    raise exception 'Not authorized to log fuel for this vehicle';
  end if;
  if p_state_code is not null and not exists (
    select 1 from public.ifta_us_state_boundaries where state_code = p_state_code
  ) then
    raise exception 'Unknown state_code: %', p_state_code;
  end if;
  insert into public.fuel_purchases (
    vehicle_id, user_id, organization_id, purchase_date, state_code,
    gallons, price_per_gallon_usd, total_cost_usd, fuel_type,
    receipt_image_url, file_hash, ocr_source, ocr_confidence, vendor_name
  )
  values (
    p_vehicle_id, auth.uid(), v_org, p_purchase_date, p_state_code,
    p_gallons, p_price_per_gallon_usd, p_total_cost_usd, coalesce(p_fuel_type, 'diesel'),
    p_receipt_image_url, p_file_hash, p_ocr_source, p_ocr_confidence,
    nullif(btrim(p_vendor_name), '')
  )
  returning * into v_row;
  return v_row;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.submit_fuel_purchase(uuid, date, numeric, text, numeric, numeric, text, text, text, boolean, numeric, text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.submit_fuel_purchase(uuid, date, numeric, text, numeric, numeric, text, text, text, boolean, numeric, text) FROM anon;
GRANT EXECUTE ON FUNCTION public.submit_fuel_purchase(uuid, date, numeric, text, numeric, numeric, text, text, text, boolean, numeric, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.correct_fuel_purchase_ifta(
  p_purchase_id uuid, p_state_code text, p_fuel_type text, p_tax_paid boolean
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.fuel_purchases where id = p_purchase_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  if p_state_code is not null and not exists (
    select 1 from public.ifta_us_state_boundaries where state_code = p_state_code
  ) then
    raise exception 'Unknown state_code: %', p_state_code;
  end if;
  if p_fuel_type not in ('diesel', 'gasoline') then
    raise exception 'Unknown fuel type: %', p_fuel_type;
  end if;
  update public.fuel_purchases
  set state_code = p_state_code, fuel_type = p_fuel_type, tax_paid = coalesce(p_tax_paid, true)
  where id = p_purchase_id;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.correct_fuel_purchase_ifta(uuid, text, text, boolean) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.correct_fuel_purchase_ifta(uuid, text, text, boolean) TO authenticated;

CREATE OR REPLACE FUNCTION public.set_vehicle_ifta(
  p_vehicle_id uuid, p_qualified boolean, p_fuel_type text
)
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
  if p_fuel_type not in ('diesel', 'gasoline') then
    raise exception 'Unknown fuel type: %', p_fuel_type;
  end if;
  update public.vehicles
  set ifta_qualified = coalesce(p_qualified, false), ifta_fuel_type = p_fuel_type
  where id = p_vehicle_id;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.set_vehicle_ifta(uuid, boolean, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.set_vehicle_ifta(uuid, boolean, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.compute_ifta_vehicle_state_miles(
  p_organization_id uuid, p_start_date date, p_end_date date
)
RETURNS TABLE(vehicle_id uuid, state_code text, miles double precision)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'Not authorized for this organization';
  end if;
  return query
  with ordered as (
    select
      b.vehicle_id as vid, b.latitude, b.longitude,
      lag(b.latitude) over w as prev_lat,
      lag(b.longitude) over w as prev_lng
    from public.session_gps_breadcrumbs b
    where b.organization_id = p_organization_id
      and b.recorded_at::date between p_start_date and p_end_date
      and b.vehicle_id is not null
    window w as (partition by b.session_id order by b.recorded_at)
  ),
  segments as (
    select
      o.vid, o.latitude, o.longitude,
      6371000 * acos(
        least(1.0, greatest(-1.0,
          cos(radians(o.prev_lat)) * cos(radians(o.latitude)) *
            cos(radians(o.longitude) - radians(o.prev_lng)) +
          sin(radians(o.prev_lat)) * sin(radians(o.latitude))
        ))
      ) / 1609.34 as seg_miles
    from ordered o
    where o.prev_lat is not null
  )
  select
    s.vid,
    coalesce(sb.state_code, 'UNKNOWN')::text,
    sum(s.seg_miles)::double precision
  from segments s
  left join public.ifta_us_state_boundaries sb
    on ST_Contains(sb.geom, ST_SetSRID(ST_MakePoint(s.longitude, s.latitude), 4326))
  group by s.vid, sb.state_code;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.compute_ifta_vehicle_state_miles(uuid, date, date) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.compute_ifta_vehicle_state_miles(uuid, date, date) TO authenticated;

CREATE OR REPLACE FUNCTION public.ifta_state_at_point(p_lat double precision, p_lng double precision)
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  select state_code from public.ifta_us_state_boundaries
  where ST_Contains(geom, ST_SetSRID(ST_MakePoint(p_lng, p_lat), 4326))
  limit 1;
$function$;

REVOKE EXECUTE ON FUNCTION public.ifta_state_at_point(double precision, double precision) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.ifta_state_at_point(double precision, double precision) TO authenticated;
