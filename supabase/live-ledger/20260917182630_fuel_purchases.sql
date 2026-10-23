create table public.fuel_purchases (
  id uuid primary key default gen_random_uuid(),
  vehicle_id uuid not null references public.vehicles(id) on delete cascade,
  user_id uuid not null references public.profiles(id),
  organization_id uuid references public.organizations(id),
  purchase_date date not null,
  state_code text references public.ifta_us_state_boundaries(state_code),
  gallons numeric not null check (gallons > 0),
  price_per_gallon_usd numeric check (price_per_gallon_usd is null or price_per_gallon_usd >= 0),
  total_cost_usd numeric check (total_cost_usd is null or total_cost_usd >= 0),
  fuel_type text not null default 'diesel',
  receipt_image_url text not null,
  file_hash text not null,
  ocr_source boolean not null default false,
  ocr_confidence numeric,
  created_at timestamptz not null default now()
);

alter table public.fuel_purchases enable row level security;

create policy fuel_purchases_select
on public.fuel_purchases
for select
using (
  user_id = auth.uid()
  or (organization_id is not null and public.is_org_member(organization_id))
);

create policy fuel_purchases_delete
on public.fuel_purchases
for delete
using (
  user_id = auth.uid()
  or (organization_id is not null and public.is_org_admin_or_owner(organization_id))
);

create index fuel_purchases_vehicle_date_idx on public.fuel_purchases (vehicle_id, purchase_date);
create index fuel_purchases_org_date_idx on public.fuel_purchases (organization_id, purchase_date) where organization_id is not null;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('fuel_receipts', 'fuel_receipts', false, 10485760, array['image/jpeg', 'image/png'])
on conflict (id) do nothing;

create policy fuel_receipts_insert_own
on storage.objects for insert
with check (bucket_id = 'fuel_receipts' and (storage.foldername(name))[1] = auth.uid()::text);

create policy fuel_receipts_select_own
on storage.objects for select
using (bucket_id = 'fuel_receipts' and (storage.foldername(name))[1] = auth.uid()::text);

create policy fuel_receipts_update_own
on storage.objects for update
using (bucket_id = 'fuel_receipts' and (storage.foldername(name))[1] = auth.uid()::text);

create policy fuel_receipts_delete_own
on storage.objects for delete
using (bucket_id = 'fuel_receipts' and (storage.foldername(name))[1] = auth.uid()::text);

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
  p_ocr_confidence numeric DEFAULT NULL
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

  select owner_user_id, organization_id into v_owner, v_org
  from public.vehicles
  where id = p_vehicle_id;

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
    receipt_image_url, file_hash, ocr_source, ocr_confidence
  )
  values (
    p_vehicle_id, auth.uid(), v_org, p_purchase_date, p_state_code,
    p_gallons, p_price_per_gallon_usd, p_total_cost_usd, coalesce(p_fuel_type, 'diesel'),
    p_receipt_image_url, p_file_hash, p_ocr_source, p_ocr_confidence
  )
  returning * into v_row;

  return v_row;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.submit_fuel_purchase(uuid, date, numeric, text, numeric, numeric, text, text, text, boolean, numeric) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.submit_fuel_purchase(uuid, date, numeric, text, numeric, numeric, text, text, text, boolean, numeric) FROM anon;
GRANT EXECUTE ON FUNCTION public.submit_fuel_purchase(uuid, date, numeric, text, numeric, numeric, text, text, text, boolean, numeric) TO authenticated;
