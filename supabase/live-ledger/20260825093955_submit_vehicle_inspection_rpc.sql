
CREATE OR REPLACE FUNCTION public.submit_vehicle_inspection(
  p_vehicle_id uuid,
  p_inspection_type text,
  p_items jsonb,
  p_odometer numeric DEFAULT NULL
)
RETURNS public.vehicle_inspections
LANGUAGE plpgsql
SET search_path TO 'public'
AS $function$
declare
  v_owner uuid;
  v_org uuid;
  v_defect_count int;
  v_overall text;
  v_inspection public.vehicle_inspections;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if p_inspection_type not in ('pre_trip', 'post_trip') then
    raise exception 'Invalid inspection_type: %', p_inspection_type;
  end if;

  select owner_user_id, organization_id into v_owner, v_org
  from public.vehicles
  where id = p_vehicle_id;

  if not found then
    raise exception 'Vehicle not found';
  end if;

  if v_owner is distinct from auth.uid()
     and not (v_org is not null and public.is_org_member(v_org)) then
    raise exception 'Not authorized to inspect this vehicle';
  end if;

  select count(*) into v_defect_count
  from jsonb_array_elements(p_items) elem
  where elem->>'status' = 'defect';

  v_overall := case when v_defect_count > 0 then 'fail' else 'pass' end;

  insert into public.vehicle_inspections (
    vehicle_id, user_id, organization_id, inspection_type, overall_status, items, odometer
  )
  values (
    p_vehicle_id, auth.uid(), v_org, p_inspection_type, v_overall, p_items, p_odometer
  )
  returning * into v_inspection;

  if v_overall = 'fail' then
    insert into public.vehicle_maintenance_records (
      vehicle_id, user_id, organization_id, type, performed_at, odometer_at_service, notes
    )
    values (
      p_vehicle_id, auth.uid(), v_org, 'other', current_date, p_odometer,
      'Auto-created from failed ' || p_inspection_type || ' inspection: ' ||
      coalesce(
        (select string_agg(elem->>'category', ', ')
         from jsonb_array_elements(p_items) elem
         where elem->>'status' = 'defect'),
        ''
      )
    );
  end if;

  return v_inspection;
end;
$function$;

REVOKE EXECUTE ON FUNCTION public.submit_vehicle_inspection(uuid, text, jsonb, numeric) FROM anon;
