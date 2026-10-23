-- User rule (2026-10-19): a driving school's or a school fleet's admin always
-- sees their drivers on the live map, on any plan.
create or replace function public.fn_org_feature_list_internal(p_org_id uuid)
returns text[] language plpgsql stable security definer set search_path to 'public'
as $$
declare
  v_tpl text;
  v_tier text;
  f text[] := '{}';
begin
  select industry_template into v_tpl from public.organizations where id = p_org_id;
  if v_tpl is null then
    return f;
  end if;
  v_tier := public.fn_org_tier_internal(p_org_id);
  if v_tier = 'none' then
    return f;
  end if;

  f := array['dvir'];
  if v_tpl in ('delivery', 'trucking', 'general') then f := f || 'owner_operators'::text; end if;
  if v_tpl in ('trucking', 'construction', 'general') then f := f || 'ifta'::text; end if;
  if v_tpl = 'school_transport' then f := f || 'school'::text; end if;
  if v_tpl = 'driving_school' then f := f || 'classes'::text; end if;
  if v_tpl in ('school_transport', 'driving_school') then f := f || 'live_map'::text; end if;

  if v_tier = 'growth' then
    if not 'live_map' = any(f) then f := f || 'live_map'::text; end if;
    f := f || array['fleet_export', 'activity_log', 'safety_scores', 'fuel_alerts',
                    'shift_schedules', 'open_assignment'];
    if v_tpl in ('delivery', 'field_service', 'trucking', 'construction', 'passenger', 'general') then
      f := f || 'routes'::text;
    end if;
    if v_tpl <> 'driving_school' then f := f || 'geofences'::text; end if;
    if v_tpl = 'school_transport' then f := f || 'school_live'::text; end if;
    if v_tpl = 'sales' then f := f || 'trip_approval'::text; end if;
  end if;
  return f;
end;
$$;
