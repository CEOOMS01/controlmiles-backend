-- Fleet app (2026-10-26): an instructor sees their classes for the next days, not only
-- today (get_my_shift_day). Same rules: own classes only, cancelled ones left out,
-- weekly-template classes are materialized for those days first.
create or replace function public.get_my_upcoming_classes(p_org uuid, p_days int default 7)
returns jsonb
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_uid uuid := auth.uid();
  v_tz text;
  v_today date;
  v_n int := least(greatest(coalesce(p_days, 7), 1), 14);
  d date;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  if not public.fn_org_has_classes(p_org) then return '[]'::jsonb; end if;
  if not exists (select 1 from public.organization_members m
                  where m.organization_id = p_org and m.user_id = v_uid and m.is_active) then
    return '[]'::jsonb;
  end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_org;
  v_today := (now() at time zone v_tz)::date;
  for d in select (v_today + g)::date from generate_series(1, v_n) g loop
    perform public.materialize_shift_blocks(p_org, d);
  end loop;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
        'id', b.id,
        'date', b.block_date,
        'start_time', b.start_time,
        'end_time', b.end_time,
        'note', b.note,
        'vehicle_label', nullif(concat_ws(' ', v.make, v.model), ''),
        'vehicle_display_id', v.display_id,
        'student_name', nullif(concat_ws(' ', st.first_name, st.last_name), '')
      ) order by b.block_date, b.start_time)
      from public.shift_blocks b
      left join public.vehicles v on v.id = b.vehicle_id
      left join public.ds_students st on st.id = b.student_id
     where b.organization_id = p_org and b.driver_id = v_uid
       and b.block_date > v_today and b.block_date <= v_today + v_n
       and b.status = 'scheduled'
  ), '[]'::jsonb);
end $function$;
revoke execute on function public.get_my_upcoming_classes(uuid, int) from public, anon;
grant execute on function public.get_my_upcoming_classes(uuid, int) to authenticated;
