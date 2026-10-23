create or replace function public.fn_fold_empty_trip_sections(p_session_id uuid)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  r record;
  v_keep uuid;
  v_folded integer := 0;
begin
  for r in
    select id, start_time
      from public.session_sections
     where session_id = p_session_id
       and coalesce(total_miles, 0) < 0.05
       and section_status in ('closed', 'switched')
       and nullif(btrim(coalesce(notes, '')), '') is null
       and start_odometer_image_url is null
       and end_odometer_image_url is null
  loop
    select k.id into v_keep
      from public.session_sections k
     where k.session_id = p_session_id
       and coalesce(k.total_miles, 0) >= 0.05
     order by (k.start_time <= r.start_time) desc,
              abs(extract(epoch from (k.start_time - r.start_time)))
     limit 1;

    continue when v_keep is null;

    update public.audit_events set section_id = v_keep where section_id = r.id;
    update public.session_gps_breadcrumbs set section_id = v_keep where section_id = r.id;
    delete from public.session_sections where id = r.id;
    v_folded := v_folded + 1;
  end loop;
  return v_folded;
end;
$$;

revoke execute on function public.fn_fold_empty_trip_sections(uuid) from public, anon, authenticated;

create or replace function public.fn_discard_zero_mile_trip()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if coalesce(new.total_miles, 0) < 0.05
     and coalesce((select sum(ss.total_miles) from public.session_sections ss
                   where ss.session_id = new.id), 0) < 0.05 then
    delete from public.sessions where id = new.id;
  else
    perform public.fn_fold_empty_trip_sections(new.id);
  end if;
  return null;
end;
$$;

revoke execute on function public.fn_discard_zero_mile_trip() from public, anon, authenticated;
