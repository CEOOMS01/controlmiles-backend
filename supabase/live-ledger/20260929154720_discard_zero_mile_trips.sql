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
  end if;
  return null;
end;
$$;

revoke execute on function public.fn_discard_zero_mile_trip() from public, anon, authenticated;

drop trigger if exists trg_discard_zero_mile_trip on public.sessions;
create trigger trg_discard_zero_mile_trip
  after update of is_closed on public.sessions
  for each row
  when (new.is_closed and not coalesce(old.is_closed, false))
  execute function public.fn_discard_zero_mile_trip();

do $mig$
declare
  v_def text := pg_get_functiondef('public.generate_report_access_code(date,date,uuid,jsonb,uuid)'::regprocedure);
  v_new text;
begin
  v_new := replace(v_def,
    'and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)',
    'and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
      and coalesce(s.total_miles, 0) >= 0.05');
  if v_new = v_def then
    raise exception 'pattern not found, function unchanged';
  end if;
  execute v_new;
end
$mig$;
