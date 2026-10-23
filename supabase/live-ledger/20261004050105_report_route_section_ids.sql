do $do$
declare d text; n text;
begin
  d := pg_get_functiondef('public.generate_report_access_code(date,date,uuid,jsonb,uuid)'::regprocedure);
  n := replace(d,
    $a$'total_miles', rp.total_miles, 'map_token', rp.map_token$a$,
    $a$'total_miles', rp.total_miles, 'map_token', rp.map_token,
        'section_ids', (select case when count(*) > 1 then jsonb_agg(ss.id order by ss.start_time) end
                          from public.session_sections ss where ss.session_id = rp.session_id)$a$);
  if n = d then
    raise exception 'route_points pattern not found';
  end if;
  execute n;
end
$do$;
