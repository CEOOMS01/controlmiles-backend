do $do$
declare d text; n text;
begin
  d := pg_get_functiondef('public.generate_report_access_code(date,date,uuid,jsonb,uuid)'::regprocedure);
  n := replace(d,
    $a$from public.session_sections ss where ss.session_id = rp.session_id)$a$,
    $a$from public.session_sections ss where ss.session_id = rp.session_id and ss.total_miles >= 0.05)$a$);
  if n = d then
    raise exception 'section_ids pattern not found';
  end if;
  execute n;
end
$do$;
