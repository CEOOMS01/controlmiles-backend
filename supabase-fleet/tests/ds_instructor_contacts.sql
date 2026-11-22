-- Driving school: the number an instructor gets is the guardian's for a minor, the student's own for an adult
-- (2026-11-22). Never changes anything: it ends with an error whose text is the report.
-- A healthy report ends with "RESULT: OK". Looks at every student of the database (read only).
do $$
declare out text := ''; fails int := 0; r public.ds_students; shown text;
begin
  for r in select st.* from public.ds_students st loop
    shown := public.fn_ds_contact_phone(r);
    if public.fn_ds_is_minor(r.id) then
      if shown is distinct from nullif(trim(r.guardian_phone), '') then
        out := out || 'FAIL minor ' || r.first_name || ' shows ' || coalesce(shown, 'null') || E' instead of the guardian number\n'; fails := fails + 1;
      end if;
      if shown is not null and shown is not distinct from nullif(trim(r.phone), '') and r.phone is distinct from r.guardian_phone then
        out := out || 'FAIL minor ' || r.first_name || E' shows their own phone\n'; fails := fails + 1;
      end if;
    elsif shown is distinct from nullif(trim(r.phone), '') then
      out := out || 'FAIL adult ' || r.first_name || E' does not show their own phone\n'; fails := fails + 1;
    end if;
  end loop;
  out := out || case when fails = 0 then 'RESULT: OK' else 'RESULT: ' || fails || ' FAIL' end;
  raise exception E'DS INSTRUCTOR CONTACTS REPORT\n%', out;
end $$;
