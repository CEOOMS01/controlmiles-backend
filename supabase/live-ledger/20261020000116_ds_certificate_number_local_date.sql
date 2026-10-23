create or replace function public.ds_issue_certificate(p_student uuid)
returns uuid language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare
  v_org uuid;
  v jsonb;
  v_id uuid := gen_random_uuid();
  v_number text;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(v_org, 'student_certificates');
  v := public.fn_ds_student_snapshot(p_student);
  if (v->>'minutes')::numeric < (v->>'required_minutes')::numeric
     or (v->>'night_minutes')::numeric < (v->>'required_night_minutes')::numeric then
    raise exception 'REQUIRED_HOURS_NOT_MET';
  end if;
  v_number := 'CM-' || to_char(now() at time zone (v->>'timezone'), 'YYYYMMDD') || '-' || upper(substr(replace(v_id::text, '-', ''), 1, 6));
  v := (v - 'upcoming') || jsonb_build_object('number', v_number, 'issued_at', now());
  insert into public.ds_certificates (id, number, organization_id, student_id, data, sha256, issued_by)
  values (v_id, v_number, v_org, p_student, v, encode(digest(v::text, 'sha256'), 'hex'), auth.uid());
  return v_id;
end $$;
