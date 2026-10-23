create or replace function public.ds_student_progress(p_org uuid, p_student uuid default null)
returns table(student_id uuid, classes_done int, minutes numeric, night_minutes numeric, miles numeric,
              last_class date, next_class timestamptz, purchased_minutes numeric, evaluations int)
language plpgsql stable security definer set search_path to 'public' as $$
declare
  v_tz text;
begin
  if not public.is_org_operator_or_above(p_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(p_org, 'students');
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_org;
  return query
  with done as (
    select b.student_id sid, b.block_date, n.minutes, n.night_minutes, n.miles
      from public.shift_blocks b, lateral public.fn_ds_class_numbers(b.id) n
     where b.organization_id = p_org and b.student_id is not null and b.status = 'done'
       and (p_student is null or b.student_id = p_student)
  )
  select st.id,
         coalesce((select count(*)::int from done where sid = st.id), 0),
         coalesce((select sum(d.minutes) from done d where d.sid = st.id), 0),
         coalesce((select sum(d.night_minutes) from done d where d.sid = st.id), 0),
         coalesce((select round(sum(d.miles), 1) from done d where d.sid = st.id), 0),
         (select max(d.block_date) from done d where d.sid = st.id),
         (select min((b.block_date + b.start_time) at time zone v_tz) from public.shift_blocks b
           where b.student_id = st.id and b.status = 'scheduled'
             and (b.block_date + b.start_time) at time zone v_tz > now()),
         coalesce((select sum(sp.minutes)::numeric from public.ds_student_packages sp where sp.student_id = st.id), 0),
         coalesce((select count(*)::int from public.ds_evaluations e where e.student_id = st.id), 0)
    from public.ds_students st
   where st.organization_id = p_org and (p_student is null or st.id = p_student);
end $$;
