create or replace function public.ds_student_classes(p_student uuid)
returns table(block_id uuid, block_date date, start_time time, end_time time, status text,
              instructor_id uuid, vehicle_id uuid, session_id uuid, map_token text,
              minutes numeric, night_minutes numeric, miles numeric, evaluated boolean)
language plpgsql stable security definer set search_path to 'public' as $$
declare v_org uuid;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.is_org_operator_or_above(v_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(v_org, 'students');
  return query
  select b.id, b.block_date, b.start_time, b.end_time, b.status, b.driver_id, b.vehicle_id, b.session_id, s.map_token::text,
         n.minutes, n.night_minutes, n.miles,
         exists (select 1 from public.ds_evaluations e where e.shift_block_id = b.id)
    from public.shift_blocks b
    left join public.sessions s on s.id = b.session_id
    cross join lateral public.fn_ds_class_numbers(b.id) n
   where b.student_id = p_student and b.status <> 'cancelled'
   order by b.block_date desc, b.start_time desc;
end $$;
