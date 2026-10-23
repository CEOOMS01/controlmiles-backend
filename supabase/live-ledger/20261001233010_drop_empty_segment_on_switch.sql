create or replace function public.fn_drop_empty_switched_section(
  p_section_id uuid,
  p_into_section_id uuid
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  s public.session_sections%rowtype;
begin
  select * into s from public.session_sections where id = p_section_id;
  if not found
     or s.user_id is distinct from auth.uid()
     or s.section_status <> 'switched'
     or coalesce(s.total_miles, 0) >= 0.05
     or nullif(btrim(coalesce(s.notes, '')), '') is not null
     or s.start_odometer_image_url is not null
     or s.end_odometer_image_url is not null then
    return false;
  end if;

  if not exists (
    select 1 from public.session_sections t
     where t.id = p_into_section_id
       and t.id <> s.id
       and t.session_id = s.session_id
       and t.user_id = auth.uid()
  ) then
    return false;
  end if;

  update public.audit_events set section_id = p_into_section_id where section_id = s.id;
  update public.session_gps_breadcrumbs set section_id = p_into_section_id where section_id = s.id;
  delete from public.session_sections where id = s.id;
  return true;
end;
$$;

revoke execute on function public.fn_drop_empty_switched_section(uuid, uuid) from public, anon;
grant execute on function public.fn_drop_empty_switched_section(uuid, uuid) to authenticated;

create or replace function public.switch_gig_app_section(
  p_session_id uuid,
  p_old_section_id uuid,
  p_new_section_id uuid,
  p_new_gig_app text,
  p_new_irs_purpose text,
  p_old_total_miles double precision,
  p_old_total_duration_seconds integer,
  p_old_end_latitude double precision,
  p_old_end_longitude double precision
)
returns setof public.session_sections
language plpgsql
set search_path to 'public'
as $function$
declare
  v_org_id uuid;
begin
  select organization_id into v_org_id from public.sessions where id = p_session_id;

  if p_old_section_id is not null then
    update session_sections
    set section_status = 'switched',
        end_time = now(),
        total_miles = coalesce(p_old_total_miles, total_miles),
        total_duration_seconds = coalesce(p_old_total_duration_seconds, total_duration_seconds),
        end_latitude = p_old_end_latitude,
        end_longitude = p_old_end_longitude
    where id = p_old_section_id
      and user_id = auth.uid()
      and section_status in ('active', 'paused');
  end if;

  insert into session_sections (
    id, session_id, user_id, organization_id, gig_app, irs_purpose,
    section_status, total_miles, total_duration_seconds, start_time
  )
  values (
    p_new_section_id, p_session_id, auth.uid(), v_org_id, p_new_gig_app,
    case when p_new_gig_app = 'custom' then p_new_irs_purpose else 'business' end,
    'active', 0, 0, now()
  );

  if p_old_section_id is not null then
    perform public.fn_drop_empty_switched_section(p_old_section_id, p_new_section_id);
  end if;

  return query select * from session_sections where id = p_new_section_id;
end;
$function$;
