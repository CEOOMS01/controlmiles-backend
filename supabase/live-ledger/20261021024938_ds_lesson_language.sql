alter table public.organization_members
  add column if not exists languages text[] not null default '{en}'
    check (cardinality(languages) between 1 and 2 and languages <@ array['en', 'es']);
alter table public.ds_students
  add column if not exists preferred_language text check (preferred_language in ('en', 'es'));
alter table public.ds_enrollment_requests
  add column if not exists preferred_language text check (preferred_language in ('en', 'es'));

create or replace function public.set_member_languages(p_organization_id uuid, p_user_id uuid, p_languages text[])
returns void language plpgsql security definer set search_path to 'public' as $$
declare
  v text[] := array(select distinct x from unnest(p_languages) x where x in ('en', 'es') order by 1);
begin
  if not public.is_org_admin_or_owner(p_organization_id) then raise exception 'Not authorized'; end if;
  if cardinality(v) = 0 then raise exception 'Pick at least one language' using errcode = 'P0001'; end if;
  update public.organization_members set languages = v
   where organization_id = p_organization_id and user_id = p_user_id;
end $$;
revoke execute on function public.set_member_languages(uuid, uuid, text[]) from public, anon;
grant execute on function public.set_member_languages(uuid, uuid, text[]) to authenticated;

create or replace function public.ds_portal_slots(p_token text)
returns jsonb language plpgsql stable security definer set search_path to 'public' as $$
declare
  l public.ds_portal_links := public.fn_ds_portal_link(p_token);
  st public.ds_students;
  pr public.ds_programs;
  cfg public.ds_settings;
  v_tz text;
begin
  if l.id is null then return null; end if;
  if not public.fn_org_feature_internal(l.organization_id, 'student_booking') then return null; end if;
  select * into cfg from public.ds_settings where organization_id = l.organization_id;
  if not coalesce(cfg.booking_enabled, false) then return null; end if;
  select * into st from public.ds_students where id = l.student_id;
  select * into pr from public.ds_programs where id = st.program_id and is_active;
  if pr.id is null or st.status not in ('registered', 'active') then return null; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = l.organization_id;
  return jsonb_build_object(
    'minutes', pr.class_minutes,
    'language', st.preferred_language,
    'slots', coalesce((
      select jsonb_agg(jsonb_build_object('date', t.block_date, 'start', t.start_time, 'end', t.end_time)
                       order by t.block_date, t.start_time)
        from (select distinct s.block_date, s.start_time, s.end_time
                from public.fn_ds_free_slots(l.organization_id, pr.class_minutes, (now() at time zone v_tz)::date,
                                             cfg.booking_horizon_days, cfg.booking_lead_hours) s
                join public.organization_members m
                  on m.organization_id = l.organization_id and m.user_id = s.instructor_id
               where st.preferred_language is null or st.preferred_language = any (m.languages)) t), '[]'::jsonb)
  );
end $$;

drop function if exists public.ds_portal_book(text, uuid, date, time without time zone);
create or replace function public.ds_portal_book(p_token text, p_date date, p_start time without time zone)
returns uuid language plpgsql security definer set search_path to 'public' as $$
declare
  l public.ds_portal_links := public.fn_ds_portal_link(p_token);
  st public.ds_students;
  pr public.ds_programs;
  cfg public.ds_settings;
  v_tz text;
  s record;
  bal record;
  v_upcoming int;
  v_id uuid;
begin
  if l.id is null then raise exception 'LINK_NOT_ACTIVE'; end if;
  perform public.fn_require_org_feature(l.organization_id, 'student_booking');
  select * into cfg from public.ds_settings where organization_id = l.organization_id;
  if not coalesce(cfg.booking_enabled, false) then raise exception 'BOOKING_OFF'; end if;
  select * into st from public.ds_students where id = l.student_id;
  select * into pr from public.ds_programs where id = st.program_id and is_active;
  if pr.id is null or st.status not in ('registered', 'active') then raise exception 'BOOKING_OFF'; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = l.organization_id;

  perform pg_advisory_xact_lock(hashtext(l.organization_id::text || p_date::text || p_start::text));

  select count(*) into v_upcoming from public.shift_blocks
   where student_id = st.id and status = 'scheduled' and (block_date + start_time) at time zone v_tz > now();
  if v_upcoming >= cfg.booking_max_upcoming then raise exception 'TOO_MANY_UPCOMING'; end if;

  if public.fn_org_feature_internal(l.organization_id, 'student_packages')
     and exists (select 1 from public.ds_packages where organization_id = l.organization_id and is_active) then
    bal := public.fn_ds_balance(st.id);
    if bal.purchased - bal.used - bal.booked < pr.class_minutes then raise exception 'NO_BALANCE'; end if;
  end if;

  select f.* into s
    from public.fn_ds_free_slots(l.organization_id, pr.class_minutes, p_date, 1, cfg.booking_lead_hours) f
    join public.organization_members m on m.organization_id = l.organization_id and m.user_id = f.instructor_id
   where f.start_time = p_start
     and p_date <= (now() at time zone v_tz)::date + cfg.booking_horizon_days
     and (st.preferred_language is null or st.preferred_language = any (m.languages))
   order by random()
   limit 1;
  if s.instructor_id is null then raise exception 'SLOT_TAKEN'; end if;

  insert into public.shift_blocks (organization_id, driver_id, vehicle_id, block_date, start_time, end_time, source,
                                   status, student_id, booked_via, note)
  values (l.organization_id, s.instructor_id, s.vehicle_id, s.block_date, s.start_time, s.end_time, 'one_off',
          'scheduled', st.id, 'portal', 'Booked online')
  returning id into v_id;
  return v_id;
end $$;
revoke execute on function public.ds_portal_book(text, date, time without time zone) from public;
grant execute on function public.ds_portal_book(text, date, time without time zone) to anon, authenticated;
