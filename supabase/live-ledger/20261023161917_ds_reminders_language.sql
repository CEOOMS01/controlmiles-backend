-- Driving school reminders in the student's language (audit 2026-10-23,
-- finding 9). Students can choose English or Spanish for their lessons
-- (ds_students.preferred_language) and that choice already decides which
-- instructors they are offered, but class reminders and "a lesson time
-- opened" emails were always sent in English. Both lists now carry the
-- student's language (null = English); the Edge Function send-class-reminders
-- writes the email in it.
-- A return type cannot change in place, so the two functions are dropped and
-- created again with the live bodies plus the new column.

drop function if exists public.ds_due_class_reminders();
create function public.ds_due_class_reminders()
returns table(shift_block_id uuid, organization_id uuid, school text, timezone text, block_date date,
              start_time time without time zone, student_first_name text, recipient text, instructor text, language text)
language sql
stable security definer
set search_path to 'public'
as $function$
  select b.id, b.organization_id, coalesce(o.report_display_name, o.name), coalesce(o.timezone, 'America/New_York'),
         b.block_date, b.start_time, st.first_name, lower(btrim(r.email)),
         nullif(concat_ws(' ', p.first_name, left(p.last_name, 1)), ''), st.preferred_language
    from public.shift_blocks b
    join public.organizations o on o.id = b.organization_id
    join public.ds_students st on st.id = b.student_id and st.status in ('registered', 'active')
    left join public.ds_programs pr on pr.id = st.program_id
    left join public.ds_settings cfg on cfg.organization_id = b.organization_id
    left join public.profiles p on p.id = b.driver_id
    cross join lateral (values (st.email), (case when coalesce(pr.notify_guardian, true) then st.guardian_email end)) as r(email)
   where b.status = 'scheduled'
     and r.email is not null and btrim(r.email) <> ''
     and (b.block_date + b.start_time) at time zone coalesce(o.timezone, 'America/New_York')
         between now() and now() + make_interval(hours => coalesce(cfg.reminder_hours, 24))
     and public.fn_org_feature_internal(b.organization_id, 'class_reminders')
     and not exists (select 1 from public.ds_reminders_sent x
                      where x.shift_block_id = b.id and x.recipient = lower(btrim(r.email)));
$function$;
revoke execute on function public.ds_due_class_reminders() from public, anon, authenticated;
grant execute on function public.ds_due_class_reminders() to service_role;

drop function if exists public.ds_due_slot_notices();
create function public.ds_due_slot_notices()
returns table(notice_id uuid, school text, block_date date, start_time time without time zone, instructor text,
              recipient text, first_name text, language text)
language sql
stable security definer
set search_path to 'public'
as $function$
  select n.id, coalesce(o.report_display_name, o.name), n.block_date, n.start_time,
         nullif(concat_ws(' ', p.first_name, left(p.last_name, 1)), ''), lower(btrim(r.email)), st.first_name,
         st.preferred_language
    from public.ds_slot_notices n
    join public.organizations o on o.id = n.organization_id
    join public.ds_settings cfg on cfg.organization_id = n.organization_id and cfg.booking_enabled
    left join public.ds_programs pr on pr.id = n.program_id
    left join public.profiles p on p.id = n.instructor_id
    join public.ds_students st on st.organization_id = n.organization_id and st.program_id = n.program_id
                              and st.status in ('registered', 'active') and st.id is distinct from n.freed_by_student
                              and exists (select 1 from public.ds_portal_links pl
                                           where pl.student_id = st.id and pl.revoked_at is null and pl.expires_at > now())
    cross join lateral (values (st.email), (case when coalesce(pr.notify_guardian, true) then st.guardian_email end)) as r(email)
   where n.sent_at is null
     and r.email is not null and btrim(r.email) <> ''
     and public.fn_org_feature_internal(n.organization_id, 'student_booking')
     and (n.block_date + n.start_time) at time zone coalesce(o.timezone, 'America/New_York') > now()
     and not exists (select 1 from public.shift_blocks b
                      where b.organization_id = n.organization_id and b.block_date = n.block_date
                        and b.status <> 'cancelled' and b.driver_id = n.instructor_id
                        and b.start_time < n.end_time and b.end_time > n.start_time);
$function$;
revoke execute on function public.ds_due_slot_notices() from public, anon, authenticated;
grant execute on function public.ds_due_slot_notices() to service_role;
