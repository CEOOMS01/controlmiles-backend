-- Student portal (2026-10-25): the balance was null for a student who never bought a
-- package, so the portal offered free times that booking then refused with
-- NO_BALANCE (the booking rule applies whenever the school sells packages). Now the
-- balance is returned (zeros included) whenever the school has an active package,
-- so the page can say "no hours left" before the student picks a time.
create or replace function public.fn_ds_portal_payload(p_student uuid)
 returns jsonb
 language plpgsql
 stable security definer
 set search_path to 'public'
as $function$
declare
  st public.ds_students;
  cfg public.ds_settings;
  bal record;
  v_booking boolean;
begin
  select * into st from public.ds_students where id = p_student;
  if st.id is null or not public.fn_org_feature_internal(st.organization_id, 'student_portal') then return null; end if;
  select * into cfg from public.ds_settings where organization_id = st.organization_id;
  bal := public.fn_ds_balance(st.id);
  v_booking := public.fn_org_feature_internal(st.organization_id, 'student_booking') and coalesce(cfg.booking_enabled, false)
               and st.status in ('registered', 'active') and st.program_id is not null;
  return public.fn_ds_student_snapshot(st.id) || jsonb_build_object(
    'certificates', coalesce((select jsonb_agg(jsonb_build_object('number', c.number, 'issued_at', c.issued_at, 'sha256', c.sha256) order by c.issued_at)
                                from public.ds_certificates c where c.student_id = st.id), '[]'::jsonb),
    'booking', jsonb_build_object(
       'enabled', v_booking,
       'cancel_free_hours', coalesce(cfg.cancel_free_hours, 24),
       'policy', cfg.cancellation_policy,
       'max_upcoming', coalesce(cfg.booking_max_upcoming, 2)),
    'balance', case when public.fn_org_feature_internal(st.organization_id, 'student_packages')
                     and (exists (select 1 from public.ds_student_packages where student_id = st.id)
                          or exists (select 1 from public.ds_packages where organization_id = st.organization_id and is_active))
                    then jsonb_build_object('purchased', bal.purchased, 'used', bal.used, 'booked', bal.booked,
                                            'available', bal.purchased - bal.used - bal.booked)
                    else null end,
    'sms', jsonb_build_object('available', public.fn_org_feature_internal(st.organization_id, 'sms_reminders'),
                              'consent', st.sms_consent_at is not null,
                              'phone', st.sms_consent_phone)
  );
end $function$;
