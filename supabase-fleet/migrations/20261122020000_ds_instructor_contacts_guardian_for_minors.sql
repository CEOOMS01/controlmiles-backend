-- Driving school: an instructor never contacts a minor directly, only the guardian who enrolled them (2026-11-22).
--
-- Until now the schedule gave the instructor `ds_students.phone` (the student's own number) for every student.
-- For a minor the number the instructor sees (and the Call / Message buttons use) is now the guardian's
-- `guardian_phone`; with no guardian number there is simply no number (the app already shows "no phone").
-- An adult, or an emancipated minor, keeps their own number. fn_ds_is_minor already applies the school's age of
-- majority and the emancipation date.

create or replace function public.fn_ds_contact_phone(st public.ds_students) returns text
language sql stable security definer set search_path = public as $$
  select case when public.fn_ds_is_minor(st.id) then nullif(trim(st.guardian_phone), '')
              else nullif(trim(st.phone), '') end
$$;
create or replace function public.fn_ds_contact_is_guardian(st public.ds_students) returns boolean
language sql stable security definer set search_path = public as $$
  select public.fn_ds_is_minor(st.id)
$$;
revoke execute on function public.fn_ds_contact_phone(public.ds_students) from public, anon;
revoke execute on function public.fn_ds_contact_is_guardian(public.ds_students) from public, anon;

do $$
declare f regprocedure; d text; nd text;
begin
  foreach f in array array['public.get_branch_schedule(uuid,date,integer)'::regprocedure, 'public.my_next_class(uuid)'::regprocedure] loop
    d := pg_get_functiondef(f);
    nd := replace(d, 'nullif(trim(st.phone), '''')', 'public.fn_ds_contact_phone(st)');
    if nd = d then raise exception '% : marker not found', f; end if;
    if f::text like 'get_branch_schedule%' then
      nd := replace(nd, '''student_phone'', ', '''student_contact_is_guardian'', public.fn_ds_contact_is_guardian(st), ''student_phone'', ');
    end if;
    execute nd;
  end loop;
end $$;
