-- "My child is not riding the bus" notices (2026-10-25). A parent (from the
-- Fleet app) or the office (when the parent calls) tells us a student will not
-- take the bus on a day: a medical appointment, they overslept and a parent is
-- driving them, they are sick at home. Until now such a child showed as
-- "Absent -- not picked up" and pulled the attendance rate down although the
-- parent had warned us.
--
-- Additive only: public.fn_rider_status (read by the driver app) is untouched;
-- the web layer reads this table to show "Notified" instead of "Absent".
-- Writes go through the two functions below (a guardian linked to the student,
-- or an operator/admin/owner of the organization); there is no direct write
-- policy. Reads: staff of the organization, and the guardians of the student.
insert into ops.domain_tables (tbl, domain) values ('student_ride_notices', 'school_bus') on conflict do nothing;

create table if not exists public.student_ride_notices (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  student_id uuid not null references public.students(id) on delete cascade,
  notice_date date not null,
  -- which bus: the morning one, the afternoon one, or both
  part text not null default 'am' check (part in ('am', 'pm', 'both')),
  reason text not null check (reason in ('medical', 'overslept', 'sick', 'other')),
  -- true: a parent takes the student to school (or picks them up) themselves;
  -- false: the student stays home that day.
  will_attend_school boolean not null default true,
  note text check (note is null or char_length(note) <= 300),
  reported_by uuid references auth.users(id) on delete set null,
  reported_by_role text not null check (reported_by_role in ('guardian', 'staff')),
  created_at timestamptz not null default now(),
  unique (student_id, notice_date)
);

create index if not exists student_ride_notices_org_date_idx on public.student_ride_notices (organization_id, notice_date);

alter table public.student_ride_notices enable row level security;

create policy student_ride_notices_select_staff on public.student_ride_notices for select to authenticated
  using (public.is_org_operator_or_above(organization_id));

create policy student_ride_notices_select_guardian on public.student_ride_notices for select to authenticated
  using (exists (
    select 1
      from public.school_guardians g
      join public.student_guardians sg on sg.guardian_id = g.id and sg.is_active
     where g.user_id = auth.uid() and g.is_active and sg.student_id = student_ride_notices.student_id
  ));

revoke all on public.student_ride_notices from anon;
revoke insert, update, delete on public.student_ride_notices from authenticated;

-- Who may write a notice for a student: staff of the organization, or an
-- active guardian linked to that student. Returns 'staff' / 'guardian'.
create or replace function public.fn_ride_notice_role(p_student_id uuid)
returns text
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.students where id = p_student_id and is_active;
  if v_org is null then raise exception 'Student not found'; end if;
  if public.is_org_operator_or_above(v_org) then return 'staff'; end if;
  if exists (
    select 1
      from public.school_guardians g
      join public.student_guardians sg on sg.guardian_id = g.id and sg.is_active
     where g.user_id = auth.uid() and g.is_active and sg.student_id = p_student_id
  ) then return 'guardian'; end if;
  raise exception 'Not authorized';
end $$;

create or replace function public.report_student_no_ride(
  p_student_id uuid,
  p_date date,
  p_part text,
  p_reason text,
  p_will_attend boolean,
  p_note text default null
) returns void
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_role text := public.fn_ride_notice_role(p_student_id);
  v_org uuid := (select organization_id from public.students where id = p_student_id);
  v_today date := public.fn_org_today(v_org);
begin
  if p_date is null or p_date < v_today or p_date > v_today + 30 then
    raise exception 'NOTICE_DATE_OUT_OF_RANGE';
  end if;
  if p_part not in ('am', 'pm', 'both') then raise exception 'Invalid part'; end if;
  if p_reason not in ('medical', 'overslept', 'sick', 'other') then raise exception 'Invalid reason'; end if;
  insert into public.student_ride_notices
    (organization_id, student_id, notice_date, part, reason, will_attend_school, note, reported_by, reported_by_role)
  values
    (v_org, p_student_id, p_date, p_part, p_reason, coalesce(p_will_attend, true),
     nullif(left(trim(coalesce(p_note, '')), 300), ''), auth.uid(), v_role)
  on conflict (student_id, notice_date) do update
    set part = excluded.part, reason = excluded.reason, will_attend_school = excluded.will_attend_school,
        note = excluded.note, reported_by = excluded.reported_by, reported_by_role = excluded.reported_by_role,
        created_at = now();
end $$;

create or replace function public.cancel_student_no_ride(p_student_id uuid, p_date date)
returns void
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_role text := public.fn_ride_notice_role(p_student_id);
  v_org uuid := (select organization_id from public.students where id = p_student_id);
begin
  if p_date is null or p_date < public.fn_org_today(v_org) then
    raise exception 'NOTICE_DATE_OUT_OF_RANGE';
  end if;
  delete from public.student_ride_notices where student_id = p_student_id and notice_date = p_date;
end $$;

revoke all on function public.fn_ride_notice_role(uuid) from public, anon, authenticated;
revoke all on function public.report_student_no_ride(uuid, date, text, text, boolean, text) from public, anon;
revoke all on function public.cancel_student_no_ride(uuid, date) from public, anon;
grant execute on function public.report_student_no_ride(uuid, date, text, text, boolean, text) to authenticated;
grant execute on function public.cancel_student_no_ride(uuid, date) to authenticated;
