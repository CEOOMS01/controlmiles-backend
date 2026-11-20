-- Driving school: a reminder the office shows to every instructor on the app's home (2026-11-19, owner request).
-- One message per school, written in Settings on the web panel (organizations_update_admin already limits who
-- can change it) and read by the instructors' app together with the rest of the organization row.

alter table public.organizations
  add column if not exists instructor_notice text,
  add column if not exists instructor_notice_updated_at timestamptz;

alter table public.organizations drop constraint if exists organizations_instructor_notice_len;
alter table public.organizations
  add constraint organizations_instructor_notice_len check (instructor_notice is null or char_length(instructor_notice) <= 500);
