-- Correction: "Courial" (courial.com) was initially misread as Curri
-- (curri.com), a real but entirely unrelated company, before the user
-- pointed to the actual site. Remove the wrong entry, add the correct one.
-- No session_sections rows ever referenced 'curri' (added and corrected
-- within the same session, never shipped/used), so the delete is safe.
delete from public.gig_app_packages where gig_app_id = 'curri';
delete from public.gig_apps where id = 'curri';

insert into public.gig_apps (id, name, is_active, sort_order) values
  ('courial', 'Courial', true, 25)
on conflict (id) do nothing;

insert into public.gig_app_packages (gig_app_id, os, package_name) values
  ('courial', 'android', 'live.courial.partner')
on conflict do nothing;
