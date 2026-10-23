-- Reference table (session's earlier confirmed FK: session_sections.gig_app
-- -> gig_apps(id), separate from gig_app_packages which is detection-only).
-- Wingz/Alto included here too (manual selection still needs to work even
-- with no detection package).
insert into public.gig_apps (id, name, is_active, sort_order) values
  ('grubhub', 'Grubhub', true, 14),
  ('gopuff', 'Gopuff', true, 15),
  ('curb', 'Curb', true, 16),
  ('point_pickup', 'Point Pickup', true, 17),
  ('skipcart', 'Skipcart', true, 18),
  ('dispatch', 'Dispatch', true, 19),
  ('deliverthat', 'DeliverThat', true, 20),
  ('wingz', 'Wingz', true, 21),
  ('hopskipdrive', 'HopSkipDrive', true, 22),
  ('alto', 'Alto', true, 23),
  ('goshare', 'GoShare', true, 24),
  ('curri', 'Curri', true, 25)
on conflict (id) do nothing;

-- Detection package mapping -- Wingz and Alto deliberately excluded (no
-- verified Android package for either, see the Dart-side catalog comment).
insert into public.gig_app_packages (gig_app_id, os, package_name) values
  ('grubhub', 'android', 'com.grubhub.driver'),
  ('gopuff', 'android', 'com.gopuff.godrive2.live'),
  ('curb', 'android', 'com.verifone.curb.driver'),
  ('curb', 'android', 'com.curb.one'),
  ('point_pickup', 'android', 'com.pointpickup.partner'),
  ('skipcart', 'android', 'com.skipcart.app.mobile.prod'),
  ('dispatch', 'android', 'com.dispatchit'),
  ('deliverthat', 'android', 'com.deliverthat.driver'),
  ('hopskipdrive', 'android', 'com.hopskipdrive.driver'),
  ('goshare', 'android', 'co.goshare.driverapp'),
  ('curri', 'android', 'com.Curri.Driver'),
  ('curri', 'android', 'com.Curri.RouteDriver')
on conflict do nothing;
