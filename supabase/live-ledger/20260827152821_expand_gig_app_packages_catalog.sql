-- Explicit user request: expand gig-app detection coverage. All 4
-- verified live via WebSearch against Play Store listings before
-- inserting, not guessed:
--
-- - 'empower': the earlier pass left this out due to genuine ambiguity
--   between two unrelated real products both branded "Empower" --
--   resolved now because the user specifically named "Empower Driver",
--   which matches com.yazam.empower.driver's own Play Store listing
--   title exactly (the OTHER one is titled "Empower Delivery Driver",
--   package delivery.empower.driver, a different company).
-- - 'veho' / 'jitsu' / 'walmart_spark': brand-new GigApp entries (see
--   the same-day migration to lib/models/gig_app.dart) -- these
--   platforms had zero coverage in ControlMiles before, not even as a
--   manual selection option, let alone auto-detection.
insert into public.gig_app_packages (gig_app_id, package_name) values
  ('empower', 'com.yazam.empower.driver'),
  ('veho', 'com.vehotechnologies.Driver'),
  ('jitsu', 'com.axlehire.drive'),
  ('walmart_spark', 'com.walmart.sparkdriver');
