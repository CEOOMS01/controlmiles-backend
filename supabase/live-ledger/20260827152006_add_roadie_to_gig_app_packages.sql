-- Roadie was one of the two apps deliberately left out of the initial
-- catalog (2026-08-27) for lack of a verified package name -- verified
-- now via WebSearch against consistent Google Play + multiple APK
-- mirror sources: com.roadie.drive.android.app.
--
-- Empower stays out: genuinely ambiguous, two unrelated real products
-- share the "Empower" name (com.yazam.empower.driver, a rideshare
-- driver app by Yazam Inc, vs delivery.empower.driver, an unrelated
-- business delivery platform) -- not the same "old app / new app"
-- situation Amazon Flex was, no way to know which one ControlMiles's
-- 'empower' gig app actually refers to without asking the user.
insert into public.gig_app_packages (gig_app_id, package_name) values
  ('roadie', 'com.roadie.drive.android.app');
