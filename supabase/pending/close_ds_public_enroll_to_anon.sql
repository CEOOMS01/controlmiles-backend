-- PENDING - apply ONLY after the web that calls the Edge Function
-- ds-public-enroll is deployed (controlmiles-web commit "ds-public-enroll").
-- Until then the live /book form still calls ds_public_enroll with the
-- public key, and this revoke would make every enrollment fail.
--
-- After the web deploy:
--   1. open a school's /book/<slug> page and send a test request;
--   2. apply this file as a migration (apply_migration name
--      "close_ds_public_enroll_to_anon") and move it to migrations/ with the
--      applied version.
-- Effect: the browser's public key can no longer call ds_public_enroll
-- directly; only the Edge Function (service role) can, so the per visitor IP
-- limit and the captcha cannot be skipped.

revoke execute on function public.ds_public_enroll(text, jsonb) from public, anon, authenticated;
grant execute on function public.ds_public_enroll(text, jsonb) to service_role;
