-- The public enrollment form now goes through the Edge Function
-- ds-public-enroll (per visitor IP limit, optional captcha). Closing the
-- database function to the browser's public key so those checks cannot be
-- skipped by calling it directly; only the Edge Function (service role) can.
revoke execute on function public.ds_public_enroll(text, jsonb) from public, anon, authenticated;
grant execute on function public.ds_public_enroll(text, jsonb) to service_role;
