-- Close functions that only the server (service role) calls.
--
-- Found in the 2026-11-21 security review of the Fleet project: the baseline
-- copied from Gig revoked these from PUBLIC only, so anon and authenticated
-- kept their own explicit EXECUTE. Gig had them closed (revoke ... from anon,
-- authenticated). Fleet's own checks:
--   * ds_client_request_links(email) returns a working login token for any
--     email, to anyone with the public key: a client-portal account takeover.
--   * ds_client_open_link / ds_client_* act on a session or link token.
--   * ds_public_enroll skips the edge function's per-IP limit and Turnstile.
--   * check_rate_limit lets anyone fill edge_function_rate_limits.
-- Callers: the edge functions ds-portal-access and ds-public-enroll and the
-- other rate-limited edge functions use the service role, which keeps access.
-- The web's own calls (student portal token links, public booking page,
-- orders, trip map, report redeem) are NOT touched here.

revoke execute on function public.check_rate_limit(text, text, integer, integer) from public, anon, authenticated;
revoke execute on function public.ds_public_enroll(text, jsonb) from public, anon, authenticated;
revoke execute on function public.ds_client_request_links(text) from public, anon, authenticated;
revoke execute on function public.ds_client_link_info(text) from public, anon, authenticated;
revoke execute on function public.ds_client_open_link(text) from public, anon, authenticated;
revoke execute on function public.ds_client_home(text) from public, anon, authenticated;
revoke execute on function public.ds_client_sign_out(text) from public, anon, authenticated;
revoke execute on function public.ds_client_add_child(text, jsonb) from public, anon, authenticated;
revoke execute on function public.ds_client_slots(text, uuid) from public, anon, authenticated;
revoke execute on function public.ds_client_student_view(text, uuid) from public, anon, authenticated;
revoke execute on function public.ds_client_book(text, uuid, date, time) from public, anon, authenticated;
revoke execute on function public.ds_client_cancel(text, uuid, uuid) from public, anon, authenticated;
revoke execute on function public.ds_client_certificate(text, uuid, text) from public, anon, authenticated;
revoke execute on function public.ds_client_set_sms(text, uuid, boolean, text) from public, anon, authenticated;

-- The mutable search_path warnings (Gig has the same ones).
alter function public.fn_freeze_closed_session() set search_path = public;
alter function public.service_for_industry(text) set search_path = public;
alter function public.fn_sync_org_service() set search_path = public;
alter function public.fn_ds_student_address(public.ds_students) set search_path = public;
