
-- Pre-launch security audit finding: create_driver_invite and
-- resolve_driver_invite were the only two token/invite-redemption-style
-- functions in the project with NO rate limiting at all -- their two
-- structural siblings (redeem_report_access_code, claim_driver_slot)
-- both got dedicated attempts tables specifically because they're
-- anon/token-redemption surfaces. Reusing the existing generic
-- check_rate_limit() RPC (already proven correct under concurrency,
-- advisory-locked) instead of a new table, since neither function here
-- needs its own audit trail beyond a simple cap.
--
-- resolve_driver_invite is called directly by the mobile client via
-- PostgREST RPC (no Next.js layer in front of it the way the Report
-- Portal has), so a per-IP key isn't reliably available here the way it
-- is for redeem_report_access_code. The token itself is 192 bits of
-- randomness (gen_random_bytes(24)) -- brute-forcing the token value is
-- not the realistic threat the way an 8-character human-typed code is
-- for the other two flows. Rate-limiting by the TOKEN'S OWN HASH instead
-- closes the real risk that exists (a single leaked/shared invite link
-- being hammered) without inventing an unreliable IP-extraction path.
create or replace function public.resolve_driver_invite(p_token text)
returns table(valid boolean, organization_name text, email text, account_exists boolean)
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $function$
declare
  v_hash text := encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_invite record;
  v_limited boolean;
begin
  select public.check_rate_limit('resolve_driver_invite', v_hash, 20, 60) into v_limited;
  if v_limited then
    return query select false, null::text, null::text, null::boolean;
    return;
  end if;

  select i.email, i.organization_id, o.name as org_name
  into v_invite
  from public.driver_invites i
  join public.organizations o on o.id = i.organization_id
  where i.token_hash = v_hash
    and i.status = 'pending'
    and i.expires_at > now()
  limit 1;

  if not found then
    return query select false, null::text, null::text, null::boolean;
    return;
  end if;

  return query select
    true,
    v_invite.org_name,
    v_invite.email,
    exists(select 1 from public.profiles where lower(profiles.email) = lower(v_invite.email));
end;
$function$;

-- create_driver_invite: authenticated + admin-gated already, but nothing
-- stopped a compromised admin session (or a runaway client bug) from
-- minting invite tokens in a tight loop. 20/hour per admin is generous
-- for legitimate bulk onboarding, tight enough to cap abuse -- the actual
-- email send is separately rate-limited in send-driver-invite already.
create or replace function public.create_driver_invite(p_org_id uuid, p_email text)
returns text
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $function$
declare
  v_email text := lower(trim(p_email));
  v_target_id uuid;
  v_target_account_type text;
  v_existing_membership uuid;
  v_token text;
  v_hash text;
  v_limited boolean;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if not public.is_org_admin_or_owner(p_org_id) then
    raise exception 'Only an org admin or owner can invite drivers';
  end if;

  select public.check_rate_limit('create_driver_invite', auth.uid()::text, 20, 3600) into v_limited;
  if v_limited then
    raise exception 'Too many invites created recently. Try again later.';
  end if;

  if v_email = '' or v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    raise exception 'A valid email is required';
  end if;

  select id, account_type into v_target_id, v_target_account_type
  from public.profiles
  where lower(email) = v_email
  limit 1;

  if v_target_id is not null then
    if v_target_account_type = 'fleet_admin' then
      raise exception 'This person already owns their own fleet and cannot be invited as a driver';
    end if;

    select id into v_existing_membership
    from public.organization_members
    where organization_id = p_org_id and user_id = v_target_id and is_active = true;

    if v_existing_membership is not null then
      raise exception 'This person is already a member of this organization';
    end if;
  end if;

  update public.driver_invites
  set status = 'expired'
  where organization_id = p_org_id and lower(email) = v_email and status = 'pending';

  v_token := encode(gen_random_bytes(24), 'hex');
  v_hash := encode(digest(v_token, 'sha256'), 'hex');

  insert into public.driver_invites (organization_id, email, token_hash, created_by)
  values (p_org_id, v_email, v_hash, auth.uid());

  return v_token;
end;
$function$;
