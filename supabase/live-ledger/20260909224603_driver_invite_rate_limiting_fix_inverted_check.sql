
-- BUG FIX (caught immediately after writing the previous migration,
-- before it was ever exercised live): check_rate_limit() returns TRUE
-- when the caller is UNDER the limit (allowed) and FALSE when over it --
-- confirmed by reading its own definition. The prior version of these two
-- functions had this backwards (`if v_limited then <block>`), which would
-- have blocked every FIRST request and let unlimited requests through
-- after the first one failed open via the exception handler in one case,
-- and in the other silently permitted every real invite... the exact
-- opposite of the intended fix. Renamed to v_allowed for clarity and
-- inverted the condition correctly this time.
create or replace function public.resolve_driver_invite(p_token text)
returns table(valid boolean, organization_name text, email text, account_exists boolean)
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $function$
declare
  v_hash text := encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_invite record;
  v_allowed boolean;
begin
  select public.check_rate_limit('resolve_driver_invite', v_hash, 20, 60) into v_allowed;
  if not v_allowed then
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
  v_allowed boolean;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if not public.is_org_admin_or_owner(p_org_id) then
    raise exception 'Only an org admin or owner can invite drivers';
  end if;

  select public.check_rate_limit('create_driver_invite', auth.uid()::text, 20, 3600) into v_allowed;
  if not v_allowed then
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
