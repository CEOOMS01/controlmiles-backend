-- Restores the 2026-09-26 fix (driver_invite_resend_and_cleanup) that
-- 20261009170000_school_monitor_role overwrote: re-sending an invite to an
-- email whose earlier invite was never accepted REUSES that invite's
-- fleet_driver_slots row instead of minting another CM-D#### id.
-- Starts from the LIVE definition (monitor role, school-only monitors,
-- tier gate, rate limit) and adds only the reuse block.

create or replace function public.create_driver_invite(p_org_id uuid, p_email text, p_first_name text, p_last_name text, p_intended_role text default 'driver'::text)
returns text
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $function$
declare
  v_email text := lower(trim(p_email));
  v_first_name text := trim(p_first_name);
  v_last_name text := trim(p_last_name);
  v_target_id uuid;
  v_target_account_type text;
  v_existing_membership uuid;
  v_token text;
  v_hash text;
  v_allowed boolean;
  v_slot_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if p_intended_role not in ('driver', 'operator', 'admin', 'monitor') then
    raise exception 'Invalid role: %', p_intended_role;
  end if;

  if p_intended_role = 'monitor' and not exists (
    select 1 from public.organizations where id = p_org_id and industry_template = 'school_transport'
  ) then
    raise exception 'Bus monitors are only available for School transportation fleets';
  end if;

  if p_intended_role = 'admin' and not public.is_org_owner(p_org_id) then
    raise exception 'Only the organization owner can invite someone directly as an admin';
  end if;

  if p_intended_role = 'operator' and not public.is_org_admin_or_owner(p_org_id) then
    raise exception 'Only an org admin or owner can invite someone directly as an operator';
  end if;

  if not public.is_org_operator_or_above(p_org_id) then
    raise exception 'Only an org admin, owner, or operator can invite drivers';
  end if;

  if public.fn_org_effective_tier(p_org_id) = 'none' then
    raise exception 'FLEET_SUBSCRIPTION_REQUIRED';
  end if;

  select public.check_rate_limit('create_driver_invite', auth.uid()::text, 20, 3600) into v_allowed;
  if not v_allowed then
    raise exception 'Too many invites created recently. Try again later.';
  end if;

  if v_email = '' or v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    raise exception 'A valid email is required';
  end if;

  if v_first_name = '' or v_last_name = '' then
    raise exception 'First and last name are required';
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

  -- Reuse this person's slot when they were already invited and never
  -- accepted: a re-send must not mint another CM-D#### id.
  select s.id into v_slot_id
  from public.driver_invites i
  join public.fleet_driver_slots s on s.id = i.slot_id
  where i.organization_id = p_org_id
    and lower(i.email) = v_email
    and s.claimed_by is null
  order by i.created_at desc
  limit 1;

  update public.driver_invites
  set status = 'expired'
  where organization_id = p_org_id and lower(email) = v_email and status = 'pending';

  if v_slot_id is not null then
    update public.fleet_driver_slots
       set first_name = v_first_name, last_name = v_last_name
     where id = v_slot_id;
  else
    insert into public.fleet_driver_slots (organization_id, first_name, last_name, claim_code_hash, created_by)
    values (p_org_id, v_first_name, v_last_name, encode(gen_random_bytes(24), 'hex'), auth.uid())
    returning id into v_slot_id;
  end if;

  v_token := encode(gen_random_bytes(24), 'hex');
  v_hash := encode(digest(v_token, 'sha256'), 'hex');

  insert into public.driver_invites (organization_id, email, token_hash, created_by, first_name, last_name, slot_id, intended_role)
  values (p_org_id, v_email, v_hash, auth.uid(), v_first_name, v_last_name, v_slot_id, p_intended_role);

  return v_token;
end;
$function$;
