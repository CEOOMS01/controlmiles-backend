-- Fleet: the name the school typed in the invitation becomes the account's name (2026-11-19, owner request).
--
-- An instructor who signs up from the invitation link used to end up with their email prefix as first name
-- ("info.omsapp"), because the sign-up trigger falls back to it, so the app greeted them with that. The invite
-- already carries the real first and last name; accepting it now copies them into the profile whenever the
-- profile has no name of its own (empty, or just the email prefix). A name the person typed is never replaced.

create or replace function public.accept_driver_invite(p_token text) returns uuid
language plpgsql security definer set search_path to 'public', 'extensions' as $$
declare
  v_caller uuid := auth.uid();
  v_caller_email text;
  v_caller_account_type text;
  v_hash text := encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_invite record;
begin
  if v_caller is null then
    raise exception 'Authentication required';
  end if;

  select email, account_type into v_caller_email, v_caller_account_type
  from public.profiles where id = v_caller;

  if v_caller_account_type = 'fleet_admin' then
    raise exception 'You already manage your own fleet and cannot join another as a driver';
  end if;

  select id, organization_id, email, slot_id, intended_role, first_name, last_name into v_invite
  from public.driver_invites
  where token_hash = v_hash and status = 'pending' and expires_at > now()
  limit 1;

  if not found then
    raise exception 'Invalid or expired invite';
  end if;

  if lower(v_caller_email) != lower(v_invite.email) then
    raise exception 'This invite was sent to a different email address';
  end if;

  insert into public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
  values (v_invite.organization_id, v_caller, coalesce(v_invite.intended_role, 'driver'), true, now())
  on conflict (organization_id, user_id) do update
    set is_active = true, joined_at = now();

  update public.profiles
  set account_type = 'fleet_driver', default_org_id = v_invite.organization_id,
      first_name = case
        when nullif(btrim(coalesce(v_invite.first_name, '')), '') is not null
         and (nullif(btrim(coalesce(first_name, '')), '') is null or lower(first_name) = lower(split_part(email, '@', 1)))
        then btrim(v_invite.first_name) else first_name end,
      last_name = case
        when nullif(btrim(coalesce(v_invite.last_name, '')), '') is not null
         and nullif(btrim(coalesce(last_name, '')), '') is null
        then btrim(v_invite.last_name) else last_name end
  where id = v_caller;

  insert into public.user_onboarding (user_id, account_type_chosen)
  values (v_caller, true)
  on conflict (user_id) do update set account_type_chosen = true;

  update public.driver_invites
  set status = 'accepted', accepted_by = v_caller
  where id = v_invite.id;

  if v_invite.slot_id is not null then
    update public.fleet_driver_slots
    set claimed_by = v_caller, claimed_at = now()
    where id = v_invite.slot_id and claimed_by is null;
  end if;

  return v_invite.organization_id;
end;
$$;

-- Accounts that already joined with only their email prefix as a name: take the name from their invite.
update public.profiles p
set first_name = btrim(i.first_name),
    last_name = case when nullif(btrim(coalesce(p.last_name, '')), '') is null then btrim(i.last_name) else p.last_name end
from (
  select distinct on (accepted_by) accepted_by, first_name, last_name
  from public.driver_invites
  where status = 'accepted' and accepted_by is not null and nullif(btrim(coalesce(first_name, '')), '') is not null
  order by accepted_by, created_at desc
) i
where i.accepted_by = p.id
  and (nullif(btrim(coalesce(p.first_name, '')), '') is null or lower(p.first_name) = lower(split_part(p.email, '@', 1)));
