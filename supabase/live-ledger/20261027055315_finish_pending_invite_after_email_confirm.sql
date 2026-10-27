-- Applied to production 2026-10-27 as version 20261027055315.
--
-- Invite flow: a driver who creates the account from the invite page has to confirm the
-- email first (Supabase asks for it). The confirmation page then sent them to the app "to
-- sign in with email and password", and the invitation stayed pending (no membership,
-- driver ID unclaimed), so the ID login always failed. These two functions let the
-- confirmation page finish the join:
--   my_pending_invite()          what the signed-in user was invited to (their own email only)
--   accept_my_pending_invite()   accepts it, exactly like accept_driver_invite, but finds the
--                                invite by the user's own CONFIRMED email instead of the link token.
-- Confirming the mailbox proves the same thing the link token does (that the person reads
-- that inbox), and an unconfirmed account (e.g. someone pre-registering another person's
-- email) can never use it.
create or replace function public.my_pending_invite()
returns table(organization_name text, intended_role text, display_id text)
language sql
stable
security definer
set search_path to 'public'
as $$
  select o.name, coalesce(i.intended_role, 'driver'), s.display_id
    from public.driver_invites i
    join public.profiles p on lower(p.email) = lower(i.email)
    join public.organizations o on o.id = i.organization_id
    join auth.users u on u.id = p.id
    left join public.fleet_driver_slots s on s.id = i.slot_id
   where p.id = auth.uid()
     and u.email_confirmed_at is not null
     and i.status = 'pending'
     and i.expires_at > now()
   order by i.created_at desc
   limit 1;
$$;
revoke execute on function public.my_pending_invite() from public, anon;
grant execute on function public.my_pending_invite() to authenticated;

create or replace function public.accept_my_pending_invite()
returns uuid
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_caller uuid := auth.uid();
  v_email text;
  v_account_type text;
  v_confirmed timestamptz;
  v_invite record;
begin
  if v_caller is null then raise exception 'Authentication required'; end if;

  select p.email, p.account_type, u.email_confirmed_at into v_email, v_account_type, v_confirmed
    from public.profiles p join auth.users u on u.id = p.id where p.id = v_caller;
  if v_confirmed is null then raise exception 'Confirm your email first'; end if;
  if v_account_type = 'fleet_admin' then
    raise exception 'You already manage your own fleet and cannot join another as a driver';
  end if;

  select id, organization_id, slot_id, intended_role into v_invite
    from public.driver_invites
   where status = 'pending' and expires_at > now() and lower(email) = lower(v_email)
   order by created_at desc
   limit 1;
  if not found then raise exception 'Invalid or expired invite'; end if;

  insert into public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
  values (v_invite.organization_id, v_caller, coalesce(v_invite.intended_role, 'driver'), true, now())
  on conflict (organization_id, user_id) do update set is_active = true, joined_at = now();

  update public.profiles set account_type = 'fleet_driver', default_org_id = v_invite.organization_id
   where id = v_caller;

  insert into public.user_onboarding (user_id, account_type_chosen) values (v_caller, true)
  on conflict (user_id) do update set account_type_chosen = true;

  update public.driver_invites set status = 'accepted', accepted_by = v_caller where id = v_invite.id;

  if v_invite.slot_id is not null then
    update public.fleet_driver_slots set claimed_by = v_caller, claimed_at = now()
     where id = v_invite.slot_id and claimed_by is null;
  end if;

  return v_invite.organization_id;
end;
$function$;
revoke execute on function public.accept_my_pending_invite() from public, anon;
grant execute on function public.accept_my_pending_invite() to authenticated;
