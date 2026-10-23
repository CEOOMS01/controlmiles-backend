-- Traffic-safety review (2026-09-09, explicit user request: layered
-- protection against mass/accidental clicks -- frontend debounce+disable,
-- backend rate limiting, DB constraints/timeouts). Auditing what already
-- exists (frontend disable-on-submit is now everywhere; statement_timeout
-- is already tuned per-role: anon=3s, authenticated=8s; UNIQUE
-- constraints already cover the real duplicate-row risks) surfaced one
-- genuine gap: create_organization's "you already own a fleet" check
-- (added in 20260826180000_fix_account_type_chosen_atomicity.sql) reads
-- organization_members with a plain SELECT COUNT, then INSERTs later in
-- the same function -- not atomic against two near-simultaneous calls
-- from the same brand-new account (e.g. a double-click before the
-- frontend's own disabled-on-submit state has painted, or two tabs).
-- Both could pass the count=0 check before either commits its INSERT,
-- letting one account create 2 "first" organizations and bypassing the
-- one-owned-org rule for non-multi_org_entitled accounts.
--
-- Fixed with a transaction-scoped advisory lock keyed to the caller's
-- own user id (pg_advisory_xact_lock, auto-released at commit/rollback,
-- no separate unlock call needed) -- a second concurrent call from the
-- same user blocks until the first transaction finishes, so its count
-- check always sees the first call's result. hashtext() collapses the
-- uuid to a lock key; a false-positive hash collision between two
-- different users only costs unrelated callers a brief serialization
-- wait, never a wrong result, since the actual authorization check
-- underneath is unchanged.

create or replace function public.create_organization(p_name text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  v_org_id uuid;
  v_owned_count int;
  v_entitled boolean;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if p_name is null or length(trim(p_name)) = 0 then
    raise exception 'Organization name is required';
  end if;

  perform pg_advisory_xact_lock(hashtext('create_organization:' || auth.uid()::text));

  select count(*) into v_owned_count
  from public.organization_members
  where user_id = auth.uid() and member_role = 'owner';

  select multi_org_entitled into v_entitled
  from public.profiles where id = auth.uid();

  if v_owned_count >= 1 and not coalesce(v_entitled, false) then
    raise exception 'You already own a fleet organization. Creating more than one requires the multi-fleet add-on.';
  end if;

  insert into public.organizations (name, created_by)
  values (trim(p_name), auth.uid())
  returning id into v_org_id;

  insert into public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
  values (v_org_id, auth.uid(), 'owner', true, now());

  update public.profiles
  set account_type = 'fleet_admin', default_org_id = v_org_id
  where id = auth.uid();

  insert into public.user_onboarding (user_id, account_type_chosen)
  values (auth.uid(), true)
  on conflict (user_id) do update set account_type_chosen = true;

  return v_org_id;
end;
$$;

revoke all on function public.create_organization(text) from public;
revoke all on function public.create_organization(text) from anon;
grant execute on function public.create_organization(text) to authenticated;
