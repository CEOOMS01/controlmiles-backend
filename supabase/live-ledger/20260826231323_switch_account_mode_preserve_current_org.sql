
-- Real bug caught immediately on first live test: switching gig ->
-- fleet_admin -> gig -> fleet_admin again for an account that owns
-- MULTIPLE orgs landed on a DIFFERENT org than the one active before
-- switching away ("first owned org by join date" instead of "the one
-- you actually had"). Fixed: if the account's current default_org_id
-- is still a valid org they hold the target role in, keep it; only
-- fall back to "first eligible org" if it isn't (e.g. switching into
-- fleet_admin for the first time with no prior default_org_id, or the
-- prior org was removed).
create or replace function public.switch_account_mode(p_mode text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller uuid := auth.uid();
  v_current_org_id uuid;
  v_org_id uuid;
begin
  if v_caller is null then
    raise exception 'Not authenticated';
  end if;

  if p_mode not in ('gig', 'fleet_admin', 'fleet_driver') then
    raise exception 'Invalid mode';
  end if;

  if p_mode = 'gig' then
    update public.profiles set account_type = 'gig' where id = v_caller;
    return;
  end if;

  select default_org_id into v_current_org_id from public.profiles where id = v_caller;

  if p_mode = 'fleet_admin' then
    select organization_id into v_org_id
    from public.organization_members
    where user_id = v_caller and organization_id = v_current_org_id
      and member_role = 'owner' and is_active = true;

    if v_org_id is null then
      select organization_id into v_org_id
      from public.organization_members
      where user_id = v_caller and member_role = 'owner' and is_active = true
      order by joined_at asc
      limit 1;
    end if;

    if v_org_id is null then
      raise exception 'You do not own a fleet organization yet.';
    end if;

    update public.profiles
    set account_type = 'fleet_admin', default_org_id = v_org_id
    where id = v_caller;
    return;
  end if;

  if p_mode = 'fleet_driver' then
    select organization_id into v_org_id
    from public.organization_members
    where user_id = v_caller and organization_id = v_current_org_id
      and member_role = 'driver' and is_active = true;

    if v_org_id is null then
      select organization_id into v_org_id
      from public.organization_members
      where user_id = v_caller and member_role = 'driver' and is_active = true
      order by joined_at desc
      limit 1;
    end if;

    if v_org_id is null then
      raise exception 'You are not an active driver in any fleet.';
    end if;

    update public.profiles
    set account_type = 'fleet_driver', default_org_id = v_org_id
    where id = v_caller;
    return;
  end if;
end;
$$;

revoke all on function public.switch_account_mode(text) from public;
revoke all on function public.switch_account_mode(text) from anon;
grant execute on function public.switch_account_mode(text) to authenticated;
