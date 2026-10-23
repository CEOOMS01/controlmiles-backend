
-- Explicit user requirement: be able to switch between Gig/Fleet Admin/
-- Fleet Driver mode on the same account, persisting, for testing --
-- but also a genuinely useful capability for a real hybrid user (a
-- fleet owner who also drives personally sometimes). Validates real
-- underlying membership before allowing the switch -- you can't fake
-- your way into fleet_admin without actually owning an org, or into
-- fleet_driver without an active membership row. default_org_id is
-- preserved when switching to gig (not nulled), so switching back to
-- fleet_admin/fleet_driver later instantly restores the right org
-- instead of losing it.
create or replace function public.switch_account_mode(p_mode text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller uuid := auth.uid();
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

  if p_mode = 'fleet_admin' then
    select organization_id into v_org_id
    from public.organization_members
    where user_id = v_caller and member_role = 'owner' and is_active = true
    order by joined_at asc
    limit 1;

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
    where user_id = v_caller and member_role = 'driver' and is_active = true
    order by joined_at desc
    limit 1;

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
