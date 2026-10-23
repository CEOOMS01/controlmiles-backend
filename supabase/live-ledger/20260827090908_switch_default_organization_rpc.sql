-- Real gap closed (explicit user ask, web admin panel): the real account
-- owns 2 organizations ("Hola Test", "Doble A Cargo Xpress") but the
-- admin panel just follows profiles.default_org_id -- no UI existed to
-- pick the other one. Built for testing now; the user's stated intent
-- is that managing multiple organizations from one account becomes a
-- paid extra in the future (see profiles.multi_org_entitled, which
-- already gates CREATING a 2nd org -- this RPC only lets someone switch
-- among orgs they already own/admin, not create new ones, so it doesn't
-- need its own entitlement check yet).
create or replace function public.switch_default_organization(p_org_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_caller uuid := auth.uid();
  v_ok boolean;
begin
  if v_caller is null then
    raise exception 'Not authenticated';
  end if;

  select exists(
    select 1 from public.organization_members
    where organization_id = p_org_id and user_id = v_caller
      and member_role in ('owner', 'admin') and is_active = true
  ) into v_ok;

  if not v_ok then
    raise exception 'You are not an admin of that organization';
  end if;

  update public.profiles set default_org_id = p_org_id where id = v_caller;
end;
$$;

revoke all on function public.switch_default_organization(uuid) from public;
revoke all on function public.switch_default_organization(uuid) from anon;
grant execute on function public.switch_default_organization(uuid) to authenticated;
