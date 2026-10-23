create or replace function public.fn_org_effective_tier(p_org_id uuid)
returns text
language plpgsql
stable
security definer
set search_path to 'public'
as $$
declare
  v_tier text;
begin
  if not public.is_org_member(p_org_id) then
    return 'none';
  end if;

  select case
    when o.tier_enforcement_exempt then 'growth'
    when o.subscription_status in ('active', 'trialing') and o.subscription_tier = 'growth' then 'growth'
    when o.subscription_status in ('active', 'trialing') and o.subscription_tier = 'starter' then 'starter'
    when now() - o.created_at <= interval '5 days' then 'starter'
    else 'none'
  end
  into v_tier
  from public.organizations o
  where o.id = p_org_id;

  return v_tier;
end;
$$;
