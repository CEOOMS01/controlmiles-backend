create table if not exists public.play_subscriptions (
  purchase_token text primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  product_id text not null,
  tier text not null check (tier in ('base', 'premium')),
  order_id text,
  state text not null,
  expiry_time timestamptz,
  auto_renewing boolean,
  linked_purchase_token text,
  raw jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists play_subscriptions_user_idx on public.play_subscriptions (user_id);

alter table public.play_subscriptions enable row level security;

drop policy if exists play_subscriptions_select_own on public.play_subscriptions;
create policy play_subscriptions_select_own on public.play_subscriptions
  for select to authenticated using (user_id = auth.uid());
revoke insert, update, delete on public.play_subscriptions from anon, authenticated;

create or replace function public.recompute_personal_entitlements(p_user uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_base boolean;
  v_premium boolean;
begin
  with sources as (
    select tier from public.play_subscriptions
     where user_id = p_user
       and expiry_time > now()
       and state in ('SUBSCRIPTION_STATE_ACTIVE',
                     'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                     'SUBSCRIPTION_STATE_CANCELED')
    union all
    select coalesce(tier, 'premium') from public.subscriptions
     where user_id = p_user
       and status in ('active', 'trialing')
       and (current_period_end is null or current_period_end > now())
  )
  select count(*) > 0, bool_or(tier = 'premium')
    into v_base, v_premium
    from sources;

  update public.profiles
     set base_entitled = coalesce(v_base, false),
         premium_entitled = coalesce(v_premium, false)
   where id = p_user;
end;
$$;

revoke execute on function public.recompute_personal_entitlements(uuid) from public, anon, authenticated;

create or replace function public.expire_lapsed_play_subscriptions()
returns integer language plpgsql security definer set search_path = public as $$
declare
  r record;
  n integer := 0;
begin
  for r in
    select distinct p.id
      from public.profiles p
      join public.play_subscriptions s on s.user_id = p.id
     where (p.base_entitled or p.premium_entitled)
       and s.expiry_time <= now()
  loop
    perform public.recompute_personal_entitlements(r.id);
    n := n + 1;
  end loop;
  return n;
end;
$$;

revoke execute on function public.expire_lapsed_play_subscriptions() from public, anon, authenticated;

select cron.schedule(
  'expire-lapsed-play-subscriptions',
  '23 * * * *',
  $$select public.expire_lapsed_play_subscriptions()$$
);
