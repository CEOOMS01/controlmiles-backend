-- The gig plan as one readable value, derived from the two entitlements so it can never
-- drift from them. recompute_personal_entitlements stays the only writer of those.
update public.profiles set base_entitled = true where premium_entitled and not base_entitled;

alter table public.profiles
  add constraint profiles_premium_includes_base check (not premium_entitled or base_entitled);

alter table public.profiles
  add column personal_plan text generated always as (
    case when premium_entitled then 'premium' when base_entitled then 'basic' else 'none' end
  ) stored;
