drop policy if exists onboarding_insert_blocked on public.user_onboarding;
drop policy if exists onboarding_insert_own on public.user_onboarding;
create policy onboarding_insert_own on public.user_onboarding
  for insert to authenticated
  with check (user_id = auth.uid());
