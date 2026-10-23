alter table public.user_onboarding
  add column if not exists tour_seen text[] not null default '{}';
