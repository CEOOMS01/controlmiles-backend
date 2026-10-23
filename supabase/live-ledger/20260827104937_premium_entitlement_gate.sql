-- Real gap opened deliberately (explicit user ask): automatic trip
-- detection for ControlMiles Gig will be a paid premium feature.
-- Enforcement-only, same posture as multi_org_entitled
-- (20260826170000_multi_org_entitlement_gate.sql) -- no payment
-- processor is wired yet, this just gives the client something
-- authoritative to check before showing/enabling the auto-detect
-- toggle. Granting the flag today is a manual/support action, same as
-- multi_org_entitled; real billing needs the user to choose a
-- processor first.
alter table public.profiles
  add column if not exists premium_entitled boolean not null default false;

comment on column public.profiles.premium_entitled is
  'Gates paid Gig features (starting with automatic trip detection). Enforcement-only -- no payment processing wired yet, see multi_org_entitled for the same pattern.';
