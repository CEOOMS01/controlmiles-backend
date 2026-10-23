-- CRITICAL FIX #1: a signed-in user could PATCH their own profiles row and
-- flip premium_entitled / base_entitled / tier_enforcement_exempt /
-- multi_org_entitled (and other system columns) to unlock the whole app for
-- free. profiles_update_own only checks auth.uid()=id, with no column guard.
--
-- Enforcement: a BEFORE UPDATE trigger that rejects any change to a protected
-- column when the caller is the client role (authenticated/anon). It does NOT
-- fire for the privileged paths that legitimately change these columns:
--   * SECURITY DEFINER RPCs (create_organization, switch_default_organization,
--     claim_driver_slot, etc.) run as their owner -> current_user = 'postgres'
--   * the Stripe webhook uses the service_role key -> current_user = 'service_role'
-- so only a raw client-side write is blocked.

create or replace function public.fn_guard_profile_protected_columns()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $$
begin
  -- Only guard raw client writes; privileged callers (RPCs, webhook) pass through.
  if current_user in ('authenticated', 'anon') then
    if new.id                     is distinct from old.id
       or new.display_id          is distinct from old.display_id
       or new.email               is distinct from old.email
       or new.account_type        is distinct from old.account_type
       or new.is_active           is distinct from old.is_active
       or new.default_org_id      is distinct from old.default_org_id
       or new.base_entitled       is distinct from old.base_entitled
       or new.premium_entitled    is distinct from old.premium_entitled
       or new.multi_org_entitled  is distinct from old.multi_org_entitled
       or new.tier_enforcement_exempt is distinct from old.tier_enforcement_exempt
       or new.created_at          is distinct from old.created_at
    then
      raise exception 'PROTECTED_PROFILE_COLUMN: this field cannot be changed directly';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_guard_profile_protected_columns on public.profiles;
create trigger trg_guard_profile_protected_columns
  before update on public.profiles
  for each row
  execute function public.fn_guard_profile_protected_columns();
