-- Fix: the guard must be SECURITY INVOKER. As SECURITY DEFINER, current_user
-- inside the trigger was always the owner (postgres), so the client check never
-- matched and the guard was a no-op. As INVOKER, current_user reflects the real
-- caller: 'authenticated'/'anon' for a raw client write (blocked), 'postgres'
-- while inside a SECURITY DEFINER RPC (passes), 'service_role' for the webhook
-- (passes).
create or replace function public.fn_guard_profile_protected_columns()
returns trigger
language plpgsql
security invoker
set search_path to 'public'
as $$
begin
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
