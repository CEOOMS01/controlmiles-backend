-- Fleet was missing three pieces of the driver-invite work that Gig's 20260926120000 migration added
-- (found 2026-11-19: "Could not find the function public.resend_driver_invite"):
--   * driver_invites.slot_id FK now ON DELETE SET NULL
--   * trigger that cancels the pending invite when its slot is removed
--   * resend_driver_invite(p_invite_id)
-- create_driver_invite (slot reuse) and the operator select policy were already in Fleet.

do $$
declare c text;
begin
  select conname into c
  from pg_constraint
  where conrelid = 'public.driver_invites'::regclass
    and contype = 'f'
    and confrelid = 'public.fleet_driver_slots'::regclass;
  if c is not null then
    execute format('alter table public.driver_invites drop constraint %I', c);
  end if;
  alter table public.driver_invites
    add constraint driver_invites_slot_id_fkey
    foreign key (slot_id) references public.fleet_driver_slots(id) on delete set null;
end $$;

create or replace function public.trg_slot_delete_cancels_invite()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.driver_invites
     set status = 'expired'
   where slot_id = old.id and status = 'pending';
  return old;
end;
$$;

drop trigger if exists trg_slot_delete_cancels_invite on public.fleet_driver_slots;
create trigger trg_slot_delete_cancels_invite
  before delete on public.fleet_driver_slots
  for each row execute function public.trg_slot_delete_cancels_invite();

-- ------------------------------------------------------------------
-- 3. resend_driver_invite: a fresh link for the SAME driver row
-- ------------------------------------------------------------------
create or replace function public.resend_driver_invite(p_invite_id uuid)
returns text
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $function$
declare
  v_inv record;
  v_allowed boolean;
  v_token text;
  v_hash text;
  v_target_id uuid;
  v_target_account_type text;
  v_existing_membership uuid;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  select id, organization_id, email, first_name, last_name, slot_id, intended_role, status
    into v_inv
  from public.driver_invites
  where id = p_invite_id;

  if not found then
    raise exception 'Invitation not found';
  end if;

  if v_inv.status = 'accepted' then
    raise exception 'This invitation was already accepted';
  end if;

  if not public.is_org_operator_or_above(v_inv.organization_id) then
    raise exception 'Only an org admin, owner, or operator can resend invitations';
  end if;

  -- Same hierarchy as create_driver_invite: an admin/operator invitation can
  -- only be re-issued by someone who could have created it.
  if v_inv.intended_role = 'admin' and not public.is_org_owner(v_inv.organization_id) then
    raise exception 'Only the organization owner can resend an admin invitation';
  end if;
  if v_inv.intended_role = 'operator' and not public.is_org_admin_or_owner(v_inv.organization_id) then
    raise exception 'Only an org admin or owner can resend an operator invitation';
  end if;

  -- The driver row was removed (or claimed some other way): nothing to resend.
  if v_inv.slot_id is null then
    raise exception 'This driver was removed. Add them again to send a new invitation';
  end if;
  if exists (
    select 1 from public.fleet_driver_slots
    where id = v_inv.slot_id and claimed_by is not null
  ) then
    raise exception 'This driver already joined';
  end if;

  select public.check_rate_limit('resend_driver_invite', auth.uid()::text, 20, 3600) into v_allowed;
  if not v_allowed then
    raise exception 'Too many invitations sent recently. Try again later.';
  end if;

  select id, account_type into v_target_id, v_target_account_type
  from public.profiles
  where lower(email) = lower(v_inv.email)
  limit 1;

  if v_target_id is not null then
    if v_target_account_type = 'fleet_admin' then
      raise exception 'This person already owns their own fleet and cannot be invited as a driver';
    end if;
    select id into v_existing_membership
    from public.organization_members
    where organization_id = v_inv.organization_id and user_id = v_target_id and is_active = true;
    if v_existing_membership is not null then
      raise exception 'This person is already a member of this organization';
    end if;
  end if;

  update public.driver_invites
     set status = 'expired'
   where organization_id = v_inv.organization_id
     and lower(email) = lower(v_inv.email)
     and status = 'pending';

  v_token := encode(gen_random_bytes(24), 'hex');
  v_hash := encode(digest(v_token, 'sha256'), 'hex');

  insert into public.driver_invites
    (organization_id, email, token_hash, created_by, first_name, last_name, slot_id, intended_role)
  values
    (v_inv.organization_id, v_inv.email, v_hash, auth.uid(), v_inv.first_name, v_inv.last_name, v_inv.slot_id, v_inv.intended_role);

  return v_token;
end;
$function$;

revoke execute on function public.resend_driver_invite(uuid) from public, anon;
grant execute on function public.resend_driver_invite(uuid) to authenticated;
