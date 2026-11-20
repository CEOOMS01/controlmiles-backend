-- Fleet: driver invitations and driver slots belong to a branch (2026-11-20).
-- Before, every operator of a school saw (and could resend) every invitation. Now an invitation takes the branch of
-- the person who sends it (an owner or an all-branches admin sends branch-less ones), only people of that branch see
-- it, and the person who accepts lands in that branch.

alter table public.driver_invites add column if not exists branch_id uuid references public.branches(id) on delete set null;
alter table public.fleet_driver_slots add column if not exists branch_id uuid references public.branches(id) on delete set null;

drop trigger if exists tr_driver_invites_fill_branch on public.driver_invites;
create trigger tr_driver_invites_fill_branch before insert on public.driver_invites for each row execute function public.fn_fill_branch_from_actor();
drop trigger if exists tr_fleet_driver_slots_fill_branch on public.fleet_driver_slots;
create trigger tr_fleet_driver_slots_fill_branch before insert on public.fleet_driver_slots for each row execute function public.fn_fill_branch_from_actor();

drop policy if exists driver_invites_branch_gate on public.driver_invites;
create policy driver_invites_branch_gate on public.driver_invites as restrictive for all to authenticated
  using (public.fn_branch_gate(organization_id, branch_id));
drop policy if exists fleet_driver_slots_branch_gate on public.fleet_driver_slots;
create policy fleet_driver_slots_branch_gate on public.fleet_driver_slots as restrictive for all to authenticated
  using (public.fn_branch_gate(organization_id, branch_id));

create or replace function public.fn_invite_gate(p_invite uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select public.fn_branch_gate(i.organization_id, i.branch_id) from public.driver_invites i where i.id = p_invite), true)
$$;
revoke execute on function public.fn_invite_gate(uuid) from public, anon;

-- the person who accepts lands in the invitation's branch; resending is limited to the branch
do $$
declare d text;
begin
  select pg_get_functiondef('public.accept_driver_invite(text)'::regprocedure) into d;
  if position('v_invite.branch_id' in d) = 0 then
    d := replace(d, 'intended_role, first_name, last_name into v_invite', 'intended_role, first_name, last_name, branch_id into v_invite');
    d := replace(d, 'insert into public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
  values (v_invite.organization_id, v_caller, coalesce(v_invite.intended_role, ''driver''), true, now())',
      'insert into public.organization_members (organization_id, user_id, member_role, is_active, joined_at, branch_id)
  values (v_invite.organization_id, v_caller, coalesce(v_invite.intended_role, ''driver''), true, now(), v_invite.branch_id)');
    if position('v_invite.branch_id' in d) = 0 then raise exception 'accept_driver_invite anchors not found'; end if;
    execute d;
  end if;

  select pg_get_functiondef('public.resend_driver_invite(uuid)'::regprocedure) into d;
  if d not like '%fn_guard(%' then
    execute regexp_replace(d, '\mbegin\M', 'begin perform public.fn_guard(public.fn_invite_gate(p_invite_id));', 'i');
  end if;
end $$;
