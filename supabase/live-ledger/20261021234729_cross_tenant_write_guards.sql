create or replace function public.fn_guard_session_tenant()
returns trigger language plpgsql security definer set search_path to 'public' as $$
declare
  v record;
begin
  if tg_op = 'UPDATE' then
    if new.user_id is distinct from old.user_id or new.organization_id is distinct from old.organization_id then
      raise exception 'TRIP_OWNER_LOCKED' using errcode = 'P0001';
    end if;
    if new.vehicle_id is not distinct from old.vehicle_id then
      return new;
    end if;
  end if;

  if new.vehicle_id is not null then
    select owner_user_id, organization_id into v from public.vehicles where id = new.vehicle_id;
    -- coalesce: a company vehicle has no owner_user_id, and a null here
    -- would let the check pass.
    if not found
       or not coalesce((new.organization_id is null and v.owner_user_id = new.user_id)
                       or (new.organization_id is not null and v.organization_id = new.organization_id), false) then
      raise exception 'VEHICLE_NOT_YOURS' using errcode = 'P0001';
    end if;
  end if;
  return new;
end $$;
revoke execute on function public.fn_guard_session_tenant() from public, anon, authenticated;

drop trigger if exists tr_sessions_guard_tenant on public.sessions;
create trigger tr_sessions_guard_tenant
  before insert or update of user_id, organization_id, vehicle_id on public.sessions
  for each row execute function public.fn_guard_session_tenant();

create or replace function public.fn_inherit_session_tenant()
returns trigger language plpgsql security definer set search_path to 'public' as $$
declare
  s record;
begin
  select user_id, organization_id into s from public.sessions where id = new.session_id;
  if not found or s.user_id is distinct from new.user_id then
    raise exception 'TRIP_NOT_YOURS' using errcode = 'P0001';
  end if;
  new.organization_id := s.organization_id;
  return new;
end $$;
revoke execute on function public.fn_inherit_session_tenant() from public, anon, authenticated;

drop trigger if exists tr_session_sections_inherit_tenant on public.session_sections;
create trigger tr_session_sections_inherit_tenant
  before insert or update of session_id, user_id, organization_id on public.session_sections
  for each row execute function public.fn_inherit_session_tenant();

drop trigger if exists tr_audit_events_inherit_tenant on public.audit_events;
create trigger tr_audit_events_inherit_tenant
  before insert on public.audit_events
  for each row execute function public.fn_inherit_session_tenant();

create or replace function public.fn_guard_maintenance_tenant()
returns trigger language plpgsql security definer set search_path to 'public' as $$
declare
  v record;
begin
  select owner_user_id, organization_id into v from public.vehicles where id = new.vehicle_id;
  if not found
     or not (coalesce(v.owner_user_id = new.user_id, false)
             or exists (select 1 from public.organization_members m
                         where m.organization_id = v.organization_id and m.user_id = new.user_id and m.is_active)) then
    raise exception 'VEHICLE_NOT_YOURS' using errcode = 'P0001';
  end if;
  new.organization_id := v.organization_id;
  return new;
end $$;
revoke execute on function public.fn_guard_maintenance_tenant() from public, anon, authenticated;

drop trigger if exists tr_maintenance_guard_tenant on public.vehicle_maintenance_records;
create trigger tr_maintenance_guard_tenant
  before insert or update of vehicle_id, user_id, organization_id on public.vehicle_maintenance_records
  for each row execute function public.fn_guard_maintenance_tenant();

create or replace function public.fn_is_org_creator(p_organization_id uuid)
returns boolean language sql stable security definer set search_path to 'public' as $$
  select exists (select 1 from public.organizations where id = p_organization_id and created_by = auth.uid());
$$;
revoke execute on function public.fn_is_org_creator(uuid) from public, anon;
grant execute on function public.fn_is_org_creator(uuid) to authenticated;

drop policy if exists org_members_insert_admin on public.organization_members;
create policy org_members_insert_admin on public.organization_members for insert to authenticated
  with check (
    is_org_owner(organization_id)
    or (is_org_admin_or_owner(organization_id) and member_role = any (array['driver', 'operator']))
    or (is_org_operator_or_above(organization_id) and member_role = 'driver')
    or (
      user_id = auth.uid()
      and fn_is_org_creator(organization_id)
      and not exists (select 1 from public.organization_members om2 where om2.organization_id = organization_members.organization_id)
    )
  );
