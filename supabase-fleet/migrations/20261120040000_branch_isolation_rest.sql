-- Fleet: finish the branch fence (2026-11-20).
--  1. fuel anomalies, school clients (portal contacts) and their links respect the branch;
--  2. the FIRST branch a school creates adopts everything that exists so far (cars, students, staff, upcoming
--     classes), so nobody is left looking at an empty school and the owner does not have to move things by hand.

-- a client (portal contact) is seen when any of its students is in reach, and handled only when all of them are
create or replace function public.fn_client_see(p_client uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select not exists (select 1 from public.ds_client_students l where l.client_id = c.id and l.is_active)
                       or exists (select 1 from public.ds_client_students l where l.client_id = c.id and l.is_active
                                    and public.fn_student_gate(l.student_id))
                     from public.ds_clients c where c.id = p_client), true)
$$;
create or replace function public.fn_client_gate(p_client uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.ds_client_students l where l.client_id = p_client and l.is_active
                       and not public.fn_student_gate(l.student_id))
$$;
create or replace function public.fn_anomaly_gate(p_anomaly uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select public.fn_vehicle_gate(a.vehicle_id) from public.fuel_anomalies a where a.id = p_anomaly), true)
$$;
revoke execute on function public.fn_client_see(uuid), public.fn_client_gate(uuid), public.fn_anomaly_gate(uuid) from public, anon;

drop policy if exists ds_clients_branch_gate on public.ds_clients;
create policy ds_clients_branch_gate on public.ds_clients as restrictive for all to authenticated using (public.fn_client_see(id));
drop policy if exists fuel_anomalies_branch_gate on public.fuel_anomalies;
create policy fuel_anomalies_branch_gate on public.fuel_anomalies as restrictive for all to authenticated using (public.fn_vehicle_gate(vehicle_id));

do $$
declare r record; d text;
begin
  for r in select * from (values
    ('review_fuel_anomaly', 'perform public.fn_guard(public.fn_anomaly_gate(p_anomaly_id));'),
    ('ds_client_revoke', 'perform public.fn_guard(public.fn_client_gate(p_client));'),
    ('ds_client_welcome_link', 'perform public.fn_guard(public.fn_client_gate(p_client));'),
    ('ds_client_unlink', 'perform public.fn_guard(public.fn_student_gate(p_student));')
  ) as t(fname, guard) loop
    select pg_get_functiondef(p.oid) into d from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname = r.fname limit 1;
    if d is null then raise exception 'function % not found', r.fname; end if;
    if d like '%fn_guard(%' then continue; end if;
    execute regexp_replace(d, '\mbegin\M', 'begin ' || r.guard, 'i');
  end loop;
end $$;

-- the first branch adopts what already exists
create or replace function public.fn_first_branch_adopts() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from public.branches b where b.organization_id = new.organization_id) = 1 then
    update public.vehicles set branch_id = new.id where organization_id = new.organization_id and branch_id is null;
    update public.ds_students set branch_id = new.id where organization_id = new.organization_id and branch_id is null;
    update public.organization_members set branch_id = new.id
     where organization_id = new.organization_id and branch_id is null and not coalesce(any_branch, false) and member_role <> 'owner';
    update public.shift_blocks set branch_id = new.id
     where organization_id = new.organization_id and branch_id is null and status = 'scheduled' and block_date >= current_date;
  end if;
  return new;
end $$;
revoke execute on function public.fn_first_branch_adopts() from public, anon, authenticated;
drop trigger if exists tr_first_branch_adopts on public.branches;
create trigger tr_first_branch_adopts after insert on public.branches for each row execute function public.fn_first_branch_adopts();
