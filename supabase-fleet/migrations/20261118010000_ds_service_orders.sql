-- Olympus Mont Systems LLC - ControlMiles Fleet
-- 2026-11-18, phase 1 step 4: a client picks a service on the school's portal and the school gets an
-- order "pending payment". The client pays the SCHOOL (at the school or on the school's own payment
-- page); the school marks the order paid. ControlMiles never takes the money.

create table if not exists public.ds_service_orders (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  service_id uuid references public.ds_services(id) on delete set null,
  branch_id uuid references public.branches(id) on delete set null,
  -- Snapshot: the price and name the client saw, even if the school edits the service later.
  service_name text not null check (char_length(service_name) between 1 and 80),
  price_cents integer not null check (price_cents between 0 and 10000000),
  client_name text not null check (char_length(client_name) between 2 and 120),
  client_email text check (client_email is null or char_length(client_email) <= 120),
  client_phone text check (client_phone is null or char_length(client_phone) <= 30),
  note text check (note is null or char_length(note) <= 500),
  status text not null default 'pending_payment' check (status in ('pending_payment', 'paid', 'cancelled')),
  decided_at timestamptz,
  created_at timestamptz not null default now(),
  check (client_email is not null or client_phone is not null)
);

create index if not exists ds_service_orders_org_idx on public.ds_service_orders (organization_id, status, created_at desc);

alter table public.ds_service_orders enable row level security;

drop policy if exists ds_service_orders_select on public.ds_service_orders;
create policy ds_service_orders_select on public.ds_service_orders for select to authenticated
  using (public.is_org_operator_or_above(organization_id) and public.fn_org_feature_internal(organization_id, 'student_portal'));

drop policy if exists ds_service_orders_update on public.ds_service_orders;
create policy ds_service_orders_update on public.ds_service_orders for update to authenticated
  using (public.is_org_operator_or_above(organization_id) and public.fn_org_feature_internal(organization_id, 'student_portal'))
  with check (public.is_org_operator_or_above(organization_id));

-- Only the status can change from the admin; everything else is what the client sent.
revoke update on public.ds_service_orders from authenticated;
grant update (status, decided_at) on public.ds_service_orders to authenticated;
grant select on public.ds_service_orders to authenticated;

insert into ops.domain_tables (tbl, domain) values ('ds_service_orders', 'driving_school') on conflict do nothing;

-- Public: create an order. Limits live here (the page has no captcha in phase 1).
create or replace function public.ds_public_order(p_slug text, p jsonb)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_org uuid;
  sv public.ds_services;
  v_name text := btrim(coalesce(p->>'client_name', ''));
  v_email text := nullif(lower(btrim(coalesce(p->>'client_email', ''))), '');
  v_phone text := nullif(btrim(coalesce(p->>'client_phone', '')), '');
  v_note text := left(nullif(btrim(coalesce(p->>'note', '')), ''), 500);
  v_id uuid;
begin
  select pg.organization_id into v_org
    from public.ds_public_pages pg
   where pg.slug = lower(p_slug) and pg.enabled
     and public.fn_org_feature_internal(pg.organization_id, 'student_portal');
  if v_org is null then raise exception 'NOT_AVAILABLE' using errcode = 'P0001'; end if;

  begin
    select * into sv from public.ds_services
     where id = (p->>'service_id')::uuid and organization_id = v_org and is_active;
  exception when others then
    raise exception 'INVALID' using errcode = 'P0001';
  end;
  if sv.id is null then raise exception 'INVALID' using errcode = 'P0001'; end if;

  if char_length(v_name) < 2 then raise exception 'NAME_REQUIRED' using errcode = 'P0001'; end if;
  if v_email is not null and v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'EMAIL' using errcode = 'P0001'; end if;
  if v_email is null and v_phone is null then raise exception 'CONTACT_REQUIRED' using errcode = 'P0001'; end if;

  delete from public.ds_service_orders where organization_id = v_org and status <> 'pending_payment' and created_at < now() - interval '2 years';
  if (select count(*) from public.ds_service_orders where organization_id = v_org and created_at > now() - interval '1 hour') >= 30 then
    raise exception 'BUSY' using errcode = 'P0001';
  end if;
  if (select count(*) from public.ds_service_orders o where o.organization_id = v_org and o.created_at > now() - interval '24 hours'
        and ((v_email is not null and o.client_email = v_email) or (v_phone is not null and o.client_phone = v_phone))) >= 5 then
    raise exception 'BUSY' using errcode = 'P0001';
  end if;

  insert into public.ds_service_orders (organization_id, service_id, branch_id, service_name, price_cents,
                                        client_name, client_email, client_phone, note)
  values (v_org, sv.id, sv.branch_id, sv.name, sv.price_cents, left(v_name, 120), left(v_email, 120), left(v_phone, 30), v_note)
  returning id into v_id;
  return jsonb_build_object('id', v_id, 'service', sv.name, 'price_cents', sv.price_cents);
end $$;

revoke all on function public.ds_public_order(text, jsonb) from public;
grant execute on function public.ds_public_order(text, jsonb) to anon, authenticated, service_role;
