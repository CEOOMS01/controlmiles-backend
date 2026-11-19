-- Driving school: service catalog with prices + how the SCHOOL collects payment (2026-11-18).
-- Fleet project only (oweekkdectvsigspyafu).
--
-- ControlMiles never touches the money a student pays the school. The school lists what it sells (a 36-hour
-- course, a DIP class, a re-evaluation...) and says how it is paid: at the school, or on the school's own
-- payment page (its own link, any provider). The embeddable page shows the price and sends the client there.
--   * ds_services: the school's catalog (price, optional minutes, optional single location).
--   * ds_settings.payment_mode / payment_link / payment_instructions.
--   * ds_public_page now also returns the active services and the payment way (still public, nothing private).

create table if not exists public.ds_services (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations(id) on delete cascade,
  branch_id uuid references public.branches(id) on delete set null,   -- null = every location
  name text not null,
  description text,
  kind text not null default 'product',
  price_cents integer not null default 0,
  minutes integer,
  is_active boolean not null default true,
  sort integer not null default 0,
  created_at timestamptz not null default now(),
  constraint ds_services_name_check check (length(btrim(name)) between 1 and 80),
  constraint ds_services_description_check check (description is null or length(description) <= 300),
  constraint ds_services_kind_check check (kind in ('lesson', 'group_class', 'product')),
  constraint ds_services_price_check check (price_cents >= 0 and price_cents <= 10000000),
  constraint ds_services_minutes_check check (minutes is null or (minutes >= 1 and minutes <= 100000))
);
create index if not exists ds_services_org_idx on public.ds_services (organization_id, is_active, sort);

alter table public.ds_services enable row level security;

create policy ds_services_select on public.ds_services for select to authenticated
  using (public.is_org_operator_or_above(organization_id) and public.fn_org_has_feature(organization_id, 'student_portal'));
create policy ds_services_write on public.ds_services to authenticated
  using (public.is_org_admin_or_owner(organization_id) and public.fn_org_has_feature(organization_id, 'student_portal'))
  with check (public.is_org_admin_or_owner(organization_id) and public.fn_org_has_feature(organization_id, 'student_portal'));

-- A branch must belong to the same school.
create or replace function public.fn_ds_services_branch_check() returns trigger
language plpgsql set search_path to 'public' as $$
begin
  if new.branch_id is not null
     and not exists (select 1 from public.branches b where b.id = new.branch_id and b.organization_id = new.organization_id) then
    raise exception 'BAD_BRANCH';
  end if;
  return new;
end $$;
drop trigger if exists ds_services_branch_check on public.ds_services;
create trigger ds_services_branch_check before insert or update on public.ds_services
  for each row execute function public.fn_ds_services_branch_check();

insert into ops.domain_tables (tbl, domain) values ('ds_services', 'driving_school') on conflict do nothing;

alter table public.ds_settings
  add column if not exists payment_mode text not null default 'at_school',
  add column if not exists payment_link text,
  add column if not exists payment_instructions text;
alter table public.ds_settings
  add constraint ds_settings_payment_mode_check check (payment_mode in ('at_school', 'link')),
  add constraint ds_settings_payment_link_check check (payment_link is null or (payment_link ~ '^https://' and length(payment_link) <= 300)),
  add constraint ds_settings_payment_instructions_check check (payment_instructions is null or length(payment_instructions) <= 500);

create or replace function public.ds_public_page(p_slug text) returns jsonb
language sql stable security definer set search_path to 'public' as $$
  select jsonb_build_object(
           'school', coalesce(nullif(btrim(o.report_display_name), ''), o.name),
           'intro', pg.intro,
           'min_age', pg.min_age,
           'age_of_majority', coalesce((select s.age_of_majority from public.ds_settings s where s.organization_id = o.id), 18),
           'terms_url', pg.terms_url,
           'programs', coalesce((select jsonb_agg(jsonb_build_object('id', p.id, 'name', p.name) order by p.sort, p.name)
                                   from public.ds_programs p where p.organization_id = o.id and p.is_active), '[]'::jsonb),
           'branches', coalesce((select jsonb_agg(jsonb_build_object('id', b.id, 'name', b.name) order by b.name)
                                   from public.branches b where b.organization_id = o.id and not b.is_archived), '[]'::jsonb),
           'services', coalesce((select jsonb_agg(jsonb_build_object(
                                          'id', sv.id, 'name', sv.name, 'description', sv.description, 'kind', sv.kind,
                                          'price_cents', sv.price_cents, 'minutes', sv.minutes, 'branch_id', sv.branch_id)
                                        order by sv.sort, sv.name)
                                   from public.ds_services sv where sv.organization_id = o.id and sv.is_active), '[]'::jsonb),
           'payment', (select jsonb_build_object(
                               'mode', s.payment_mode,
                               'link', case when s.payment_mode = 'link' then s.payment_link end,
                               'instructions', s.payment_instructions)
                         from public.ds_settings s where s.organization_id = o.id))
    from public.ds_public_pages pg
    join public.organizations o on o.id = pg.organization_id
   where pg.slug = lower(p_slug) and pg.enabled
     and public.fn_org_feature_internal(o.id, 'student_portal');
$$;
