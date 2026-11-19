-- Olympus Mont Systems LLC - ControlMiles Fleet
-- 2026-11-19, phase 1 step 5: automatic payments with the school's own Banquest account.
-- ControlMiles never holds the money and takes no commission. The school connects its Banquest key;
-- the portal makes a one-time pay link for each order; Banquest tells us when it is paid (signed webhook).
-- The key and the webhook signature live in Supabase Vault; only the Edge Functions (service role) read them.

alter table public.ds_settings drop constraint if exists ds_settings_payment_mode_check;
alter table public.ds_settings add constraint ds_settings_payment_mode_check
  check (payment_mode in ('at_school', 'link', 'banquest'));

create table if not exists public.ds_payment_providers (
  organization_id uuid primary key references public.organizations(id) on delete cascade,
  provider text not null check (provider in ('banquest')),
  environment text not null default 'production' check (environment in ('sandbox', 'production')),
  page_slug text not null check (page_slug ~ '^[A-Za-z0-9_-]{2,80}$'),
  -- Secret part of the webhook address; the HMAC signature is the real proof.
  webhook_token text not null unique default (replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '')),
  webhook_id integer,
  source_key_secret uuid,
  signature_secret uuid,
  status text not null default 'connected' check (status in ('connected', 'error')),
  last_error text check (last_error is null or char_length(last_error) <= 300),
  connected_at timestamptz not null default now()
);

alter table public.ds_payment_providers enable row level security;
drop policy if exists ds_payment_providers_select on public.ds_payment_providers;
create policy ds_payment_providers_select on public.ds_payment_providers for select to authenticated
  using (public.is_org_admin_or_owner(organization_id) and public.fn_org_feature_internal(organization_id, 'student_portal'));
-- The admin sees the state, never the secrets or the webhook address.
revoke all on public.ds_payment_providers from anon, authenticated;
grant select (organization_id, provider, environment, page_slug, webhook_id, status, last_error, connected_at)
  on public.ds_payment_providers to authenticated;

insert into ops.domain_tables (tbl, domain) values ('ds_payment_providers', 'driving_school') on conflict do nothing;

-- Webhook events already handled (Banquest retries, so the same event can arrive more than once).
create table if not exists public.ds_payment_events (
  event_id text not null,
  organization_id uuid not null references public.organizations(id) on delete cascade,
  received_at timestamptz not null default now(),
  primary key (organization_id, event_id)
);
alter table public.ds_payment_events enable row level security;
revoke all on public.ds_payment_events from anon, authenticated;
insert into ops.domain_tables (tbl, domain) values ('ds_payment_events', 'driving_school') on conflict do nothing;

alter table public.ds_service_orders
  add column if not exists provider text check (provider is null or provider in ('banquest')),
  add column if not exists provider_key text,
  add column if not exists provider_ref text,
  add column if not exists payment_link text,
  add column if not exists paid_via text check (paid_via is null or paid_via in ('manual', 'banquest')),
  add column if not exists review_note text check (review_note is null or char_length(review_note) <= 300);
create unique index if not exists ds_service_orders_provider_ref_uq
  on public.ds_service_orders (organization_id, provider, provider_ref) where provider_ref is not null;
-- The admin can still change only status and decided_at (and the paid_via mark when it marks by hand).
grant update (paid_via) on public.ds_service_orders to authenticated;
grant select on public.ds_service_orders to authenticated;

-- ---------- Secrets: service role only ----------

create or replace function public.fn_ds_provider_store(
  p_org uuid, p_env text, p_slug text, p_source_key text, p_webhook_id integer, p_signature text)
returns text
language plpgsql security definer set search_path = public, vault as $$
declare
  old public.ds_payment_providers;
  v_key uuid;
  v_sig uuid;
  v_token text;
begin
  select * into old from public.ds_payment_providers where organization_id = p_org;
  if old.organization_id is not null then
    delete from vault.secrets where id in (old.source_key_secret, old.signature_secret);
  end if;
  v_key := vault.create_secret(p_source_key, 'banquest-key-' || p_org::text || '-' || extract(epoch from clock_timestamp())::bigint::text, 'Banquest source key');
  v_sig := vault.create_secret(p_signature, 'banquest-sig-' || p_org::text || '-' || extract(epoch from clock_timestamp())::bigint::text, 'Banquest webhook signature key');
  insert into public.ds_payment_providers (organization_id, provider, environment, page_slug, webhook_id, source_key_secret, signature_secret, status, last_error, connected_at)
  values (p_org, 'banquest', p_env, p_slug, p_webhook_id, v_key, v_sig, 'connected', null, now())
  on conflict (organization_id) do update
    set environment = excluded.environment, page_slug = excluded.page_slug, webhook_id = excluded.webhook_id,
        source_key_secret = excluded.source_key_secret, signature_secret = excluded.signature_secret,
        status = 'connected', last_error = null, connected_at = now()
  returning webhook_token into v_token;
  return v_token;
end $$;

-- Everything the functions need about a school's provider, secrets included.
create or replace function public.fn_ds_provider_secrets(p_org uuid, p_token text)
returns jsonb
language sql security definer set search_path = public, vault as $$
  select jsonb_build_object(
           'organization_id', pr.organization_id, 'environment', pr.environment, 'page_slug', pr.page_slug,
           'webhook_id', pr.webhook_id, 'webhook_token', pr.webhook_token,
           'source_key', (select decrypted_secret from vault.decrypted_secrets where id = pr.source_key_secret),
           'signature', (select decrypted_secret from vault.decrypted_secrets where id = pr.signature_secret))
    from public.ds_payment_providers pr
   where (p_org is not null and pr.organization_id = p_org) or (p_token is not null and pr.webhook_token = p_token)
   limit 1;
$$;

create or replace function public.fn_ds_provider_remove(p_org uuid)
returns void
language plpgsql security definer set search_path = public, vault as $$
declare old public.ds_payment_providers;
begin
  select * into old from public.ds_payment_providers where organization_id = p_org;
  if old.organization_id is null then return; end if;
  delete from public.ds_payment_providers where organization_id = p_org;
  delete from vault.secrets where id in (old.source_key_secret, old.signature_secret);
  update public.ds_settings set payment_mode = 'at_school' where organization_id = p_org and payment_mode = 'banquest';
end $$;

create or replace function public.fn_ds_provider_error(p_org uuid, p_message text)
returns void
language sql security definer set search_path = public as $$
  update public.ds_payment_providers set status = 'error', last_error = left(p_message, 300) where organization_id = p_org;
$$;

-- A paid order, from the provider. Locks the row; the amount must match the price the client saw.
create or replace function public.fn_ds_order_paid_provider(
  p_org uuid, p_order uuid, p_ref text, p_amount_cents integer, p_event text)
returns text
language plpgsql security definer set search_path = public as $$
declare o public.ds_service_orders;
begin
  select * into o from public.ds_service_orders where id = p_order and organization_id = p_org for update;
  if o.id is null then return 'unknown_order'; end if;
  begin
    insert into public.ds_payment_events (organization_id, event_id) values (p_org, p_event);
  exception when unique_violation then
    return 'duplicate';
  end;
  delete from public.ds_payment_events where received_at < now() - interval '60 days';
  if o.status = 'paid' and o.provider_ref = p_ref then return 'already'; end if;
  if p_amount_cents <> o.price_cents then
    update public.ds_service_orders
       set review_note = left('Paid $' || (p_amount_cents / 100.0)::numeric(12,2) || ' but the price was $' || (o.price_cents / 100.0)::numeric(12,2) || '. Check Banquest.', 300)
     where id = o.id;
    return 'amount_mismatch';
  end if;
  update public.ds_service_orders
     set status = 'paid', decided_at = now(), paid_via = 'banquest', provider = 'banquest', provider_ref = p_ref,
         review_note = case when o.status = 'cancelled' then 'Paid after it was cancelled.' else review_note end
   where id = o.id;
  return 'paid';
end $$;

-- Public: just the state of one order (its id is a secret only the client has).
create or replace function public.ds_public_order_status(p_order uuid)
returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('status', o.status, 'service', o.service_name, 'price_cents', o.price_cents,
                            'school', coalesce(nullif(btrim(g.report_display_name), ''), g.name))
    from public.ds_service_orders o join public.organizations g on g.id = o.organization_id
   where o.id = p_order;
$$;

revoke all on function public.fn_ds_provider_store(uuid, text, text, text, integer, text) from public, anon, authenticated;
revoke all on function public.fn_ds_provider_secrets(uuid, text) from public, anon, authenticated;
revoke all on function public.fn_ds_provider_remove(uuid) from public, anon, authenticated;
revoke all on function public.fn_ds_provider_error(uuid, text) from public, anon, authenticated;
revoke all on function public.fn_ds_order_paid_provider(uuid, uuid, text, integer, text) from public, anon, authenticated;
grant execute on function public.fn_ds_provider_store(uuid, text, text, text, integer, text) to service_role;
grant execute on function public.fn_ds_provider_secrets(uuid, text) to service_role;
grant execute on function public.fn_ds_provider_remove(uuid) to service_role;
grant execute on function public.fn_ds_provider_error(uuid, text) to service_role;
grant execute on function public.fn_ds_order_paid_provider(uuid, uuid, text, integer, text) to service_role;
revoke all on function public.ds_public_order_status(uuid) from public;
grant execute on function public.ds_public_order_status(uuid) to anon, authenticated, service_role;

-- The webhook address has to exist before Banquest is asked to register it, so the function makes the token
-- and passes it in (replaces the first version of fn_ds_provider_store above).
drop function if exists public.fn_ds_provider_store(uuid, text, text, text, integer, text);
create or replace function public.fn_ds_provider_store(
  p_org uuid, p_env text, p_slug text, p_credential text, p_webhook_id integer, p_signature text, p_token text)
returns void
language plpgsql security definer set search_path = public, vault as $$
declare
  old public.ds_payment_providers;
  v_key uuid;
  v_sig uuid;
begin
  if p_token !~ '^[0-9a-f]{64}$' then raise exception 'BAD_TOKEN'; end if;
  select * into old from public.ds_payment_providers where organization_id = p_org;
  if old.organization_id is not null then
    delete from vault.secrets where id in (old.source_key_secret, old.signature_secret);
  end if;
  v_key := vault.create_secret(p_credential, 'banquest-key-' || p_org::text || '-' || extract(epoch from clock_timestamp())::bigint::text, 'Banquest source key');
  v_sig := vault.create_secret(p_signature, 'banquest-sig-' || p_org::text || '-' || extract(epoch from clock_timestamp())::bigint::text, 'Banquest webhook signature key');
  insert into public.ds_payment_providers (organization_id, provider, environment, page_slug, webhook_token, webhook_id, source_key_secret, signature_secret, status, last_error, connected_at)
  values (p_org, 'banquest', p_env, p_slug, p_token, p_webhook_id, v_key, v_sig, 'connected', null, now())
  on conflict (organization_id) do update
    set environment = excluded.environment, page_slug = excluded.page_slug, webhook_token = excluded.webhook_token,
        webhook_id = excluded.webhook_id, source_key_secret = excluded.source_key_secret,
        signature_secret = excluded.signature_secret, status = 'connected', last_error = null, connected_at = now();
end $$;
revoke all on function public.fn_ds_provider_store(uuid, text, text, text, integer, text, text) from public, anon, authenticated;
grant execute on function public.fn_ds_provider_store(uuid, text, text, text, integer, text, text) to service_role;
