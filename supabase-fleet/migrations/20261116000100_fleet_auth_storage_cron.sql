-- Fleet project: pieces the schema dump does not carry (auth trigger, buckets, storage policies,
-- cron jobs, vault secret). Copied from the gig project's live setup, pointing at THIS project.

-- 1. New-user trigger
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 2. Storage buckets (private)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values
  ('fuel_receipts', 'fuel_receipts', false, 10485760, array['image/jpeg','image/png']),
  ('odometers',     'odometers',     false, 10485760, array['image/jpeg','image/png']),
  ('org_branding',  'org_branding',  false, 2097152,  array['image/png','image/jpeg','image/webp'])
on conflict (id) do nothing;

-- 3. Storage policies
create policy fuel_receipts_delete_own on storage.objects for delete
  using (bucket_id = 'fuel_receipts' and (storage.foldername(name))[1] = (auth.uid())::text);
create policy fuel_receipts_insert_own on storage.objects for insert
  with check (bucket_id = 'fuel_receipts' and (storage.foldername(name))[1] = (auth.uid())::text);
create policy fuel_receipts_select_own on storage.objects for select
  using (bucket_id = 'fuel_receipts' and (storage.foldername(name))[1] = (auth.uid())::text);
create policy fuel_receipts_update_own on storage.objects for update
  using (bucket_id = 'fuel_receipts' and (storage.foldername(name))[1] = (auth.uid())::text);
create policy fuel_receipts_select_org_admin on storage.objects for select
  using (bucket_id = 'fuel_receipts' and exists (
    select 1 from public.fuel_purchases fp
    where fp.receipt_path = objects.name and fp.organization_id is not null
      and public.is_org_admin_or_owner(fp.organization_id)));

create policy odometers_delete_own on storage.objects for delete
  using (bucket_id = 'odometers' and (storage.foldername(name))[1] = (auth.uid())::text);
create policy odometers_insert_own on storage.objects for insert
  with check (bucket_id = 'odometers' and (storage.foldername(name))[1] = (auth.uid())::text);
create policy odometers_select_own on storage.objects for select
  using (bucket_id = 'odometers' and (storage.foldername(name))[1] = (auth.uid())::text);
create policy odometers_update_own on storage.objects for update
  using (bucket_id = 'odometers' and (storage.foldername(name))[1] = (auth.uid())::text);

create policy org_branding_delete_admin on storage.objects for delete
  using (bucket_id = 'org_branding' and public.is_org_admin_or_owner(((storage.foldername(name))[1])::uuid));
create policy org_branding_insert_admin on storage.objects for insert
  with check (bucket_id = 'org_branding' and public.is_org_admin_or_owner(((storage.foldername(name))[1])::uuid));
create policy org_branding_select_member on storage.objects for select
  using (bucket_id = 'org_branding' and public.is_org_member(((storage.foldername(name))[1])::uuid));
create policy org_branding_update_admin on storage.objects for update
  using (bucket_id = 'org_branding' and public.is_org_admin_or_owner(((storage.foldername(name))[1])::uuid));

-- 4. A NEW shared secret for this project's cron -> edge function calls (never the gig one)
select vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'ifta_sync_shared_secret',
                           'Cron to edge function shared secret (Fleet project)');

-- 5. Cron jobs that belong to Fleet (Play-subscription expiry stays in gig)
select cron.schedule('close-abandoned-trips', '17 * * * *', 'select public.close_abandoned_trips()');
select cron.schedule('domain-boundaries-daily', '43 7 * * *', 'select ops.fn_domain_check_daily()');
select cron.schedule('driver-safety-summaries', '0 14 1,16 * *', 'select public.fn_send_safety_summaries();');
select cron.schedule('ds-client-tokens-purge', '27 8 * * *', 'select public.fn_ds_purge_client_tokens()');
select cron.schedule('ds-enrollment-requests-purge', '37 8 * * *', 'select public.fn_ds_purge_enrollment_requests()');
select cron.schedule('ds-guardian-links-daily', '17 8 * * *', 'select public.fn_ds_close_guardian_links()');

select cron.schedule('class-reminders-hourly', '5 * * * *', $$
  select net.http_post(
    url := 'https://oweekkdectvsigspyafu.supabase.co/functions/v1/send-class-reminders',
    headers := jsonb_build_object('Content-Type', 'application/json',
      'X-Sync-Secret', (select decrypted_secret from vault.decrypted_secrets where name = 'ifta_sync_shared_secret')),
    body := '{}'::jsonb);
$$);
select cron.schedule('fuel-anomalies-nightly', '0 9 * * *', $$
  select public.fn_reevaluate_recent_fuel_purchases();
  select net.http_post(
    url := 'https://oweekkdectvsigspyafu.supabase.co/functions/v1/send-fuel-alerts',
    headers := jsonb_build_object('Content-Type', 'application/json',
      'X-Sync-Secret', (select decrypted_secret from vault.decrypted_secrets where name = 'ifta_sync_shared_secret')),
    body := '{}'::jsonb);
$$);
select cron.schedule('ifta-quarterly-rate-sync', '0 6 1-10 1,4,7,10 *', $$
  select net.http_post(
    url := 'https://oweekkdectvsigspyafu.supabase.co/functions/v1/sync-ifta-tax-rates',
    headers := jsonb_build_object('Content-Type', 'application/json',
      'X-Sync-Secret', (select decrypted_secret from vault.decrypted_secrets where name = 'ifta_sync_shared_secret')),
    body := '{}'::jsonb);
$$);
