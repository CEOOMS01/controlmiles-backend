select cron.schedule(
  'fuel-anomalies-nightly',
  '0 9 * * *',
  $$
  select public.fn_reevaluate_recent_fuel_purchases();
  select net.http_post(
    url := 'https://zuujwmcftycmdaxesdya.supabase.co/functions/v1/send-fuel-alerts',
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'X-Sync-Secret', (select decrypted_secret from vault.decrypted_secrets where name = 'ifta_sync_shared_secret')
    ),
    body := '{}'::jsonb
  );
  $$
);
