-- Daily cleanup of the driving school client portal tokens (ds_client_tokens).
-- Sign-in links live 30 minutes (7 days for the welcome link) and sessions 30
-- days; nothing ever deleted them, so the table only grew. A token is removed
-- 7 days after it expired, was used or was revoked (the week gives support a
-- short trail to answer "my link did not work").
create or replace function public.fn_ds_purge_client_tokens()
returns integer
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_deleted integer;
begin
  delete from public.ds_client_tokens
   where expires_at < now() - interval '7 days'
      or used_at < now() - interval '7 days'
      or revoked_at < now() - interval '7 days';
  get diagnostics v_deleted = row_count;
  return v_deleted;
end
$function$;
revoke execute on function public.fn_ds_purge_client_tokens() from public, anon, authenticated;

select cron.unschedule('ds-client-tokens-purge')
 where exists (select 1 from cron.job where jobname = 'ds-client-tokens-purge');
select cron.schedule('ds-client-tokens-purge', '27 8 * * *', 'select public.fn_ds_purge_client_tokens()');
