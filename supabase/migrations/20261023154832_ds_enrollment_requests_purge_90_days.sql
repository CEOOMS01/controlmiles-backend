-- Retention promised on the public enrollment page: a request (any status)
-- is removed 90 days after it arrived. Until now that delete only ran
-- inside ds_public_enroll, i.e. when someone NEW sent a request to the same
-- school, so a school with no traffic kept minors' names and birth dates
-- indefinitely. A daily job makes the promise independent of traffic.
create or replace function public.fn_ds_purge_enrollment_requests()
returns integer
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_deleted integer;
begin
  delete from public.ds_enrollment_requests where created_at < now() - interval '90 days';
  get diagnostics v_deleted = row_count;
  return v_deleted;
end
$function$;
revoke execute on function public.fn_ds_purge_enrollment_requests() from public, anon, authenticated;

select cron.unschedule('ds-enrollment-requests-purge')
 where exists (select 1 from cron.job where jobname = 'ds-enrollment-requests-purge');
select cron.schedule('ds-enrollment-requests-purge', '37 8 * * *', 'select public.fn_ds_purge_enrollment_requests()');
