
create or replace function public.redeem_report_access_code(
  p_code text,
  p_ip_hash text
)
returns table(success boolean, message text, report jsonb)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_recent_failures int;
  v_hash text;
  v_report record;
begin
  select count(*) into v_recent_failures
  from public.report_access_attempts raa
  where raa.ip_hash = p_ip_hash
    and raa.success = false
    and raa.attempted_at > now() - interval '15 minutes';

  if v_recent_failures >= 5 then
    return query select false, 'Too many attempts. Try again later.', null::jsonb;
    return;
  end if;

  v_hash := encode(digest(coalesce(p_code, ''), 'sha256'), 'hex');

  select * into v_report
  from public.reports r
  where r.qr_token = v_hash
    and r.qr_expires_at > now()
    and r.qr_uses < r.qr_max_uses
  limit 1;

  if not found then
    insert into public.report_access_attempts (ip_hash, success, report_id)
    values (p_ip_hash, false, null);
    return query select false, 'Invalid or expired code.', null::jsonb;
    return;
  end if;

  update public.reports set qr_uses = qr_uses + 1 where id = v_report.id;

  insert into public.report_access_attempts (ip_hash, success, report_id)
  values (p_ip_hash, true, v_report.id);

  return query select true, 'ok', v_report.metadata;
end;
$$;

revoke all on function public.redeem_report_access_code(text, text) from public;
revoke all on function public.redeem_report_access_code(text, text) from authenticated;
grant execute on function public.redeem_report_access_code(text, text) to anon;
