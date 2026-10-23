create or replace function public.ds_portal_certificate(p_token text, p_number text)
returns jsonb language plpgsql stable security definer set search_path to 'public', 'extensions' as $$
declare
  l public.ds_portal_links;
  c public.ds_certificates;
begin
  select * into l from public.ds_portal_links
   where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
     and revoked_at is null and expires_at > now();
  if l.id is null or not public.fn_org_feature_internal(l.organization_id, 'student_portal') then return null; end if;
  select * into c from public.ds_certificates where student_id = l.student_id and number = p_number;
  if c.id is null then return null; end if;
  return jsonb_build_object('data', c.data, 'sha256', c.sha256, 'number', c.number, 'issued_at', c.issued_at);
end $$;
revoke execute on function public.ds_portal_certificate(text, text) from public;
grant execute on function public.ds_portal_certificate(text, text) to anon, authenticated;
