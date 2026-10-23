-- CRITICAL FIX #2: the pg 'http' extension (SSRF surface) was executable by
-- anon/authenticated and reachable via PostgREST /rpc/http_get. Anyone with the
-- public anon key could make the database issue arbitrary outbound HTTP requests.
-- Nothing in the client calls these; only server-side/definer paths use outbound
-- HTTP. Revoke every http* function from the client-exposed roles and PUBLIC.
do $$
declare r record;
begin
  for r in
    select p.oid::regprocedure::text sig
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in ('http','http_get','http_post','http_put','http_delete',
                        'http_head','http_patch','http_set_curlopt','http_reset_curlopt')
  loop
    execute format('revoke execute on function %s from anon, authenticated, public', r.sig);
  end loop;
end $$;
