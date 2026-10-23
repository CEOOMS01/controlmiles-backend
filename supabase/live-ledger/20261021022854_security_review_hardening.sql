do $$
declare
  f regprocedure;
begin
  for f in
    select p.oid::regprocedure
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where n.nspname = 'public' and p.prosecdef and pg_get_function_result(p.oid) = 'trigger'
  loop
    execute format('revoke execute on function %s from public, anon, authenticated', f);
  end loop;
end $$;

alter function public.fn_ds_certificates_immutable() set search_path = public;
alter function public.fn_ds_touch() set search_path = public;
alter function public.fn_sun_times(double precision, double precision, timestamp with time zone) set search_path = public;
alter function public.fn_valid_origins(text[]) set search_path = public;
