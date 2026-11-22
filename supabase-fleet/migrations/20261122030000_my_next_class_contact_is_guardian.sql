-- my_next_class also says whether the phone it returns is the guardian's (a minor), so the Fleet app can label
-- the buttons "Call guardian" / "Message guardian" (2026-11-22). Companion of 20261122020000.
-- A new last column changes the return type, so the function is dropped and recreated with the same grants.

do $$
declare d text; nd text;
begin
  d := pg_get_functiondef('public.my_next_class(uuid)'::regprocedure);
  nd := replace(d, 'pickup_opens_at timestamp with time zone)', 'pickup_opens_at timestamp with time zone, contact_is_guardian boolean)');
  nd := replace(nd, 'then ((b.block_date + b.start_time) at time zone v_tz) - make_interval(mins => v_lead) end' || E'\n',
                    'then ((b.block_date + b.start_time) at time zone v_tz) - make_interval(mins => v_lead) end,' || E'\n         public.fn_ds_contact_is_guardian(st)' || E'\n');
  if nd = d or position('contact_is_guardian boolean' in nd) = 0 or position('fn_ds_contact_is_guardian(st)' in nd) = 0 then
    raise exception 'my_next_class: marker not found';
  end if;
  drop function public.my_next_class(uuid);
  execute nd;
  revoke execute on function public.my_next_class(uuid) from public, anon;
  grant execute on function public.my_next_class(uuid) to authenticated;
end $$;
