CREATE OR REPLACE FUNCTION public.fn_fuel_purchase_evaluate_trigger()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  v_next uuid;
begin
  -- A failing check must never block a driver from logging a receipt:
  -- errors are logged and the nightly re-check tries again.
  begin
    perform public.fn_evaluate_fuel_purchase(new.id);
    select o.id into v_next from public.fuel_purchases o
    where o.vehicle_id = new.vehicle_id and o.id <> new.id
      and (o.purchase_date > new.purchase_date
           or (o.purchase_date = new.purchase_date and o.created_at > new.created_at))
    order by o.purchase_date, o.created_at
    limit 1;
    if v_next is not null then
      perform public.fn_evaluate_fuel_purchase(v_next);
    end if;
  exception when others then
    raise warning 'fuel anomaly check failed for %: %', new.id, sqlerrm;
  end;
  return null;
end;
$function$;

CREATE OR REPLACE FUNCTION public.fn_reevaluate_recent_fuel_purchases()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
declare
  r record;
  n integer := 0;
begin
  for r in
    select id from public.fuel_purchases
    where organization_id is not null
      and purchase_date >= (now() at time zone 'utc')::date - 14
  loop
    begin
      perform public.fn_evaluate_fuel_purchase(r.id);
      n := n + 1;
    exception when others then
      raise warning 'fuel anomaly check failed for %: %', r.id, sqlerrm;
    end;
  end loop;
  return n;
end;
$function$;
