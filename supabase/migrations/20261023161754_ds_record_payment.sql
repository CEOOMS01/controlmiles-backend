-- Driving school packages: a payment is recorded in one locked step
-- (audit 2026-10-23, finding 8). The web read amount_paid_cents, added the
-- payment in JavaScript and wrote the total back, so two payments recorded
-- at the same moment (two staff, two tabs) lost one of them, and nothing
-- stopped a typo such as 500 instead of 50 from marking a package "paid".
-- Now the row is locked, the amount is added in the database and a payment
-- larger than the balance due is refused.
-- Same access rule as the table's policy: operator or above of a school
-- whose plan has student_packages.

create or replace function public.ds_record_payment(p_package uuid, p_amount_cents integer)
returns text
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  r public.ds_student_packages;
  v_status text;
begin
  select * into r from public.ds_student_packages where id = p_package for update;
  if r.id is null then raise exception 'PACKAGE_NOT_FOUND' using errcode = 'P0001'; end if;
  if not public.is_org_operator_or_above(r.organization_id) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(r.organization_id, 'student_packages');
  if p_amount_cents is null or p_amount_cents <= 0 then raise exception 'AMOUNT_REQUIRED' using errcode = 'P0001'; end if;
  if r.amount_paid_cents + p_amount_cents > r.price_cents then
    raise exception 'PAYMENT_EXCEEDS_BALANCE' using errcode = 'P0001';
  end if;
  v_status := case when r.amount_paid_cents + p_amount_cents >= r.price_cents then 'paid' else 'partial' end;
  update public.ds_student_packages
     set amount_paid_cents = amount_paid_cents + p_amount_cents, payment_status = v_status
   where id = r.id;
  return v_status;
end $function$;
revoke execute on function public.ds_record_payment(uuid, integer) from public, anon;
grant execute on function public.ds_record_payment(uuid, integer) to authenticated;
