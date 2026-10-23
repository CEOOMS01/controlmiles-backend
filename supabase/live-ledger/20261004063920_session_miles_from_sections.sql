create or replace function public.fn_session_miles_from_sections()
returns trigger
language plpgsql
set search_path to 'public'
as $$
declare
  v_sum double precision;
begin
  if coalesce(new.is_closed, false) and not coalesce(old.is_closed, false) then
    select sum(total_miles) into v_sum from public.session_sections where session_id = new.id;
    if v_sum is not null and v_sum > 0 then
      new.total_miles := v_sum;
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_session_miles_from_sections on public.sessions;
create trigger trg_session_miles_from_sections
  before update on public.sessions
  for each row execute function public.fn_session_miles_from_sections();

alter table public.sessions disable trigger trg_freeze_closed_session;

update public.sessions s
   set total_miles = x.sum_miles
  from (
    select session_id, sum(total_miles) as sum_miles
      from public.session_sections
     group by session_id
  ) x
 where x.session_id = s.id
   and s.is_closed
   and x.sum_miles > 0
   and abs(x.sum_miles - coalesce(s.total_miles, 0)) > 0.05;

alter table public.sessions enable trigger trg_freeze_closed_session;
