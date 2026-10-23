create or replace function public.fn_freeze_closed_session()
returns trigger
language plpgsql
set search_path to 'public'
as $$
begin
  if OLD.is_closed = true then
    if OLD.cgc_sealed_at is null
       and NEW.cgc_sealed_at is not null
       and (to_jsonb(NEW) - 'cgc_decision_id' - 'cgc_sealed_at' - 'updated_at')
         = (to_jsonb(OLD) - 'cgc_decision_id' - 'cgc_sealed_at' - 'updated_at') then
      return NEW;
    end if;
    raise exception 'Cannot modify a closed session';
  end if;
  return NEW;
end;
$$;
