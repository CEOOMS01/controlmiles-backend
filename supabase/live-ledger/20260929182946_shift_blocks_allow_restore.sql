-- A cancelled class can be put back on the schedule (status only); any
-- other edit to a block that is no longer 'scheduled' stays refused.
create or replace function public.fn_freeze_started_shift_block()
returns trigger language plpgsql as $$
begin
  if current_setting('cm.shift_block_rpc', true) is not distinct from 'on' then
    return new;
  end if;
  if old.status = 'scheduled' then
    return new;
  end if;
  if old.status = 'cancelled' and new.status = 'scheduled'
     and (new.driver_id, new.vehicle_id, new.block_date, new.start_time, new.end_time, new.note)
         is not distinct from
         (old.driver_id, old.vehicle_id, old.block_date, old.start_time, old.end_time, old.note) then
    return new;
  end if;
  raise exception 'A class that already started cannot be edited';
end $$;
