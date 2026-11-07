-- Delete ONE segment (gig app / category leg) of a closed trip without touching the
-- others. My Trips shows each segment as its own card (2026-11-06); deleting a card must
-- remove only that segment and keep the trip's own totals in line with what is left.
--
-- A closed trip is frozen (fn_freeze_closed_session), so the totals can only be moved by
-- this function, which switches on a transaction-local flag the freeze trigger accepts for
-- exactly four columns (total_miles, total_duration_seconds, start_time, end_time).
-- When the last segment goes, the whole trip goes.

create or replace function public.fn_freeze_closed_session()
 returns trigger
 language plpgsql
as $function$
begin
  if OLD.is_closed = true then
    if OLD.cgc_sealed_at is null
       and NEW.cgc_sealed_at is not null
       and (to_jsonb(NEW) - 'cgc_decision_id' - 'cgc_sealed_at' - 'updated_at')
         = (to_jsonb(OLD) - 'cgc_decision_id' - 'cgc_sealed_at' - 'updated_at') then
      return NEW;
    end if;
    if OLD.vehicle_id is null
       and NEW.vehicle_id is not null
       and OLD.cgc_sealed_at is null
       and OLD.organization_id is null
       and coalesce(current_setting('cm.assign_trip_vehicle', true), '') = 'on'
       and (to_jsonb(NEW) - 'vehicle_id' - 'updated_at')
         = (to_jsonb(OLD) - 'vehicle_id' - 'updated_at') then
      return NEW;
    end if;
    -- A segment was deleted: only the totals that come from the segments may move.
    if OLD.cgc_sealed_at is null
       and coalesce(current_setting('cm.section_delete', true), '') = 'on'
       and (to_jsonb(NEW) - 'total_miles' - 'total_duration_seconds' - 'start_time' - 'end_time' - 'updated_at')
         = (to_jsonb(OLD) - 'total_miles' - 'total_duration_seconds' - 'start_time' - 'end_time' - 'updated_at') then
      return NEW;
    end if;
    raise exception 'Cannot modify a closed session';
  end if;
  return NEW;
end;
$function$;

create or replace function public.delete_trip_section(p_section_id uuid)
 returns void
 language plpgsql
 security definer
 set search_path to 'public'
as $function$
declare
  v_sec  public.session_sections%rowtype;
  v_sess public.sessions%rowtype;
  v_left integer;
begin
  select * into v_sec from public.session_sections where id = p_section_id;
  if not found then
    raise exception 'Section not found' using errcode = 'P0002';
  end if;

  select * into v_sess from public.sessions where id = v_sec.session_id for update;

  if not (
    (v_sess.organization_id is null and v_sess.user_id = auth.uid())
    or (v_sess.organization_id is not null and public.is_org_admin_or_owner(v_sess.organization_id))
  ) then
    raise exception 'Not allowed to delete this trip' using errcode = '42501';
  end if;

  if not coalesce(v_sess.is_closed, false) then
    raise exception 'The trip is still open' using errcode = '55000';
  end if;

  select count(*) into v_left
    from public.session_sections
   where session_id = v_sess.id and id <> p_section_id;

  if v_left = 0 then
    delete from public.sessions where id = v_sess.id;
    return;
  end if;

  delete from public.session_sections where id = p_section_id;

  perform set_config('cm.section_delete', 'on', true);
  update public.sessions s
     set total_miles = coalesce((select sum(total_miles) from public.session_sections where session_id = s.id), 0),
         total_duration_seconds = coalesce((select sum(total_duration_seconds) from public.session_sections where session_id = s.id), 0),
         start_time = coalesce((select min(start_time) from public.session_sections where session_id = s.id), s.start_time),
         end_time = coalesce((select max(end_time) from public.session_sections where session_id = s.id), s.end_time)
   where s.id = v_sess.id;
  perform set_config('cm.section_delete', 'off', true);
end;
$function$;

revoke all on function public.delete_trip_section(uuid) from public, anon;
grant execute on function public.delete_trip_section(uuid) to authenticated;
