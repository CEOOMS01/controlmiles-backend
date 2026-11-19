-- The bell must say who did it: an instructor taking a class is not the same as the office assigning it.
-- Adds by_instructor (the actor is the instructor of the event). Fleet project only.
create or replace function public.get_schedule_events(p_org uuid, p_limit integer default 50) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  v_last timestamptz;
begin
  if auth.uid() is null or not public.is_org_operator_or_above(p_org) then raise exception 'FORBIDDEN'; end if;
  select r.last_read_at into v_last from public.schedule_event_reads r where r.organization_id = p_org and r.user_id = auth.uid();
  return jsonb_build_object(
    'unread', (select count(*) from public.schedule_events e where e.organization_id = p_org and e.created_at > coalesce(v_last, 'epoch'::timestamptz)),
    'events', coalesce((
      select jsonb_agg(x order by x.created_at desc) from (
        select e.id, e.kind, e.created_at, e.actor_role, e.payload, e.block_id, e.branch_id,
               e.created_at > coalesce(v_last, 'epoch'::timestamptz) as is_new,
               (e.actor_id is not null and e.actor_id = e.instructor_id) as by_instructor,
               nullif(trim(concat_ws(' ', pa.first_name, pa.last_name)), '') as actor_name,
               nullif(trim(concat_ws(' ', pi.first_name, pi.last_name)), '') as instructor_name
          from public.schedule_events e
          left join public.profiles pa on pa.id = e.actor_id
          left join public.profiles pi on pi.id = e.instructor_id
         where e.organization_id = p_org
         order by e.created_at desc limit least(greatest(coalesce(p_limit, 50), 1), 200)) x
    ), '[]'::jsonb));
end $$;
