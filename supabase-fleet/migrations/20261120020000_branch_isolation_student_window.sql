-- Fleet: tighten the one exception of the branch fence (2026-11-20).
-- An instructor keeps seeing a student of another branch only while they still have a class with that student
-- today, tomorrow... or finished within the last two days (they still have to evaluate it). Before, one old class
-- was enough to see that student forever.

create or replace function public.fn_student_gate(p_student uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select public.fn_branch_gate(s.organization_id, s.branch_id)
                       or exists (select 1 from public.shift_blocks b
                                   where b.student_id = s.id and b.driver_id = auth.uid()
                                     and b.status <> 'cancelled' and b.block_date >= current_date - 2)
                     from public.ds_students s where s.id = p_student), true)
$$;

drop policy if exists ds_students_branch_gate on public.ds_students;
create policy ds_students_branch_gate on public.ds_students as restrictive for all to authenticated using (
  public.fn_branch_gate(organization_id, branch_id)
  or exists (select 1 from public.shift_blocks b
              where b.student_id = ds_students.id and b.driver_id = auth.uid()
                and b.status <> 'cancelled' and b.block_date >= current_date - 2)
);
