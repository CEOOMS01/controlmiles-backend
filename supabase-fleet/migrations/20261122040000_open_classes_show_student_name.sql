-- An open class (nobody has taken it yet) now shows the student's NAME to the instructors, next to its car
-- (2026-11-22, owner's request). The student's address, phone and the class note stay hidden until the instructor
-- takes the class (or is admin/operator): only the name is shared early.

do $$
declare d text; nd text;
begin
  d := pg_get_functiondef('public.get_branch_schedule(uuid,date,integer)'::regprocedure);
  nd := replace(d, E'''student_name'', case when b.driver_id = v_uid or v_is_op\n',
                   E'''student_name'', case when b.driver_id = v_uid or v_is_op or b.driver_id is null\n');
  if nd = d then raise exception 'get_branch_schedule: marker not found'; end if;
  execute nd;
end $$;
