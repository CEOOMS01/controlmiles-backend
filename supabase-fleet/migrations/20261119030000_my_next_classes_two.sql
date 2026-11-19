-- Instructor home shows two classes: the current one (in progress, or the next to start) and the one after it.
-- my_next_class now returns up to two rows, in order; the app uses the first as "Current class" and the
-- second as "Next class".
do $$
declare d text; nd text;
begin
  d := pg_get_functiondef('public.my_next_class(uuid)'::regprocedure);
  nd := replace(d, E'   limit 1;', E'   limit 2;');
  if nd = d then raise exception 'my_next_class: marker not found'; end if;
  execute nd;
end $$;
