-- School bus: a student's home address (becomes a pick-up stop) and two parents
-- or guardians to call in an emergency (the second is optional). Only
-- operators and above read the students table (students_select_admin);
-- drivers never do, they use the run RPCs, so none of this reaches the app.
alter table public.students
  add column if not exists home_address text,
  add column if not exists home_latitude double precision,
  add column if not exists home_longitude double precision,
  add column if not exists parent1_name text,
  add column if not exists parent1_phone text,
  add column if not exists parent2_name text,
  add column if not exists parent2_phone text;

alter table public.students
  add constraint students_home_address_len check (home_address is null or char_length(home_address) <= 240),
  add constraint students_home_coords check (
    (home_latitude is null and home_longitude is null)
    or (home_latitude between -90 and 90 and home_longitude between -180 and 180)
  ),
  add constraint students_parent_len check (
    (parent1_name is null or char_length(parent1_name) <= 120)
    and (parent2_name is null or char_length(parent2_name) <= 120)
    and (parent1_phone is null or char_length(parent1_phone) <= 30)
    and (parent2_phone is null or char_length(parent2_phone) <= 30)
  );

comment on column public.students.home_address is 'Home address; the route builder turns it into a pick-up stop.';
comment on column public.students.parent1_phone is 'Emergency contact, first parent or guardian.';
comment on column public.students.parent2_phone is 'Emergency contact, second parent or guardian (optional).';
