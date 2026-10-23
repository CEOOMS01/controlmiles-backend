insert into public.gig_apps (id, name, is_active, sort_order) values
  ('shipt', 'Shipt', true, 10),
  ('veho', 'Veho', true, 11),
  ('jitsu', 'Jitsu', true, 12),
  ('walmart_spark', 'Spark Driver', true, 13)
on conflict (id) do nothing;
