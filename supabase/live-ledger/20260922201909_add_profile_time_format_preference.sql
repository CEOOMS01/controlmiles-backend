alter table public.profiles
  add column if not exists time_format text not null default '12h'
  check (time_format in ('12h', '24h'));
