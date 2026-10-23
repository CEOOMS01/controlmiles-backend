alter table public.session_sections
  add column if not exists notes text;

comment on column public.session_sections.notes is
  'Nota libre del usuario sobre la sección (ej. "faltaron 5 millas"). '
  'Nunca se usa para editar total_miles/total_duration_seconds directamente '
  '-- las millas trackeadas son inmutables por diseño. Solo contexto.';
