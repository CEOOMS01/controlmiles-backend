-- Fleet project (2026-11-16, owner decision): driving schools no longer match a student's language to an
-- instructor's. Online booking offers every free slot of any instructor. The columns stay (the student's
-- language still picks the language of reminders; organization_members.languages is simply unused now).
do $$
declare d text; nd text; f text;
begin
  foreach f in array array['fn_ds_portal_slots_for', 'fn_ds_portal_book_for'] loop
    select pg_get_functiondef(p.oid) into d from pg_proc p where p.pronamespace = 'public'::regnamespace and p.proname = f;
    nd := regexp_replace(d, E'\\n\\s*and \\(st\\.preferred_language is null or st\\.preferred_language = any \\(m\\.languages\\)\\)', '');
    nd := regexp_replace(nd, E'\\n\\s*''language'', st\\.preferred_language,', '');
    if nd = d then raise exception 'nothing changed in %', f; end if;
    if nd ~ 'm\.languages' then raise exception 'language filter still in %', f; end if;
    execute nd;
  end loop;
end $$;
