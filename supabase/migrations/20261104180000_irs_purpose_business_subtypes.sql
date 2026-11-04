-- Olympus Mont Systems LLC - ControlMiles (Gig)
-- Trip purposes (2026-11-04): the Business group of the purpose menu gets four
-- more specific purposes -- delivery, errand (errands and supplies), client
-- (client visit) and travel (airport and travel). They are all Business: the
-- reports already count any purpose that is not in their non-business list as
-- business miles, so only this CHECK has to learn the new ids. Existing rows
-- and the old ids are untouched.

alter table public.session_sections drop constraint if exists chk_irs_purpose_valid;
alter table public.session_sections
  add constraint chk_irs_purpose_valid
  check (irs_purpose is null or irs_purpose = any (array[
    'business', 'work', 'medical', 'moving', 'charitable', 'education', 'personal',
    'delivery', 'errand', 'client', 'travel'
  ]::text[]));
