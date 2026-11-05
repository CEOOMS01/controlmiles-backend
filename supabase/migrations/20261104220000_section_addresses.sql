-- Olympus Mont Systems LLC - ControlMiles (Gig)
-- Where a trip started and where it ended, as a street address (2026-11-04).
-- The coordinates were already stored (and are frozen once a trip closes); the
-- address is the readable version of them, looked up on the phone once when the
-- trip closes and editable afterwards by the driver. It is deliberately NOT part
-- of fn_freeze_closed_session_section: correcting a street name never touches
-- the recorded miles, times or coordinates. `address_edited` says the driver
-- changed it by hand.

alter table public.session_sections
  add column if not exists start_address text,
  add column if not exists end_address text,
  add column if not exists address_edited boolean not null default false;

alter table public.session_sections drop constraint if exists session_sections_address_len;
alter table public.session_sections add constraint session_sections_address_len
  check (coalesce(length(start_address), 0) <= 300 and coalesce(length(end_address), 0) <= 300);
