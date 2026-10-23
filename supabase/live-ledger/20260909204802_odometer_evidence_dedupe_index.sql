
-- Closes a real check-then-act race in OdometerCaptureService.processEvidence:
-- it SELECTs for an existing ODOMETER_START/ODOMETER_END audit_events row
-- before INSERTing, which is not atomic -- two concurrent calls for the
-- same session could both pass the check before either commits. A partial
-- unique index is the DB-level floor (client check stays as the fast-path
-- UX message); scoped to just these two event types since every other
-- event_type (GPS_TICK, SECTION_START, etc.) legitimately repeats many
-- times per session and must not be constrained.
create unique index if not exists idx_audit_events_odometer_dedupe
  on public.audit_events (session_id, event_type)
  where event_type in ('ODOMETER_START', 'ODOMETER_END');
