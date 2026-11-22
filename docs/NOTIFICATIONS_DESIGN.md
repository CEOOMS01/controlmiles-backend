# Notification hub — design (2026-11-22)

Status: DESIGN ONLY. Nothing here is built or applied. Needs the decisions at the end before phase 1.

## 1. Where we are today (verified in the repo)

| Piece | What exists | Limit |
|---|---|---|
| `schedule_events` (+ `schedule_event_reads`) | Driving-school change log, 12 kinds + alerts `class_late_start`, `class_no_show`, `class_unclaimed_soon`; severity red/amber/green computed in `get_schedule_events`; per-person dismiss | One service only, admins/operators only, org-wide table (every viewer reads the same rows), in-app only |
| `needs-attention-panel.tsx` + `ScheduleLiveRefresh` | Realtime on `shift_blocks, ds_time_off, ds_blocked_hours, schedule_events` via a server-issued short token | Driving school only |
| `driver_notifications` | `trip_safety`, `safety_summary` for gig/fleet drivers | CHECK allows two kinds, no channels |
| `vehicle_geofence_alerts`, `driver_safety_events`, fuel anomalies | Fleet detections exist | No routing, no owner, no escalation |
| Fleet app `notification_service.dart` | Local notifications only (forgotten trip, weekly summary, GPS lost) | No push backend (no FCM/APNs) |
| Email | Edge functions with Resend (driver and guardian invites) | Only invites; no reminder email |
| SMS | none | — |
| pg_cron | `class-reminders-hourly` and others | reminders exist but not per-channel or per-person |

So: three disconnected mechanisms, one per area, and no way to reach a person who is not looking at the portal.

## 2. What the market does (research, 2026-11-22)

Vendor pages and blogs, not independent studies — treat numbers as vendor claims.

**Driving schools** — [GetApp: automatic reminders](https://www.getapp.com/education-childcare-software/driving-school/f/automatic-reminders/), [Zutobi reminders](https://zutobi.com/us/driving-schools/automated-reminders), [Koalendar](https://koalendar.com/scheduling-software-for/driving-school), [Capterra list](https://www.capterra.com/driving-school-software/):
- automatic SMS + email reminders to cut no-shows is the table-stakes feature; parents can be copied;
- students reschedule/cancel online and the system notifies everyone; multi-instructor calendars, vehicle assignment;
- I found NO vendor describing automatic waitlist filling of a cancelled slot → differentiator (evidence of absence is weak; verify before marketing it).
- Reminders in general: a review cites ~34% relative reduction in non-attendance, a Cochrane review favours text reminders (healthcare, not lessons) — see [Sinch](https://sinch.com/engage/resources/business-messaging/how-to-reduce-no-show-appointments/), [Zocdoc](https://zocdoc.com/resources/blog/article/appointment-reminder-templates-that-reduce-no-shows-text-email). No solid data for push or WhatsApp; layer SMS (short, timed) + email (details). Test our own.

**School bus** — [Transfinder Stopfinder](https://www.transfinder.com/solutions/Stopfinder), [Upper](https://www.upperinc.com/customer-notification/for-school-transportation/), [Tyler Ride 360](https://www.tylertech.com/products/traversa/ride-360), [Zonar parent app](https://apps.apple.com/us/app/-/id6748876476), [School Bus Fleet](https://www.schoolbusfleet.com/10245378/inside-parent-routing-apps-how-digital-tools-are-transforming-school-transportat):
- ETA alerts at a configurable lead (5/10/15/20 min), board/exit alerts, "missed the bus" alert;
- automatic delay message to every parent of the affected route WITH reason and new ETA, sent the moment the delay is detected (goal: fewer "where is the bus" calls);
- route/schedule change notices;
- gap: nothing public on driver-incident/breakdown messaging or on student-location privacy — we must define both ourselves (see §5).

**Fleet** — [Samsara](https://www.samsara.com/guides/gps-tracking-alerts), [GPS Insight](https://help.gpsinsight.com/best-practice/strategies-for-using-alerts/), [Geotab: manage by exception](https://www.geotab.com/blog/benefits-of-managing-by-exception/), [Oxmaint: alerts without fatigue](https://oxmaint.com/industries/fleet-management/fleet-real-time-alert-threshold-configuration-guide-2026):
- core alerts: speeding, geofence in/out, maintenance (by miles/hours, not only dates), engine faults, harsh driving/idling, after-hours use;
- the real design lesson is alert fatigue: tier by urgency, each rule has a primary recipient + backup + time before escalation, fire on STATE CHANGE (not every ping), manage by exception, audit alerts nobody acted on every 30–60 days, keep driver↔vehicle assignment current or alerts lose credibility.

## 3. Principles

1. One hub, three services. Events are namespaced `ds.*`, `bus.*`, `fleet.*` (same naming law as SERVICE_MAP.md); the hub tables are shared (no prefix), the kinds registry says which service owns each kind, and a person only ever receives kinds of services their organization has.
2. Event ≠ notification ≠ delivery. An event happens once; it fans out to recipients (inbox rows); each inbox row has deliveries per channel. This removes today's "everyone reads the same org-wide row".
3. Fewer, better alerts: severity (red/amber/green), cooldown + dedupe key (state change only), snooze, ack/resolve, escalation, digests.
4. Safety notices to families are not optional; marketing-like ones always are. Consent and STOP handled for SMS.
5. Realtime = Supabase Realtime on the per-user inbox table (filter `user_id = me`), using the token pattern already in `realtime-actions.ts`. RLS is the boundary.

## 3b. Product rule set by the owner (2026-11-22) — ControlMiles never messages outsiders

1. **Driving school:** ControlMiles does NOT send SMS (or any message) to students or guardians by itself. The office staff sends them from their own phone/email, outside ControlMiles. The platform's job is to tell the office WHO needs a message, WHEN, and give the ready text; the staff sends it and marks it done.
2. **School bus:** the app sends nothing to parents. Only the administrative staff of the operations center of each company (the one that serves cities/counties) talks to parents. Drivers, monitors and assistants never contact a parent through the system — no parent contact data, no message button, no parent phone numbers in the driver app.
3. Consequence: the hub only notifies PEOPLE OF THE ORGANIZATION (owner, admin, operator, instructor, driver, monitor) about work to do. Everything aimed at an outsider becomes a **contact task** for the office. This removes our need for an SMS provider, A2P 10DLC registration, consent/STOP handling for outsiders and a parent push app; the legal exposure of the message itself stays with the school/company that sends it (still worth a lawyer's look at the message templates we suggest).
3b. **Driving school app stays as it is** (owner, 2026-11-22): the instructor keeps the Call / Message / Navigate buttons when a number was given. One difference: an instructor never contacts a minor directly, only the guardian who enrolled them. Built the same day: `fn_ds_contact_phone` gives the guardian's number for a minor (the student's own for an adult or emancipated minor); `get_branch_schedule` and `my_next_class` use it; buttons read "Call guardian / Message guardian"; test `tests/ds_instructor_contacts.sql`. Contact tasks for the office (above) are separate and still the plan for reminders.
4. Existing parent flows stay: the guardian invitation emails (`send-guardian-invite`, sent when an admin asks) and the parent's "not riding" notice that goes TO the office. Those are administrative, started by staff or by the parent toward the office.

### Contact tasks (new, replaces "send to student/parent")
`notification_contact_tasks(id, organization_id, branch_id, service, kind, person_type student|guardian, person_id, route_id/class_id, suggested_text, due_at, status open|done|skipped, done_by, done_at, method phone|sms|email|other, note)`.
- Shown in the portal as a work queue ("Messages to send today"), grouped by message so ONE text covers a whole route or the day's reminders.
- Buttons for the staff: copy text, open `sms:` / `tel:` / `mailto:` / WhatsApp link on their own device, "Mark as sent" (who, when, how). Nothing leaves ControlMiles.
- Bus: only roles admin/operator of that company see the parent contact data; RLS + the service gate; drivers/monitors have no policy at all on parent contacts (add to `service_isolation.sql`).
- Audit: who contacted which family and when (answers the city/county "did anyone tell the parents?").

## 4. Architecture

```
 source (trigger / cron / edge fn / app)
        │  fn_notify(kind, org, branch, subject, payload, dedupe_key)
        ▼
 notification_kinds (registry: service, default severity, audience, channels, cooldown, escalation)
        │  resolve recipients = org rules ⊕ role defaults ⊕ route/student/vehicle relations
        ▼
 notifications (the event, immutable)  ──►  notification_inbox (one row per recipient: read/ack/snooze/resolved)
                                                   │  Realtime (user_id = me) → bell, toast, dashboard panel, /admin/notifications
                                                   ▼
                                        notification_deliveries (outbox: inapp|push|email|sms, status, attempts, provider id)
                                                   │  worker edge fn `deliver-notifications` (pg_net on red, pg_cron each minute otherwise)
                                                   ▼
                                        FCM/APNs push · Resend email · SMS provider
```

Tables (all shared, registered in `ops.domain_tables` as `shared`; kinds carry the service):
- `notification_kinds(kind pk, service, label, default_severity, audience, default_channels[], cooldown_minutes, escalate_after_minutes, template_key, is_safety bool)`
- `notifications(id, organization_id, branch_id, kind, severity, subject_type, subject_id, payload, dedupe_key, created_at, resolved_at)` — unique `(organization_id, dedupe_key)` while open.
- `notification_inbox(notification_id, user_id, read_at, ack_at, snoozed_until, dismissed_at)` — RLS `user_id = auth.uid()`.
- `notification_rules(org, kind, recipients(role|user list), backup_user, escalate_after, channels, enabled)` — admin-editable.
- `notification_prefs(user, category, channels, quiet_hours, digest)` — per person.
- `notification_deliveries(...)`, `push_devices(user, platform, token, app, last_seen)`.
- `notification_contacts(org, person_type, person_id, channel, address, consent_at, opted_out_at)` — external people (students, guardians) who have no account; SMS needs recorded consent.

Migration of the driving school: keep `schedule_events` as the audit log; a trigger turns each row into a hub event (`ds.class_*`). The "Needs attention" panel then reads the inbox instead of computing severity in SQL. Nothing is lost; the log stays.

## 5. Use cases by service

### Driving school (improve what exists)
Existing → keep: class created/booked via portal/claimed/released/reassigned/changed/cancelled/deleted, time off, unavailable, late start, instructor no-show, unclaimed soon.
New:
- Office contact tasks (the office sends them, see §3b): reminder 24 h and 2 h before each class (one batch list with the text ready), late-cancel notice, lessons-left ("2 lessons left"), road-test / MVA appointment reminders, review request after the last lesson, re-engagement after N idle days, guardian copy for minors and hours-completed milestones (uses the existing guardian links). Each is a task with suggested text; the staff sends it from their own phone/email and marks it done.
- Waitlist: when a class is cancelled/released, the portal shows the office the next waitlisted students in order with the text ready ("a slot opened Tuesday 3 pm"); the office contacts them and assigns the slot — first to confirm wins (differentiator, see §2).
- Instructor: tomorrow's schedule the evening before, student cancelled/late/no-show (student no-show is a new kind), car change, class reassigned to me.
- Admin/owner: unclaimed class (existing), overbooking, instructor overload, payment failed/due, car pool conflicts, car maintenance/insurance/registration expiry, instructor license expiry, daily digest instead of many pings.

### School bus
- NO notifications to parents from the app (§3b). Market features such as ETA-to-parent, boarded/exited alerts and automatic delay messages are NOT built as parent messages. We keep the useful part for the operations center:
- Operations center (admin/operator only) gets the event AND the contact task: bus delayed N minutes (with the families of that route listed and one suggested text), route started late, driver late to start, child did not board / "not riding" notice received, route change / substitute driver or bus, weather or emergency broadcast list (all families of the affected routes, ready to call or text), breakdown/incident, pre-trip failed, route off-path, student with needs not boarded, attendance gaps, ETA slipping at a stop with a family waiting (so the center can call).
- Driver/monitor: receive operational alerts only — roster or needs change on my route (needs codes already built), route reassigned, end-of-route sweep reminder (nobody left on the bus), "call dispatch" prompts. One-tap incident/breakdown button reports TO the operations center, never to a parent. They never see parent phones or emails.
- Privacy rules: parent contact data is visible only to the company's admin/operators; drivers/monitors have no access; suggested texts are templates (no free text from the driver); every contact is logged (who, family, when, how); other students' names never appear in a family's message.

### Fleet (commercial vehicles)
- Owner/dispatcher (manage by exception): geofence enter/exit on named zones, speeding above the org's threshold, harsh braking/acceleration, vehicle offline / GPS lost, idle too long, after-hours use, failed inspection/defect, maintenance due by miles or date, document expiry (CDL, insurance, registration), fuel anomaly (nightly exists), shift not started.
- Driver: assigned vehicle changed, inspection reminder, document expiring, safety summary (exists).
- Every rule has primary recipient, backup, minutes before escalation; the monthly "alerts nobody acted on" report.

### Gig (individual drivers)
No organization portal. Keep local notifications. Out of scope for the hub except `driver_notifications` safety summaries if ever migrated.

## 6. Portal (web)

- Bell in the top bar again (unread count + toast for red) AND the dashboard "Needs attention" card, both fed by the same inbox.
- `/admin/notifications` — filters: severity, service, branch, status (open / acknowledged / resolved / snoozed); bulk acknowledge; deep link to the class / route / vehicle.
- `/admin/notifications/rules` — per kind: enabled, recipients, backup, escalation minutes, channels (owner/admin only).
- `/admin/notifications/log` — delivery log (sent, delivered, failed, opted out) — needed to answer "did the parent get it?".
- Person settings: channels per category, quiet hours (safety kinds ignore quiet hours), digest.
- Student/guardian: no portal; links in the message (confirm / reschedule / opt out) use the existing signed client tokens.

## 7. Phases

1. Hub core + driving school in-app: tables, registry, `fn_notify`, fan-out from `schedule_events`, inbox Realtime, bell + notifications page + rules. No new vendors. Tests: tenant/service isolation (extend `service_isolation.sql` with "a user never sees another organization's or service's inbox").
2. Delivery: email through Resend (reminders + digest), person preferences/quiet hours, push to the Fleet app (needs Firebase project + APNs key + `firebase_messaging`).
3. Driving-school contact tasks for the office ("Messages to send today": reminders, waitlist offers, lessons-left, road-test) with ready text and "mark as sent"; student no-show; NO SMS provider.
4. School bus: operations-center alerts + contact tasks (delay, missed bus, route change, incident, weather broadcast list); driver/monitor operational alerts and one-tap incident to the center; no message ever goes to a parent from the app.
5. Fleet rules: geofence/speed/maintenance/doc expiry with escalation and the 30–60-day unused-alert audit.

## 8. Decisions / lead times

- DECIDED 2026-11-22: no SMS provider, no parent push app, nothing sent to outsiders by ControlMiles (§3b). Only still open: should the office's reminders be allowed as an AUTOMATIC email from ControlMiles to students? Default answer from the owner's rule: no — the office sends.
- Firebase project + Apple APNs key for push to STAFF in the Fleet app (new build to publish); web bell works without it.
- Pilot school Front Line (driving school) → phases 1–3 first; bus after.
- The templates suggested to the office are still wording a school sends to families (minors' guardians): have a lawyer glance at them before they ship as defaults; the sending itself is the school's own act outside ControlMiles. I did not research the legal specifics.
