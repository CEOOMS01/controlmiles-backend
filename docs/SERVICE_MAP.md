# ControlMiles service map

One page that says **what belongs to which service**, in the database, the web, the Fleet app and the server functions, and
the rules that keep them apart. It is the answer to "where does this go?" for every new feature. Phase 1 of the service
separation, 2026-11-21. The table-level rules are enforced by the database (`ops.domain_violations()`, the `domain_guard`
event trigger, `supabase-fleet/tests/service_separation.sql`); the rest are conventions until phases 2 and 3 enforce them
in the web and the app. `docs/CORE_CONTRACT.md` explains the five domains and what each may call.

## 1. The services

| Service | `organizations.industry_template` | Plan features only it gets (`plan_feature_rules`) | Domain in `ops.domain_tables` |
|---|---|---|---|
| Driving school | `driving_school` | `classes`, `students`, `student_portal`, `student_booking`, `student_packages`, `student_certificates`, `student_evaluations`, `class_reminders`, `sms_reminders`, `state_records` | `driving_school` |
| School bus | `school_transport` | `school`, `school_live` | `school_bus` |
| Fleets (general, trucking, delivery, construction, field service, passenger, sales) | `general`, `trucking`, ... | `routes` (all fleets), `ifta` (trucking, construction, general), `owner_operators` (delivery, trucking, general), `trip_approval` (sales) | `fleet` |
| Platform ("core") | all | the features every service gets: `activity_log`, `dvir`, `fleet_export`, `fuel_alerts`, `live_map`, `open_assignment`, `safety_scores`, `shift_schedules`; `geofences` for everyone except driving school | `core` |
| Gig (own project, own database) | none | none | `gig` |

`organizations.service` is the commercial name of the same thing (`school_bus` for `school_transport`, ...); a trigger
(`fn_sync_org_service`) keeps the two in step. The plan catalogue also lists services that are not built yet
(construction, delivery, field service, passenger, sales); they behave as a plain fleet with their own words
(`web/src/lib/service-profile.ts`).

## 2. Naming law (database)

| Prefix | Meaning | Examples |
|---|---|---|
| `ds_` | driving school only | `ds_students`, `ds_clients`, `ds_availability` |
| `bus_` | school bus only | `bus_students`, `bus_route_stops`, `bus_guardians` |
| none | shared by every service (core and fleet) | `organizations`, `vehicles`, `routes`, `shifts`, `shift_blocks`, `fuel_*`, `ifta_*` |

- A new table of a service takes its prefix. A new shared table needs a reason in its migration.
- `routes` is shared on purpose: fleet dispatch routes and school bus runs, told apart by `route_type`
  (`fn_route_feature_ok`). `shift_blocks` is a driving school class that lives in a fleet table (see CORE_CONTRACT).
- Functions: `ds_*` and `fn_ds_*` belong to driving school. School bus functions keep their API names (`my_school_routes_today`,
  `start_route_run`, `record_ridership`, ...) because the apps call them; a new bus function is named `bus_*`.
- Every `ds_` and `bus_` table carries a comment `service=...`; `routes` says `service=shared`.

## 3. Rules the database enforces

1. **Registry.** Every public table is listed in `ops.domain_tables`; every row there points to a table that exists (rule R6).
2. **No cross-service reads in functions.** gig functions never touch fleet / school bus / driving school tables, and a school bus
   function never touches a driving school table (R1, R2).
3. **Triggers on core tables** are registered in `ops.domain_triggers` and a service trigger has a `WHEN` clause (R3, R4).
4. **Run-time SQL** is allowed only for listed functions (R5); one function name, one version (R7).
5. **Plan feature on every row.** A service table with an `organization_id` and policies has a restrictive policy that requires its plan
   feature (`fn_org_has_feature` / `fn_org_feature_internal` / `fn_route_feature_ok`), so a school without the service sees nothing
   whatever the role. Tables without policies are server-only on purpose.
6. **Tenant and branch fences.** `tests/tenant_isolation.sql` (one school never reads another) and `tests/branch_isolation.sql`.
   Branches exist for driving school and fleets; the school bus service refuses to create one (`tr_branches_service_check`) until
   its tables get a `branch_id`.
7. **`domain_guard`** (event trigger, on in Fleet since 2026-11-21) refuses a table, function or trigger that breaks 1 to 4 when it is created;
   `ops.fn_domain_check_daily` re-checks every morning.

Run `ops.domain_violations()` and the three tests after every migration that touches tables or functions.

## 4. What is where

### Driving school
- **Tables** (`ds_*`, `instructor_notices`, `schedule_event*`, `driving_school_clients`) plus `shift_blocks` (the classes).
- **Web**: `admin/students/*`, `admin/shifts/*` (agenda, weekly template, availability), `admin/school-dashboard.tsx` (its dashboard;
  the name is misleading, see section 6), `book/[slug]/*` (public enrolment and orders), `student/[token]/*` (student portal),
  `lib/driving-school.ts`, `lib/ds-conflicts.ts`, `lib/school-pricing.ts`, `lib/certificate-pdf.ts`, `lib/hour-log-pdf.ts`, `lib/custom-domain.ts`.
- **Fleet app**: `instructor_schedule_screen`, `class_detail_screen`, `evaluate_class_screen`, `claim_driver_slot_screen`;
  services `instructor_schedule_service`, `shift_block_service`, `evaluation_service`.
- **Edge functions**: `ds-banquest`, `ds-portal-access`, `ds-public-enroll`, `send-class-reminders`.

### School bus
- **Tables**: `bus_students`, `bus_sites`, `bus_route_stops`, `bus_route_runs`, `bus_route_stop_events`, `bus_route_crew_overrides`,
  `bus_stop_assignments`, `bus_ridership_events`, `bus_guardians`, `bus_student_guardians`, `bus_guardian_invites`, `bus_ride_notices`,
  `bus_clients`, `bus_need_catalog`, `bus_student_needs` (transport needs, below); plus the shared `routes` (`route_type` = `school_am` / `school_pm`).
- **Web**: `admin/school/*` (routes, students and parents, attendance, live run, `needs` codes), `lib/school-needs.ts`, `lib/school.ts`, `lib/school-status.ts`, `lib/school-crew.ts`,
  `lib/school-attendance.ts`.
- **Fleet app**: `school_run_screen`, `monitor_home_screen`, `parent_home_screen`; services `school_route_service`, `guardian_service`.
- **Edge functions**: `send-guardian-invite`.

**Transport needs** (2026-11-21): each school has its own catalog of short codes (`bus_need_catalog`: groups program, equipment, communication, mobility; the Baltimore City model, from the City Schools route-codes sheet, loads in one click with `bus_seed_need_catalog`). A student gets codes (`bus_student_needs`), one program and a short note (`bus_students.program_need_id`, `transport_note`). Never a diagnosis. The driver and the aide read only the needs of the students of their route, through `bus_route_needs(route)`, which returns the legend of the codes used on that route.

### Fleets (general, trucking, ...)
- **Tables**: `shifts`, `routes`, `fuel_*`, `ifta_*`, `state_*`, `vehicle_geofence*`, `trip_approvals`, `driver_workdays`, `driver_invites`, ...
- **Web**: `admin/routes`, `admin/fuel`, `admin/ifta`, `admin/geofences`, `admin/approvals`, `admin/safety`, `admin/export`, `lib/ifta.ts`, `lib/fleet-export.ts`.
- **Fleet app**: `fleet_dashboard_screen`, `fleet_live_map_screen`, `fuel_purchase_capture_screen`, `driver_safety_score_screen`; services
  `ifta_service`, `fuel_purchase_service`, `geofence_service`, `safety_score_service`.
- **Edge functions**: `send-fuel-alerts`, `sync-ifta-tax-rates`, `send-driver-invite`, `accept-invite-account`, `resolve-driver-login`.

### Platform (core)
- **Tables**: tenant (`organizations`, `organization_members`, `branches`), trips (`sessions`, `session_sections`, `session_gps_breadcrumbs`),
  vehicles and inspections, `profiles`, audit and notifications.
- **Web**: `admin/layout.tsx`, `admin/settings`, `admin/roster`, `admin/vehicles`, `admin/import`, `admin/maintenance`, `admin/reviews`,
  `admin/org`, `admin/activity`, `lib/fleet-features.ts`, `lib/branch-scope.ts`, `lib/service-profile.ts`, `lib/supabase/*`, `lib/errors.ts`.
- **Edge functions**: `report-error`, `ingest-gps-breadcrumb`, `cgc-seal-trip`, `check-email-exists`, `delete-account`.
- **Billing** (Gig and Fleet plans): `create-checkout-session`, `create-portal-session`, `stripe-webhook`, `verify-play-purchase`, `play-rtdn`.

## 5. Adding a service or a feature

1. Pick its prefix (`xx_`) and domain; add the rows to `ops.domain_tables` **first** (the guard refuses an unregistered table).
2. Create its tables with RLS and a restrictive plan-feature policy; comment the table `service=xx`.
3. Add its features to `plan_feature_rules` with the `templates` that get them; the menu, the page (`requireFeature`) and the policies follow.
4. Code lives in its own folder (web: pages under `admin/<service>/`, code under `lib/` with the service in the name; app: its screens and services,
   named with the service); shared code goes in the platform part and never imports from a service.
5. Run `ops.domain_violations()`, `tests/service_separation.sql`, `tests/tenant_isolation.sql`.

## 6. Still to do (phases 2 and 3)

- Web: group the code by service (`features/driving-school`, `features/school-bus`, `features/fleet`, shared) and add an ESLint rule that forbids
  importing from one service into another. Misleading names to fix: `admin/school-dashboard.tsx` (driving school) next to `admin/school/*` (bus);
  `lib/school-pricing.ts` (driving school) next to `lib/school-*.ts` (bus); `admin/students` (driving school) next to `admin/school/students` (bus).
- Fleet app: folders per service for screens and services, with the same import rule.
- School bus branches: `branch_id` on bus tables, fences and filters, then remove `tr_branches_service_check`.
- Driving school classes in their own table (`ds_lessons`) instead of `shift_blocks` (CORE_CONTRACT, finding 9 of the 2026-10-21 audit).
- A test that creates one school of each service and checks it sees nothing of the others.
