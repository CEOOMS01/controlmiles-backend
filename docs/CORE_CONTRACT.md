# ControlMiles core contract

What the platform ("core") offers and what each service may use. Measured on the live database on 2026-10-23 with `ops.v_domain_coupling` (a text scan of every public function against `ops.domain_tables`); re-run it, do not trust this page blindly.

## The five domains (`ops.domain_tables`)

| Domain | Tables |
|---|---|
| **core** (platform) | Tenant: `organizations`, `organization_members`, `branches`, `branch_moves`, `fleet_type_changes`. Trips: `sessions`, `session_sections`, `session_gps_breadcrumbs`, `audit_events`, `reports`, `trip_incidents`, `driver_safety_events`. Vehicles: `vehicles`, `vehicle_inspections`, `vehicle_maintenance_records`, `vehicle_odometer_checkpoints`. Identity: `profiles`, `user_onboarding`. Internal: `auth_signup_errors`, `edge_function_rate_limits`, `report_access_attempts`, `pdf_export_log`, `plan_feature_rules`. |
| **fleet** (general fleet service) | `driver_invites`, `fleet_driver_slots`, `driver_notifications`, `driver_workdays`, `shifts`, `shift_blocks`, `routes`, `trip_approvals`, `fuel_*`, `ifta_*`, `vehicle_geofence*`, `driver_slot_claim_attempts` |
| **school_bus** | `school_sites`, `students`, `route_stops`, `route_runs`, `route_stop_events`, `route_crew_overrides`, `ridership_events`, `student_stop_assignments`, `school_guardians`, `student_guardians`, `guardian_invites` |
| **driving_school** | the 20 `ds_*` tables |
| **gig** | `gig_apps`, `gig_app_packages`, `subscriptions`, `subscription_events`, `play_subscriptions` |

## What each service really uses (functions touching core tables)

- **gig**: only `profiles`. Gig is practically independent; it shares `sessions`/`vehicles` with the others, told apart by `organization_id is null`.
- **fleet**: `profiles` (12 functions), `vehicles` (10), `session_gps_breadcrumbs` (8), `sessions` (7), `user_onboarding` (4), then single uses.
- **school_bus**: `profiles`, `vehicles` (live location for automatic stop arrival), `sessions` (the run is tied to the driver's trip). It also depends on the fleet table `routes` (`route_type` school_am/school_pm).
- **driving_school**: no core trips/vehicles in its own functions except through classes. It depends on two fleet tables: `shift_blocks` (**a class is a row of `shift_blocks`**, 12 functions) and `driver_workdays` (`get_my_shift_day`).

So the only real cross-service dependencies are: driving_school -> fleet (`shift_blocks`, `driver_workdays`) and school_bus -> fleet (`routes`). The `students` hits that `ops.v_domain_coupling` shows between driving_school and school_bus are false positives (the word is also a feature name in `fn_require_org_feature(..., 'students')`).

## Platform API (what services should call instead of reading tables)

| Function | Use |
|---|---|
| `is_org_member / is_org_owner / is_org_admin_or_owner / is_org_operator_or_above(org)` | role checks (RLS and RPCs) |
| `fn_org_features(org)` / `fn_org_feature_internal(org, f)` / `fn_require_org_feature(org, f)` | plan features (data in `plan_feature_rules`) |
| `fn_org_tier_internal(org)` / `fn_org_enterprise_internal(org)` | plan tier |
| `fn_org_today(org)` | today's date in the organization's timezone |
| `fn_meters_between(...)` | distance |
| `check_rate_limit(fn, key, max, seconds)` | rate limiting (service role / definer only) |

## Rules (enforced by the domain guard, `ops.domain_violations()`)
1. gig functions never touch fleet / school_bus / driving_school tables, and school_bus never touches driving_school.
2. A trigger on a core table must be registered in `ops.domain_triggers`; one that serves a service needs a `WHEN` clause so other services pay nothing.
3. A new table is registered in `ops.domain_tables` first (the guard refuses to create an unregistered one).
4. No two functions with the same name (R7), no run-time built SQL unless allowed (R5).

## What would have to change to hand one service out on its own

- **School Bus alone (e.g. a city):** needs core + `routes` + the school_bus tables. Cut: give school_bus its own `school_routes` instead of sharing `routes`, and the fleet-only tables (shifts, fuel, IFTA, geofences) are simply not deployed.
- **Driving School alone:** needs core + `shift_blocks` + `driver_workdays`. Cut: move classes to their own `ds_lessons` table (finding 9 of the 2026-10-21 audit) so driving_school stops depending on fleet.
- **Gig alone:** already the smallest; needs core and the billing tables.
