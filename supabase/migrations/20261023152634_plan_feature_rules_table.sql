-- Plans as data (step 5 of the ecosystem plan, 2026-10-23).
-- Until now which features each service (industry template) gets at each
-- plan was an if-ladder inside fn_org_feature_list_internal. It is now a
-- table, so a new service or a custom plan (e.g. a city that buys only the
-- School Bus software) is a few rows, not a function rewrite.
--
-- Meaning of a row: `feature` is included when the organization's plan rank
-- is >= min_plan AND (templates is null OR its industry_template is in
-- templates). Plan rank: none = 0 (no subscription and trial over),
-- starter = 1, growth = 2 (also the 15-day trial and exempt accounts),
-- enterprise = 3 (growth + an active enterprise subscription or the
-- tier_enforcement_exempt flag, as fn_org_enterprise_internal says).
--
-- Behavior is identical to the previous if-ladder (checked for every
-- template x plan before applying).

-- Registered first: the domain guard refuses to create an unregistered table.
insert into ops.domain_tables (tbl, domain) values ('plan_feature_rules', 'core')
on conflict (tbl) do update set domain = excluded.domain;

create table if not exists public.plan_feature_rules (
  id bigint generated always as identity primary key,
  feature text not null check (feature ~ '^[a-z][a-z0-9_]*$'),
  min_plan text not null check (min_plan in ('starter', 'growth', 'enterprise')),
  templates text[],
  note text,
  created_at timestamptz not null default now()
);
create unique index if not exists plan_feature_rules_unique
  on public.plan_feature_rules (feature, min_plan, templates) nulls not distinct;

alter table public.plan_feature_rules enable row level security;
revoke all on public.plan_feature_rules from anon, authenticated;
comment on table public.plan_feature_rules is
  'Internal: read only by fn_plan_features (SECURITY DEFINER). Which features each service (industry template) gets at each plan.';

insert into public.plan_feature_rules (feature, min_plan, templates, note) values
  ('dvir',                 'starter',    null, 'pre-trip inspection, every service'),
  ('owner_operators',      'starter',    array['delivery','trucking','general'], null),
  ('ifta',                 'starter',    array['trucking','construction','general'], null),
  ('school',               'starter',    array['school_transport'], 'School Bus: planning pages and driver app routes'),
  ('live_map',             'starter',    array['school_transport','driving_school'], 'schools see the live map from the first plan'),
  ('live_map',             'growth',     null, null),
  ('fleet_export',         'growth',     null, null),
  ('activity_log',         'growth',     null, null),
  ('safety_scores',        'growth',     null, null),
  ('fuel_alerts',          'growth',     null, null),
  ('shift_schedules',      'growth',     null, null),
  ('open_assignment',      'growth',     null, null),
  ('routes',               'growth',     array['delivery','field_service','trucking','construction','passenger','general'], null),
  ('geofences',            'growth',     array['general','delivery','field_service','trucking','construction','passenger','sales','school_transport'], 'every service except Driving School'),
  ('school_live',          'growth',     array['school_transport'], 'School Bus: live run board'),
  ('trip_approval',        'growth',     array['sales'], null),
  ('classes',              'growth',     array['driving_school'], null),
  ('students',             'growth',     array['driving_school'], null),
  ('student_evaluations',  'enterprise', array['driving_school'], null),
  ('student_portal',       'enterprise', array['driving_school'], null),
  ('class_reminders',      'enterprise', array['driving_school'], null),
  ('student_packages',     'enterprise', array['driving_school'], null),
  ('student_certificates', 'enterprise', array['driving_school'], null),
  ('student_booking',      'enterprise', array['driving_school'], null),
  ('state_records',        'enterprise', array['driving_school'], null),
  ('sms_reminders',        'enterprise', array['driving_school'], null)
on conflict do nothing;

create or replace function public.fn_plan_features(p_template text, p_plan_rank integer)
returns text[]
language sql
stable
security definer
set search_path to 'public'
as $function$
  select coalesce(array_agg(distinct r.feature order by r.feature), '{}'::text[])
    from public.plan_feature_rules r
   where p_template is not null
     and p_plan_rank >= case r.min_plan when 'starter' then 1 when 'growth' then 2 else 3 end
     and (r.templates is null or p_template = any (r.templates));
$function$;
revoke execute on function public.fn_plan_features(text, integer) from public, anon, authenticated;

create or replace function public.fn_org_feature_list_internal(p_org_id uuid)
returns text[]
language sql
stable
security definer
set search_path to 'public'
as $function$
  select coalesce((
    select public.fn_plan_features(
             o.industry_template,
             case public.fn_org_tier_internal(o.id)
               when 'starter' then 1
               when 'growth' then case when public.fn_org_enterprise_internal(o.id) then 3 else 2 end
               else 0
             end)
      from public.organizations o
     where o.id = p_org_id
  ), '{}'::text[]);
$function$;
