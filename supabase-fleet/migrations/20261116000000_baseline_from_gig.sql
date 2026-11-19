


SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE EXTENSION IF NOT EXISTS "pg_cron" WITH SCHEMA "pg_catalog";






COMMENT ON SCHEMA "public" IS 'standard public schema';



CREATE EXTENSION IF NOT EXISTS "pg_net" WITH SCHEMA "public";






CREATE SCHEMA IF NOT EXISTS "ops";


ALTER SCHEMA "ops" OWNER TO "postgres";


CREATE EXTENSION IF NOT EXISTS "pg_stat_statements" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "postgis" WITH SCHEMA "extensions";






CREATE EXTENSION IF NOT EXISTS "supabase_vault" WITH SCHEMA "vault";






CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA "extensions";






CREATE OR REPLACE FUNCTION "ops"."domain_violations"("p_full" boolean DEFAULT true, "p_fn" "oid" DEFAULT NULL::"oid", "p_tg" "oid" DEFAULT NULL::"oid", "p_tbl" "oid" DEFAULT NULL::"oid") RETURNS TABLE("rule" "text", "object" "text", "detail" "text")
    LANGUAGE "plpgsql" STABLE
    SET "search_path" TO 'pg_catalog'
    AS $_$
begin
  return query
  with fns as (
    select p.oid, p.proname::text as fn, p.prosrc,
           regexp_replace(regexp_replace(p.prosrc, '--[^\n]*', '', 'g'), '''[^'']*''', '', 'g') as code
      from pg_proc p
     where p.pronamespace = 'public'::regnamespace
       and p.prokind = 'f'
       and not exists (select 1 from pg_depend e where e.classid = 'pg_proc'::regclass and e.objid = p.oid and e.deptype = 'e')
       and p.proname not in (select a.fn from ops.domain_allowed_functions a)
       and (p_full or p.oid = p_fn)
  ),
  touches as (
    select f.fn, array_agg(distinct d.domain order by d.domain) as domains
      from fns f
      join ops.domain_tables d
        on f.code ~* ('(^|[^a-z0-9_])(public\.)?' || d.tbl || '([^a-z0-9_]|$)')
     group by f.fn
  ),
  core_triggers as (
    select t.oid, c.relname::text as tbl, t.tgname::text as tg
      from pg_trigger t
      join pg_class c on c.oid = t.tgrelid and c.relnamespace = 'public'::regnamespace
      join ops.domain_tables d on d.tbl = c.relname and d.domain = 'core'
     where not t.tgisinternal and (p_full or t.oid = p_tg)
  )
  select 'R1', x.fn, array_to_string(x.domains, ', ')
    from touches x
   where 'gig' = any(x.domains) and x.domains && array['fleet', 'school_bus', 'driving_school']
  union all
  select 'R2', x.fn, array_to_string(x.domains, ', ')
    from touches x
   where x.domains @> array['school_bus', 'driving_school']
  union all
  select 'R3', ct.tbl || '.' || ct.tg, 'trigger on a core table is not in ops.domain_triggers'
    from core_triggers ct
   where not exists (select 1 from ops.domain_triggers r where r.tbl = ct.tbl and r.tg = ct.tg)
  union all
  select 'R4', ct.tbl || '.' || ct.tg, r.domain || ' trigger needs WHEN (' || r.guard || ')'
    from core_triggers ct
    join ops.domain_triggers r on r.tbl = ct.tbl and r.tg = ct.tg
   where r.guard is not null
     and position(upper(r.guard) in upper(pg_get_triggerdef(ct.oid))) = 0
  union all
  select 'R5', f.fn, 'builds SQL at run time; allow it in ops.domain_allowed_functions with a reason'
    from fns f
   where f.prosrc ~* '(^|[^a-z0-9_])execute\s+(?!function|procedure)'
  union all
  select 'R6', c.relname::text, 'table is not in ops.domain_tables'
    from pg_class c
   where c.relnamespace = 'public'::regnamespace
     and c.relkind in ('r', 'p')
     and not c.relispartition
     and not exists (select 1 from pg_depend e where e.classid = 'pg_class'::regclass and e.objid = c.oid and e.deptype = 'e')
     and not exists (select 1 from ops.domain_tables d where d.tbl = c.relname)
     and (p_full or c.oid = p_tbl)
  union all
  select 'R7', p.proname::text,
         count(*) || ' versions of this function: ' || string_agg(pg_get_function_identity_arguments(p.oid), ' | ')
           || '; remove the old one'
    from pg_proc p
   where p.pronamespace = 'public'::regnamespace
     and p.prokind = 'f'
     and not exists (select 1 from pg_depend e where e.classid = 'pg_proc'::regclass and e.objid = p.oid and e.deptype = 'e')
     and (p_full or p.proname = (select q.proname from pg_proc q where q.oid = p_fn))
   group by p.proname
  having count(*) > 1;
end $_$;


ALTER FUNCTION "ops"."domain_violations"("p_full" boolean, "p_fn" "oid", "p_tg" "oid", "p_tbl" "oid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "ops"."fn_domain_check_daily"() RETURNS "void"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'pg_catalog'
    AS $$
begin
  insert into ops.domain_check_log (source, violation_count, detail)
  select 'daily', count(*), string_agg(v.rule || '  ' || v.object || ': ' || v.detail, E'\n')
    from ops.domain_violations() v;
end $$;


ALTER FUNCTION "ops"."fn_domain_check_daily"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "ops"."fn_domain_guard"() RETURNS "event_trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'pg_catalog'
    AS $$
declare
  v text;
begin
  if current_user <> 'postgres' then
    return;
  end if;
  if coalesce(current_setting('cm.skip_domain_check', true), '') = 'on' then
    begin
      insert into ops.domain_check_log (source, detail)
      select 'bypass', string_agg(c.command_tag || ' ' || coalesce(c.object_identity, '?'), E'\n')
        from pg_event_trigger_ddl_commands() c;
    exception when others then
      raise warning 'domain guard bypass not logged: %', sqlerrm;
    end;
    return;
  end if;
  begin
    select string_agg(x.rule || '  ' || x.object || ': ' || x.detail, E'\n')
      into v
      from pg_event_trigger_ddl_commands() c
      cross join lateral ops.domain_violations(
        false,
        case when c.classid = 'pg_proc'::regclass then c.objid end,
        case when c.classid = 'pg_trigger'::regclass then c.objid end,
        case when c.classid = 'pg_class'::regclass then c.objid end
      ) x
     where c.command_tag in ('CREATE FUNCTION', 'ALTER FUNCTION', 'CREATE TRIGGER', 'CREATE TABLE')
       and c.classid in ('pg_proc'::regclass, 'pg_trigger'::regclass, 'pg_class'::regclass);
  exception when others then
    raise warning 'domain guard skipped: %', sqlerrm;
    return;
  end;
  if v is not null then
    raise exception 'Domain boundary check failed'
      using detail = v,
            hint = 'Register the table or trigger in ops.domain_tables / ops.domain_triggers before creating it, '
                   'add the WHEN guard, or allow the function in ops.domain_allowed_functions. '
                   'See supabase/checks/domain_boundaries.sql.';
  end if;
end $$;


ALTER FUNCTION "ops"."fn_domain_guard"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."abort_shift_block_start"("p_block_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  perform set_config('cm.shift_block_rpc', 'on', true);
  update public.shift_blocks
     set status = 'scheduled', started_at = null, late_minutes = null
   where id = p_block_id and driver_id = auth.uid()
     and status = 'in_progress' and session_id is null;
  perform set_config('cm.shift_block_rpc', 'off', true);
end $$;


ALTER FUNCTION "public"."abort_shift_block_start"("p_block_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."accept_driver_invite"("p_token" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
DECLARE
  v_caller uuid := auth.uid();
  v_caller_email text;
  v_caller_account_type text;
  v_hash text := encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_invite record;
BEGIN
  IF v_caller IS NULL THEN
    RAISE EXCEPTION 'Authentication required';
  END IF;

  SELECT email, account_type INTO v_caller_email, v_caller_account_type
  FROM public.profiles WHERE id = v_caller;

  IF v_caller_account_type = 'fleet_admin' THEN
    RAISE EXCEPTION 'You already manage your own fleet and cannot join another as a driver';
  END IF;

  SELECT id, organization_id, email, slot_id, intended_role INTO v_invite
  FROM public.driver_invites
  WHERE token_hash = v_hash AND status = 'pending' AND expires_at > now()
  LIMIT 1;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Invalid or expired invite';
  END IF;

  IF lower(v_caller_email) != lower(v_invite.email) THEN
    RAISE EXCEPTION 'This invite was sent to a different email address';
  END IF;

  INSERT INTO public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
  VALUES (v_invite.organization_id, v_caller, coalesce(v_invite.intended_role, 'driver'), true, now())
  ON CONFLICT (organization_id, user_id) DO UPDATE
    SET is_active = true, joined_at = now();

  UPDATE public.profiles
  SET account_type = 'fleet_driver', default_org_id = v_invite.organization_id
  WHERE id = v_caller;

  INSERT INTO public.user_onboarding (user_id, account_type_chosen)
  VALUES (v_caller, true)
  ON CONFLICT (user_id) DO UPDATE SET account_type_chosen = true;

  UPDATE public.driver_invites
  SET status = 'accepted', accepted_by = v_caller
  WHERE id = v_invite.id;

  IF v_invite.slot_id IS NOT NULL THEN
    UPDATE public.fleet_driver_slots
    SET claimed_by = v_caller, claimed_at = now()
    WHERE id = v_invite.slot_id AND claimed_by IS NULL;
  END IF;

  RETURN v_invite.organization_id;
END;
$$;


ALTER FUNCTION "public"."accept_driver_invite"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."accept_guardian_invite"("p_token" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_hash text := encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_email text;
  v_invite public.guardian_invites;
  v_display_id text;
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  select email into v_email from public.profiles where id = auth.uid();
  select * into v_invite from public.guardian_invites
   where token_hash = v_hash and status = 'pending' and expires_at > now();
  if not found then raise exception 'Invalid or expired invite'; end if;
  if lower(coalesce(v_email, '')) <> lower(v_invite.email) then
    raise exception 'This invite was sent to a different email address';
  end if;
  update public.school_guardians
     set user_id = auth.uid(), claimed_at = coalesce(claimed_at, now())
   where id = v_invite.guardian_id and is_active
     and (user_id is null or user_id = auth.uid())
  returning display_id into v_display_id;
  if v_display_id is null then raise exception 'Invalid or expired invite'; end if;
  update public.guardian_invites set status = 'accepted', accepted_at = now() where id = v_invite.id;
  return v_display_id;
end $$;


ALTER FUNCTION "public"."accept_guardian_invite"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."accept_legal_terms"("p_version" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  if p_version is null or p_version !~ '^\d{4}-\d{2}-\d{2}$' then
    raise exception 'Invalid terms version';
  end if;
  update public.profiles
     set legal_accepted_at = now(), legal_terms_version = p_version
   where id = auth.uid();
end;
$_$;


ALTER FUNCTION "public"."accept_legal_terms"("p_version" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."accept_my_pending_invite"() RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_caller uuid := auth.uid();
  v_email text;
  v_account_type text;
  v_confirmed timestamptz;
  v_invite record;
begin
  if v_caller is null then raise exception 'Authentication required'; end if;

  select p.email, p.account_type, u.email_confirmed_at into v_email, v_account_type, v_confirmed
    from public.profiles p join auth.users u on u.id = p.id where p.id = v_caller;
  if v_confirmed is null then raise exception 'Confirm your email first'; end if;
  if v_account_type = 'fleet_admin' then
    raise exception 'You already manage your own fleet and cannot join another as a driver';
  end if;

  select id, organization_id, slot_id, intended_role into v_invite
    from public.driver_invites
   where status = 'pending' and expires_at > now() and lower(email) = lower(v_email)
   order by created_at desc
   limit 1;
  if not found then raise exception 'Invalid or expired invite'; end if;

  insert into public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
  values (v_invite.organization_id, v_caller, coalesce(v_invite.intended_role, 'driver'), true, now())
  on conflict (organization_id, user_id) do update set is_active = true, joined_at = now();

  update public.profiles set account_type = 'fleet_driver', default_org_id = v_invite.organization_id
   where id = v_caller;

  insert into public.user_onboarding (user_id, account_type_chosen) values (v_caller, true)
  on conflict (user_id) do update set account_type_chosen = true;

  update public.driver_invites set status = 'accepted', accepted_by = v_caller where id = v_invite.id;

  if v_invite.slot_id is not null then
    update public.fleet_driver_slots set claimed_by = v_caller, claimed_at = now()
     where id = v_invite.slot_id and claimed_by is null;
  end if;

  return v_invite.organization_id;
end;
$$;


ALTER FUNCTION "public"."accept_my_pending_invite"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."apply_regular_trip_to_past"("p_rule_id" "uuid", "p_dry_run" boolean DEFAULT true) RETURNS integer
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
declare
  r public.regular_trips%rowtype;
  v_count integer;
begin
  select * into r from public.regular_trips t where t.id = p_rule_id and t.user_id = auth.uid();
  if not found then return 0; end if;

  if p_dry_run then
    select count(*) into v_count from public.session_sections s
    where s.user_id = auth.uid() and s.gig_app = 'custom' and s.organization_id is null
      and s.section_status = 'closed' and s.irs_purpose is null
      and public.fn_regular_trip_covers(r, s.start_latitude, s.start_longitude, s.end_latitude, s.end_longitude);
    return v_count;
  end if;

  update public.session_sections s
  set irs_purpose = r.purpose, auto_purpose_source = 'regular_trip'
  where s.user_id = auth.uid() and s.gig_app = 'custom' and s.organization_id is null
    and s.section_status = 'closed' and s.irs_purpose is null
    and public.fn_regular_trip_covers(r, s.start_latitude, s.start_longitude, s.end_latitude, s.end_longitude);
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;


ALTER FUNCTION "public"."apply_regular_trip_to_past"("p_rule_id" "uuid", "p_dry_run" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."assign_trips_to_vehicle"("p_vehicle_id" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_uid uuid := auth.uid();
  v record;
  n int;
  m double precision;
begin
  if v_uid is null then
    raise exception 'not authenticated';
  end if;
  select owner_user_id, organization_id, is_archived into v
    from public.vehicles where id = p_vehicle_id;
  if not found
     or v.organization_id is not null
     or v.owner_user_id is distinct from v_uid
     or coalesce(v.is_archived, false) then
    raise exception 'VEHICLE_NOT_YOURS' using errcode = 'P0001';
  end if;

  perform set_config('cm.assign_trip_vehicle', 'on', true);
  with upd as (
    update public.sessions
       set vehicle_id = p_vehicle_id
     where user_id = v_uid
       and organization_id is null
       and is_closed
       and vehicle_id is null
       and cgc_sealed_at is null
    returning id, total_miles
  ), ins as (
    insert into public.trip_vehicle_assignments (session_id, user_id, vehicle_id, miles)
    select id, v_uid, p_vehicle_id, total_miles from upd
    returning 1
  )
  select count(*), coalesce(sum(total_miles), 0) into n, m from upd;
  perform set_config('cm.assign_trip_vehicle', 'off', true);

  return jsonb_build_object('assigned', n, 'miles', m);
end;
$$;


ALTER FUNCTION "public"."assign_trips_to_vehicle"("p_vehicle_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."assign_vehicle_to_driver"("p_vehicle_id" "uuid", "p_driver_user_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_vehicle_org_id uuid;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  SELECT organization_id INTO v_vehicle_org_id
  FROM public.vehicles
  WHERE id = p_vehicle_id;

  IF v_vehicle_org_id IS NULL THEN
    RAISE EXCEPTION 'Vehicle not found or not a fleet vehicle';
  END IF;

  IF NOT public.is_org_operator_or_above(v_vehicle_org_id) THEN
    RAISE EXCEPTION 'Only an org admin, owner, or operator can assign vehicles';
  END IF;

  IF public.fn_org_effective_tier(v_vehicle_org_id) = 'none' THEN
    RAISE EXCEPTION 'FLEET_SUBSCRIPTION_REQUIRED';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = v_vehicle_org_id
      AND user_id = p_driver_user_id
      AND is_active = true
  ) THEN
    RAISE EXCEPTION 'That person is not an active member of this organization';
  END IF;

  UPDATE public.vehicles
  SET assigned_driver_id = p_driver_user_id
  WHERE id = p_vehicle_id;
END;
$$;


ALTER FUNCTION "public"."assign_vehicle_to_driver"("p_vehicle_id" "uuid", "p_driver_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."cancel_student_no_ride"("p_student_id" "uuid", "p_date" "date") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_role text := public.fn_ride_notice_role(p_student_id);
  v_org uuid := (select organization_id from public.students where id = p_student_id);
begin
  if p_date is null or p_date < public.fn_org_today(v_org) then
    raise exception 'NOTICE_DATE_OUT_OF_RANGE';
  end if;
  delete from public.student_ride_notices where student_id = p_student_id and notice_date = p_date;
end $$;


ALTER FUNCTION "public"."cancel_student_no_ride"("p_student_id" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_active_org_membership"("p_org_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select coalesce(
    (select is_active from public.organization_members
     where organization_id = p_org_id and user_id = auth.uid()),
    false
  );
$$;


ALTER FUNCTION "public"."check_active_org_membership"("p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_and_log_pdf_export"() RETURNS TABLE("allowed" boolean, "exports_this_month" integer, "monthly_limit" integer)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_caller uuid := auth.uid();
  v_base boolean;
  v_premium boolean;
  v_exempt boolean;
  v_month_start timestamptz;
  v_count int;
begin
  if v_caller is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  select base_entitled, premium_entitled, tier_enforcement_exempt
    into v_base, v_premium, v_exempt
    from public.profiles where id = v_caller;

  if v_premium is true or v_exempt is true then
    insert into public.pdf_export_log (user_id) values (v_caller);
    return query select true, null::int, null::int;
    return;
  end if;

  v_month_start := date_trunc('month', now());

  select count(*) into v_count
  from public.pdf_export_log
  where user_id = v_caller and exported_at >= v_month_start;

  if v_count >= 2 then
    return query select false, v_count, 2;
    return;
  end if;

  insert into public.pdf_export_log (user_id) values (v_caller);
  return query select true, v_count + 1, 2;
end;
$$;


ALTER FUNCTION "public"."check_and_log_pdf_export"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."check_rate_limit"("p_fn_name" "text", "p_client_key" "text", "p_max_requests" integer, "p_window_seconds" integer) RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_count int;
BEGIN
  -- Scoped advisory lock so concurrent calls from the SAME caller are
  -- serialized (can't both read "under limit" then both insert) --
  -- different callers never block each other.
  PERFORM pg_advisory_xact_lock(hashtext(p_fn_name || ':' || p_client_key));

  DELETE FROM public.edge_function_rate_limits
  WHERE fn_name = p_fn_name AND client_key = p_client_key
    AND created_at < now() - (p_window_seconds || ' seconds')::interval;

  SELECT count(*) INTO v_count
  FROM public.edge_function_rate_limits
  WHERE fn_name = p_fn_name AND client_key = p_client_key;

  IF v_count >= p_max_requests THEN
    RETURN false;
  END IF;

  INSERT INTO public.edge_function_rate_limits (fn_name, client_key) VALUES (p_fn_name, p_client_key);
  RETURN true;
END;
$$;


ALTER FUNCTION "public"."check_rate_limit"("p_fn_name" "text", "p_client_key" "text", "p_max_requests" integer, "p_window_seconds" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."claim_driver_slot"("p_claim_code" "text") RETURNS TABLE("success" boolean, "message" "text", "organization_name" "text", "display_id" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_caller uuid := auth.uid();
  v_recent_failures int;
  v_hash text;
  v_slot record;
  v_caller_account_type text;
  v_org_name text;
begin
  if v_caller is null then
    raise exception 'Authentication required';
  end if;

  select count(*) into v_recent_failures
  from public.driver_slot_claim_attempts a
  where a.user_id = v_caller
    and a.success = false
    and a.attempted_at > now() - interval '15 minutes';

  if v_recent_failures >= 5 then
    return query select false, 'Too many attempts. Try again later.', null::text, null::text;
    return;
  end if;

  select account_type into v_caller_account_type from public.profiles where id = v_caller;
  if v_caller_account_type = 'fleet_admin' then
    insert into public.driver_slot_claim_attempts (user_id, success, slot_id) values (v_caller, false, null);
    return query select false, 'You already manage your own fleet and cannot join another as a driver.', null::text, null::text;
    return;
  end if;

  v_hash := encode(digest(coalesce(p_claim_code, ''), 'sha256'), 'hex');

  select * into v_slot
  from public.fleet_driver_slots s
  where s.claim_code_hash = v_hash
    and s.claimed_by is null
  limit 1;

  if not found then
    insert into public.driver_slot_claim_attempts (user_id, success, slot_id) values (v_caller, false, null);
    return query select false, 'Invalid or already-claimed code.', null::text, null::text;
    return;
  end if;

  update public.fleet_driver_slots
  set claimed_by = v_caller, claimed_at = now()
  where id = v_slot.id;

  insert into public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
  values (v_slot.organization_id, v_caller, 'driver', true, now())
  on conflict do nothing;

  update public.profiles
  set account_type = 'fleet_driver', default_org_id = v_slot.organization_id
  where id = v_caller;

  insert into public.user_onboarding (user_id, account_type_chosen)
  values (v_caller, true)
  on conflict (user_id) do update set account_type_chosen = true;

  select name into v_org_name from public.organizations where id = v_slot.organization_id;

  insert into public.driver_slot_claim_attempts (user_id, success, slot_id) values (v_caller, true, v_slot.id);

  return query select true, 'ok', v_org_name, v_slot.display_id;
end;
$$;


ALTER FUNCTION "public"."claim_driver_slot"("p_claim_code" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."close_abandoned_trips"("p_idle" interval DEFAULT '12:00:00'::interval) RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  r record;
  v_closed integer := 0;
begin
  for r in
    select s.id,
           greatest(
             s.start_time,
             s.updated_at,
             (select max(b.recorded_at) from public.session_gps_breadcrumbs b where b.session_id = s.id),
             (select max(x.updated_at) from public.session_sections x where x.session_id = s.id)
           ) as last_activity
    from public.sessions s
    where not coalesce(s.is_closed, false)
  loop
    continue when r.last_activity is null or r.last_activity > now() - p_idle;

    update public.session_sections
       set section_status = 'closed',
           end_time = coalesce(end_time, r.last_activity)
     where session_id = r.id
       and section_status in ('active', 'paused');

    update public.sessions s
       set is_closed = true,
           session_status = 'closed',
           end_time = coalesce(s.end_time, r.last_activity),
           total_miles = greatest(
             coalesce(s.total_miles, 0),
             coalesce((select sum(x.total_miles) from public.session_sections x where x.session_id = s.id), 0)
           )
     where s.id = r.id;

    v_closed := v_closed + 1;
  end loop;

  perform set_config('cm.shift_block_rpc', 'on', true);
  update public.shift_blocks b
     set status = 'done', ended_at = coalesce(
       (select s.end_time from public.sessions s where s.id = b.session_id), now())
   where b.status = 'in_progress'
     and b.started_at < now() - p_idle
     and not exists (select 1 from public.sessions s where s.id = b.session_id and not s.is_closed);
  perform set_config('cm.shift_block_rpc', 'off', true);

  update public.driver_workdays set closed_at = now()
   where closed_at is null and opened_at < now() - interval '24 hours';

  return v_closed;
end;
$$;


ALTER FUNCTION "public"."close_abandoned_trips"("p_idle" interval) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."close_my_workday"("p_org" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_uid uuid := auth.uid();
begin
  if exists (select 1 from public.shift_blocks
             where organization_id = p_org and driver_id = v_uid and status = 'in_progress') then
    raise exception 'WORKDAY_BLOCK_IN_PROGRESS';
  end if;
  update public.driver_workdays
     set closed_at = now()
   where organization_id = p_org and driver_id = v_uid
     and work_date = public.fn_org_local_today(p_org) and closed_at is null;
end $$;


ALTER FUNCTION "public"."close_my_workday"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."complete_route_run"("p_run_id" "uuid", "p_child_check" boolean, "p_latitude" double precision, "p_longitude" double precision) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_run public.route_runs%rowtype := public.fn_my_open_run(p_run_id);
  v_route_type text := (select route_type from public.routes where id = v_run.route_id);
  v_on_board int;
  v_unresolved int;
begin
  if not coalesce(p_child_check, false) then
    raise exception 'CHILD_CHECK_REQUIRED';
  end if;
  select count(*) into v_on_board
    from public.ridership_events b
   where b.run_id = p_run_id and b.action = 'board'
     and not exists (select 1 from public.ridership_events x
                      where x.run_id = p_run_id and x.student_id = b.student_id and x.action = 'alight');
  if v_on_board > 0 then
    raise exception 'STUDENTS_STILL_ON_BOARD';
  end if;
  select count(*) into v_unresolved
    from public.student_stop_assignments a
   where a.route_id = v_run.route_id and a.action = 'board'
     and public.fn_rider_status(v_run.route_id, p_run_id, a.stop_id, a.student_id, 'board') in ('red', 'expected')
     and not public.fn_ride_notice_applies(a.student_id, v_run.run_date, v_route_type);
  if v_unresolved > 0 then
    raise exception 'UNRESOLVED_STUDENTS';
  end if;
  update public.route_stop_events set departed_at = coalesce(departed_at, now())
   where run_id = p_run_id;
  update public.route_runs
     set status = 'completed', completed_at = now(), child_check_at = now(),
         child_check_latitude = p_latitude, child_check_longitude = p_longitude
   where id = p_run_id;
end $$;


ALTER FUNCTION "public"."complete_route_run"("p_run_id" "uuid", "p_child_check" boolean, "p_latitude" double precision, "p_longitude" double precision) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."compute_idle_events"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") RETURNS TABLE("session_id" "uuid", "vehicle_id" "uuid", "user_id" "uuid", "started_at" timestamp with time zone, "minutes" double precision, "latitude" double precision, "longitude" double precision, "kind" "text")
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'Not authorized for this organization';
  end if;

  return query
  with o as (
    select
      b.session_id as sid, b.section_id as sec, b.vehicle_id as vid, b.user_id as uid,
      b.recorded_at, b.latitude as lat, b.longitude as lng,
      lag(b.recorded_at) over w as prev_at,
      lag(b.latitude) over w as prev_lat,
      lag(b.longitude) over w as prev_lng,
      lag(b.section_id) over w as prev_sec
    from public.session_gps_breadcrumbs b
    where b.organization_id = p_organization_id
      and b.recorded_at >= p_start_date::timestamptz
      and b.recorded_at < (p_end_date + 1)::timestamptz
    window w as (partition by b.session_id order by b.recorded_at)
  ),
  stops as (
    select
      o.sid, o.vid, o.uid, o.prev_at, o.prev_lat, o.prev_lng,
      (extract(epoch from o.recorded_at - o.prev_at) - 60) / 60.0 as mins
    from o
    where o.prev_at is not null
      and o.sec is not distinct from o.prev_sec
      and o.recorded_at - o.prev_at >= interval '4 minutes'
      and ST_DistanceSphere(ST_MakePoint(o.lng, o.lat), ST_MakePoint(o.prev_lng, o.prev_lat)) <= 200
  )
  select s.sid, s.vid, s.uid, s.prev_at, s.mins::double precision, s.prev_lat, s.prev_lng,
         case when s.mins >= 60 then 'long_stop' else 'idle' end
  from stops s
  where s.mins >= 3
  order by s.prev_at;
end;
$$;


ALTER FUNCTION "public"."compute_idle_events"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."compute_ifta_vehicle_state_miles"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") RETURNS TABLE("vehicle_id" "uuid", "state_code" "text", "miles" double precision)
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'Not authorized for this organization';
  end if;
  perform public.fn_require_org_feature(p_organization_id, 'ifta');
  return query
  with ordered as (
    select
      b.vehicle_id as vid, b.latitude, b.longitude,
      lag(b.latitude) over w as prev_lat,
      lag(b.longitude) over w as prev_lng
    from public.session_gps_breadcrumbs b
    where b.organization_id = p_organization_id
      and b.recorded_at::date between p_start_date and p_end_date
      and b.vehicle_id is not null
    window w as (partition by b.session_id order by b.recorded_at)
  ),
  segments as (
    select
      o.vid, o.latitude, o.longitude,
      6371000 * acos(
        least(1.0, greatest(-1.0,
          cos(radians(o.prev_lat)) * cos(radians(o.latitude)) *
            cos(radians(o.longitude) - radians(o.prev_lng)) +
          sin(radians(o.prev_lat)) * sin(radians(o.latitude))
        ))
      ) / 1609.34 as seg_miles
    from ordered o
    where o.prev_lat is not null
  )
  select
    s.vid,
    coalesce(sb.state_code, 'UNKNOWN')::text,
    sum(s.seg_miles)::double precision
  from segments s
  left join public.ifta_us_state_boundaries sb
    on ST_Contains(sb.geom, ST_SetSRID(ST_MakePoint(s.longitude, s.latitude), 4326))
  group by s.vid, sb.state_code;
end;
$$;


ALTER FUNCTION "public"."compute_ifta_vehicle_state_miles"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."compute_state_mileage"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid" DEFAULT NULL::"uuid") RETURNS TABLE("state_code" "text", "state_name" "text", "miles" double precision)
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'Not authorized for this organization';
  end if;

  return query
  with ordered as (
    select
      b.session_id,
      b.latitude,
      b.longitude,
      lag(b.latitude) over w as prev_lat,
      lag(b.longitude) over w as prev_lng
    from public.session_gps_breadcrumbs b
    where b.organization_id = p_organization_id
      and b.recorded_at::date between p_start_date and p_end_date
      and (p_vehicle_id is null or b.vehicle_id = p_vehicle_id)
    window w as (partition by b.session_id order by b.recorded_at)
  ),
  segments as (
    select
      o.latitude, o.longitude,
      6371000 * acos(
        least(1.0, greatest(-1.0,
          cos(radians(o.prev_lat)) * cos(radians(o.latitude)) *
            cos(radians(o.longitude) - radians(o.prev_lng)) +
          sin(radians(o.prev_lat)) * sin(radians(o.latitude))
        ))
      ) / 1609.34 as seg_miles
    from ordered o
    where o.prev_lat is not null
  ),
  attributed as (
    select
      sb.state_code as sc,
      sb.name as sn,
      s.seg_miles
    from segments s
    left join public.ifta_us_state_boundaries sb
      on ST_Contains(sb.geom, ST_SetSRID(ST_MakePoint(s.longitude, s.latitude), 4326))
  )
  select
    coalesce(a.sc, 'UNKNOWN')::text,
    coalesce(a.sn, 'Unattributed (outside US or no boundary match)')::text,
    sum(a.seg_miles)::double precision
  from attributed a
  group by a.sc, a.sn
  order by sum(a.seg_miles) desc;
end;
$$;


ALTER FUNCTION "public"."compute_state_mileage"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."correct_fuel_purchase_ifta"("p_purchase_id" "uuid", "p_state_code" "text", "p_fuel_type" "text", "p_tax_paid" boolean) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.fuel_purchases where id = p_purchase_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  perform public.fn_require_org_feature(v_org, 'ifta');
  if p_state_code is not null and not exists (
    select 1 from public.ifta_us_state_boundaries where state_code = p_state_code
  ) then
    raise exception 'Unknown state_code: %', p_state_code;
  end if;
  if p_fuel_type not in ('diesel', 'gasoline') then
    raise exception 'Unknown fuel type: %', p_fuel_type;
  end if;
  update public.fuel_purchases
  set state_code = p_state_code, fuel_type = p_fuel_type, tax_paid = coalesce(p_tax_paid, true)
  where id = p_purchase_id;
end;
$$;


ALTER FUNCTION "public"."correct_fuel_purchase_ifta"("p_purchase_id" "uuid", "p_state_code" "text", "p_fuel_type" "text", "p_tax_paid" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_driver_invite"("p_org_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_intended_role" "text" DEFAULT 'driver'::"text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $_$
declare
  v_email text := lower(trim(p_email));
  v_first_name text := trim(p_first_name);
  v_last_name text := trim(p_last_name);
  v_target_id uuid;
  v_target_account_type text;
  v_existing_membership uuid;
  v_token text;
  v_hash text;
  v_allowed boolean;
  v_slot_id uuid;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if p_intended_role not in ('driver', 'operator', 'admin', 'monitor') then
    raise exception 'Invalid role: %', p_intended_role;
  end if;

  if p_intended_role = 'monitor' and not exists (
    select 1 from public.organizations where id = p_org_id and industry_template = 'school_transport'
  ) then
    raise exception 'Bus monitors are only available for School transportation fleets';
  end if;

  if p_intended_role = 'admin' and not public.is_org_owner(p_org_id) then
    raise exception 'Only the organization owner can invite someone directly as an admin';
  end if;

  if p_intended_role = 'operator' and not public.is_org_admin_or_owner(p_org_id) then
    raise exception 'Only an org admin or owner can invite someone directly as an operator';
  end if;

  if not public.is_org_operator_or_above(p_org_id) then
    raise exception 'Only an org admin, owner, or operator can invite drivers';
  end if;

  if public.fn_org_effective_tier(p_org_id) = 'none' then
    raise exception 'FLEET_SUBSCRIPTION_REQUIRED';
  end if;

  select public.check_rate_limit('create_driver_invite', auth.uid()::text, 20, 3600) into v_allowed;
  if not v_allowed then
    raise exception 'Too many invites created recently. Try again later.';
  end if;

  if v_email = '' or v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    raise exception 'A valid email is required';
  end if;

  if v_first_name = '' or v_last_name = '' then
    raise exception 'First and last name are required';
  end if;

  select id, account_type into v_target_id, v_target_account_type
  from public.profiles
  where lower(email) = v_email
  limit 1;

  if v_target_id is not null then
    if v_target_account_type = 'fleet_admin' then
      raise exception 'This person already owns their own fleet and cannot be invited as a driver';
    end if;

    select id into v_existing_membership
    from public.organization_members
    where organization_id = p_org_id and user_id = v_target_id and is_active = true;

    if v_existing_membership is not null then
      raise exception 'This person is already a member of this organization';
    end if;
  end if;

  -- Reuse this person's slot when they were already invited and never
  -- accepted: a re-send must not mint another CM-D#### id.
  select s.id into v_slot_id
  from public.driver_invites i
  join public.fleet_driver_slots s on s.id = i.slot_id
  where i.organization_id = p_org_id
    and lower(i.email) = v_email
    and s.claimed_by is null
  order by i.created_at desc
  limit 1;

  update public.driver_invites
  set status = 'expired'
  where organization_id = p_org_id and lower(email) = v_email and status = 'pending';

  if v_slot_id is not null then
    update public.fleet_driver_slots
       set first_name = v_first_name, last_name = v_last_name
     where id = v_slot_id;
  else
    insert into public.fleet_driver_slots (organization_id, first_name, last_name, claim_code_hash, created_by)
    values (p_org_id, v_first_name, v_last_name, encode(gen_random_bytes(24), 'hex'), auth.uid())
    returning id into v_slot_id;
  end if;

  v_token := encode(gen_random_bytes(24), 'hex');
  v_hash := encode(digest(v_token, 'sha256'), 'hex');

  insert into public.driver_invites (organization_id, email, token_hash, created_by, first_name, last_name, slot_id, intended_role)
  values (p_org_id, v_email, v_hash, auth.uid(), v_first_name, v_last_name, v_slot_id, p_intended_role);

  return v_token;
end;
$_$;


ALTER FUNCTION "public"."create_driver_invite"("p_org_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_intended_role" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_driver_slot"("p_org_id" "uuid", "p_first_name" "text", "p_last_name" "text") RETURNS TABLE("slot_id" "uuid", "display_id" "text", "claim_code" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_caller uuid := auth.uid();
  v_code text;
  v_alphabet text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  v_slot_id uuid;
  v_display_id text;
  i int;
begin
  if v_caller is null then
    raise exception 'Authentication required';
  end if;

  if not is_org_operator_or_above(p_org_id) then
    raise exception 'Only an org admin, owner, or operator can add drivers';
  end if;

  if fn_org_effective_tier(p_org_id) = 'none' then
    raise exception 'FLEET_SUBSCRIPTION_REQUIRED';
  end if;

  if btrim(coalesce(p_first_name, '')) = '' or btrim(coalesce(p_last_name, '')) = '' then
    raise exception 'First and last name are required';
  end if;

  v_code := '';
  for i in 1..8 loop
    v_code := v_code || substr(v_alphabet, 1 + floor(random() * length(v_alphabet))::int, 1);
  end loop;

  insert into public.fleet_driver_slots (
    organization_id, first_name, last_name, claim_code_hash, created_by
  ) values (
    p_org_id, btrim(p_first_name), btrim(p_last_name),
    encode(digest(v_code, 'sha256'), 'hex'), v_caller
  )
  returning id, fleet_driver_slots.display_id into v_slot_id, v_display_id;

  return query select v_slot_id, v_display_id, v_code;
end;
$$;


ALTER FUNCTION "public"."create_driver_slot"("p_org_id" "uuid", "p_first_name" "text", "p_last_name" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_guardian_invite"("p_organization_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_student_ids" "uuid"[]) RETURNS TABLE("token" "text", "display_id" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $_$
declare
  v_email text := lower(btrim(coalesce(p_email, '')));
  v_guardian public.school_guardians;
  v_token text;
  v_allowed boolean;
begin
  if not public.is_org_admin_or_owner(p_organization_id) then
    raise exception 'Only an admin or the owner can authorize a parent';
  end if;
  if not exists (select 1 from public.organizations where id = p_organization_id and industry_template = 'school_transport') then
    raise exception 'Parents are only available for School transportation fleets';
  end if;
  select public.check_rate_limit('create_guardian_invite', auth.uid()::text, 30, 3600) into v_allowed;
  if not v_allowed then
    raise exception 'Too many invites created recently. Try again later.';
  end if;
  if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
    raise exception 'A valid email is required';
  end if;
  if length(btrim(coalesce(p_first_name, ''))) = 0 or length(btrim(coalesce(p_last_name, ''))) = 0 then
    raise exception 'First and last name are required';
  end if;
  if coalesce(array_length(p_student_ids, 1), 0) = 0 then
    raise exception 'Choose at least one student';
  end if;
  if exists (
    select 1 from unnest(p_student_ids) s(id)
     where not exists (select 1 from public.students st
                        where st.id = s.id and st.organization_id = p_organization_id and st.is_active)
  ) then
    raise exception 'A student does not belong to this fleet';
  end if;
  insert into public.school_guardians (organization_id, first_name, last_name, email, created_by)
  values (p_organization_id, btrim(p_first_name), btrim(p_last_name), v_email, auth.uid())
  on conflict (organization_id, email) do update
    set first_name = excluded.first_name, last_name = excluded.last_name,
        is_active = true, revoked_at = null
  returning * into v_guardian;
  insert into public.student_guardians (organization_id, student_id, guardian_id)
  select p_organization_id, s.id, v_guardian.id from unnest(p_student_ids) s(id)
  on conflict (student_id, guardian_id) do update set is_active = true, removed_at = null;
  update public.guardian_invites set status = 'expired'
   where guardian_id = v_guardian.id and status = 'pending';
  v_token := encode(gen_random_bytes(24), 'hex');
  insert into public.guardian_invites (organization_id, guardian_id, email, token_hash, created_by)
  values (p_organization_id, v_guardian.id, v_email, encode(digest(v_token, 'sha256'), 'hex'), auth.uid());
  return query select v_token, v_guardian.display_id;
end $_$;


ALTER FUNCTION "public"."create_guardian_invite"("p_organization_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_student_ids" "uuid"[]) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."create_organization"("p_name" "text", "p_industry_template" "text" DEFAULT NULL::"text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org_id uuid;
  v_owned_count int;
  v_entitled boolean;
  v_explicit boolean := public.fn_valid_fleet_profile(p_industry_template);
  v_template text := case when public.fn_valid_fleet_profile(p_industry_template) then p_industry_template else 'general' end;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;
  if p_name is null or length(trim(p_name)) = 0 then
    raise exception 'Organization name is required';
  end if;
  perform pg_advisory_xact_lock(hashtext('create_organization:' || auth.uid()::text));
  select count(*) into v_owned_count
  from public.organization_members
  where user_id = auth.uid() and member_role = 'owner';
  select multi_org_entitled into v_entitled
  from public.profiles where id = auth.uid();
  if v_owned_count >= 1 and not coalesce(v_entitled, false) then
    raise exception 'You already own a fleet organization. Creating more than one requires the multi-fleet add-on.';
  end if;
  insert into public.organizations (name, created_by, industry_template, fleet_type_confirmed_at, require_pretrip_inspection)
  values (trim(p_name), auth.uid(), v_template,
          case when coalesce(v_explicit, false) then now() end,
          public.fn_profile_requires_pretrip(v_template))
  returning id into v_org_id;
  insert into public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
  values (v_org_id, auth.uid(), 'owner', true, now());
  update public.profiles
  set account_type = 'fleet_admin', default_org_id = v_org_id
  where id = auth.uid();
  insert into public.user_onboarding (user_id, account_type_chosen)
  values (auth.uid(), true)
  on conflict (user_id) do update set account_type_chosen = true;
  if coalesce(v_explicit, false) then
    insert into public.fleet_type_changes (organization_id, from_type, to_type, changed_by, source)
    values (v_org_id, null, v_template, auth.uid(), 'onboarding');
  end if;
  return v_org_id;
end;
$$;


ALTER FUNCTION "public"."create_organization"("p_name" "text", "p_industry_template" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_organization"("p_org_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_caller uuid := auth.uid();
  v_is_owner boolean;
begin
  if v_caller is null then
    raise exception 'Not authenticated';
  end if;

  select exists(
    select 1 from public.organization_members
    where organization_id = p_org_id and user_id = v_caller
      and member_role = 'owner' and is_active = true
  ) into v_is_owner;

  if not v_is_owner then
    raise exception 'Only the organization owner can delete it';
  end if;

  update public.profiles
  set account_type = 'gig', default_org_id = null
  where default_org_id = p_org_id;

  delete from public.vehicle_geofence_alerts where organization_id = p_org_id;
  delete from public.vehicle_geofences where organization_id = p_org_id;
  delete from public.vehicle_inspections where organization_id = p_org_id;
  delete from public.vehicle_maintenance_records where organization_id = p_org_id;
  delete from public.vehicle_odometer_checkpoints where organization_id = p_org_id;
  delete from public.session_gps_breadcrumbs where organization_id = p_org_id;
  delete from public.trip_incidents where organization_id = p_org_id;

  delete from public.organizations where id = p_org_id;
end;
$$;


ALTER FUNCTION "public"."delete_organization"("p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."delete_trip_section"("p_section_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_sec  public.session_sections%rowtype;
  v_sess public.sessions%rowtype;
  v_left integer;
begin
  select * into v_sec from public.session_sections where id = p_section_id;
  if not found then
    raise exception 'Section not found' using errcode = 'P0002';
  end if;

  select * into v_sess from public.sessions where id = v_sec.session_id for update;

  if not (
    (v_sess.organization_id is null and v_sess.user_id = auth.uid())
    or (v_sess.organization_id is not null and public.is_org_admin_or_owner(v_sess.organization_id))
  ) then
    raise exception 'Not allowed to delete this trip' using errcode = '42501';
  end if;

  if not coalesce(v_sess.is_closed, false) then
    raise exception 'The trip is still open' using errcode = '55000';
  end if;

  select count(*) into v_left
    from public.session_sections
   where session_id = v_sess.id and id <> p_section_id;

  if v_left = 0 then
    delete from public.sessions where id = v_sess.id;
    return;
  end if;

  delete from public.session_sections where id = p_section_id;

  perform set_config('cm.section_delete', 'on', true);
  update public.sessions s
     set total_miles = coalesce((select sum(total_miles) from public.session_sections where session_id = s.id), 0),
         total_duration_seconds = coalesce((select sum(total_duration_seconds) from public.session_sections where session_id = s.id), 0),
         start_time = coalesce((select min(start_time) from public.session_sections where session_id = s.id), s.start_time),
         end_time = coalesce((select max(end_time) from public.session_sections where session_id = s.id), s.end_time)
   where s.id = v_sess.id;
  perform set_config('cm.section_delete', 'off', true);
end;
$$;


ALTER FUNCTION "public"."delete_trip_section"("p_section_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."driver_safety_scores"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_bucket" "text" DEFAULT NULL::"text") RETURNS TABLE("user_id" "uuid", "bucket_start" "date", "miles" numeric, "trips" integer, "harsh_braking" integer, "hard_acceleration" integer, "speeding" integer, "points" integer, "score" numeric)
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_admin boolean;
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'Not authorized for this organization';
  end if;
  perform public.fn_require_org_feature(p_organization_id, 'safety_scores');
  if p_bucket is not null and p_bucket <> 'week' then
    raise exception 'Unknown bucket: %', p_bucket;
  end if;
  v_admin := public.is_org_admin_or_owner(p_organization_id);

  return query
  with trips as (
    select s.user_id as uid,
           case when p_bucket = 'week' then date_trunc('week', s.date_key)::date else p_start_date end as b,
           sum(coalesce(s.total_miles, 0))::numeric as mi,
           count(*)::int as n
    from public.sessions s
    where s.organization_id = p_organization_id
      and s.date_key between p_start_date and p_end_date
      and (v_admin or s.user_id = auth.uid())
    group by 1, 2
  ),
  events as (
    select e.user_id as uid,
           case when p_bucket = 'week' then date_trunc('week', e.recorded_at)::date else p_start_date end as b,
           count(*) filter (where e.event_type = 'harsh_braking')::int as hb,
           count(*) filter (where e.event_type = 'hard_acceleration')::int as ha,
           count(*) filter (where e.event_type = 'speeding')::int as sp
    from public.driver_safety_events e
    where e.organization_id = p_organization_id
      and e.recorded_at >= p_start_date::timestamptz
      and e.recorded_at < (p_end_date + 1)::timestamptz
      and (v_admin or e.user_id = auth.uid())
    group by 1, 2
  )
  select
    coalesce(t.uid, ev.uid),
    coalesce(t.b, ev.b),
    round(coalesce(t.mi, 0), 1),
    coalesce(t.n, 0),
    coalesce(ev.hb, 0),
    coalesce(ev.ha, 0),
    coalesce(ev.sp, 0),
    (3 * coalesce(ev.hb, 0) + 2 * coalesce(ev.ha, 0) + 5 * coalesce(ev.sp, 0)),
    public.fn_safety_score(3 * coalesce(ev.hb, 0) + 2 * coalesce(ev.ha, 0) + 5 * coalesce(ev.sp, 0), t.mi)
  from trips t
  full join events ev on ev.uid = t.uid and ev.b = t.b
  order by 1, 2;
end;
$$;


ALTER FUNCTION "public"."driver_safety_scores"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_bucket" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_clear_custom_domain"("p_org" "uuid") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_old text;
begin
  if not public.is_org_admin_or_owner(p_org) or not public.fn_org_has_feature(p_org, 'student_portal') then
    raise exception 'Not authorized';
  end if;
  select custom_domain into v_old from public.ds_public_pages where organization_id = p_org;
  update public.ds_public_pages
     set custom_domain = null, domain_token = null, domain_status = 'none', domain_message = null,
         domain_checked_at = null, domain_verified_at = null, updated_at = now()
   where organization_id = p_org;
  return v_old;
end $$;


ALTER FUNCTION "public"."ds_clear_custom_domain"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_add_child"("p_session" "text", "p" "jsonb") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  c public.ds_clients := public.fn_ds_client_session(p_session);
  v_min smallint;
  v_major smallint;
  v_birth date;
  v_age int;
  v_program uuid;
  v_branch uuid;
  v_lang text := case when p->>'preferred_language' in ('en', 'es') then p->>'preferred_language' end;
begin
  if c.id is null then raise exception 'SESSION_ENDED'; end if;
  select pg.min_age into v_min from public.ds_public_pages pg where pg.organization_id = c.organization_id and pg.enabled;
  if v_min is null then raise exception 'NOT_AVAILABLE' using errcode = 'P0001'; end if;
  select coalesce((select age_of_majority from public.ds_settings where organization_id = c.organization_id), 18) into v_major;

  if nullif(btrim(p->>'first_name'), '') is null or nullif(btrim(p->>'last_name'), '') is null then
    raise exception 'NAME_REQUIRED' using errcode = 'P0001';
  end if;
  begin
    v_birth := (p->>'birth_date')::date;
  exception when others then
    raise exception 'BIRTH_DATE' using errcode = 'P0001';
  end;
  if v_birth is null or v_birth > current_date then raise exception 'BIRTH_DATE' using errcode = 'P0001'; end if;
  v_age := extract(year from age(current_date, v_birth))::int;
  if v_age < greatest(v_min, 13) then raise exception 'TOO_YOUNG' using errcode = 'P0001'; end if;
  if v_age >= v_major then raise exception 'NOT_A_MINOR' using errcode = 'P0001'; end if;
  if coalesce((p->>'consent')::boolean, false) is not true or length(btrim(coalesce(p->>'consent_name', ''))) < 2 then
    raise exception 'CONSENT' using errcode = 'P0001';
  end if;

  begin
    v_program := nullif(p->>'program_id', '')::uuid;
    v_branch := nullif(p->>'branch_id', '')::uuid;
  exception when others then
    raise exception 'INVALID' using errcode = 'P0001';
  end;
  if v_program is not null and not exists (select 1 from public.ds_programs where id = v_program and organization_id = c.organization_id and is_active) then
    v_program := null;
  end if;
  if v_branch is not null and not exists (select 1 from public.branches where id = v_branch and organization_id = c.organization_id and not is_archived) then
    v_branch := null;
  end if;

  if (select count(*) from public.ds_enrollment_requests where client_id = c.id and status = 'pending') >= 5 then
    raise exception 'BUSY' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.ds_enrollment_requests r
              where r.client_id = c.id and r.status = 'pending'
                and lower(r.first_name) = lower(btrim(p->>'first_name')) and r.birth_date = v_birth) then
    return 'ok';
  end if;

  insert into public.ds_enrollment_requests (
    organization_id, client_id, first_name, last_name, birth_date,
    guardian_name, guardian_email, program_id, branch_id, message,
    is_minor, consent_by, consent_name, sms_opt_in, preferred_language)
  values (
    c.organization_id, c.id, left(btrim(p->>'first_name'), 60), left(btrim(p->>'last_name'), 60), v_birth,
    c.first_name || ' ' || c.last_name, c.email, v_program, v_branch, left(nullif(btrim(p->>'message'), ''), 500),
    true, 'guardian', left(btrim(p->>'consent_name'), 120), false, v_lang);
  return 'ok';
end $$;


ALTER FUNCTION "public"."ds_client_add_child"("p_session" "text", "p" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_book"("p_session" "text", "p_student" "uuid", "p_date" "date", "p_start" time without time zone) RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  return public.fn_ds_portal_book_for(public.fn_ds_client_student(p_session, p_student), p_date, p_start);
end $$;


ALTER FUNCTION "public"."ds_client_book"("p_session" "text", "p_student" "uuid", "p_date" "date", "p_start" time without time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_cancel"("p_session" "text", "p_student" "uuid", "p_block" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  return public.fn_ds_portal_cancel_for(public.fn_ds_client_student(p_session, p_student), p_block);
end $$;


ALTER FUNCTION "public"."ds_client_cancel"("p_session" "text", "p_student" "uuid", "p_block" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_certificate"("p_session" "text", "p_student" "uuid", "p_number" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  return public.fn_ds_portal_certificate_for(public.fn_ds_client_student(p_session, p_student), p_number);
end $$;


ALTER FUNCTION "public"."ds_client_certificate"("p_session" "text", "p_student" "uuid", "p_number" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_home"("p_session" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  c public.ds_clients := public.fn_ds_client_session(p_session);
begin
  if c.id is null then return null; end if;
  return jsonb_build_object(
    'school', (select coalesce(report_display_name, name) from public.organizations where id = c.organization_id),
    'client', jsonb_build_object('first_name', c.first_name, 'last_name', c.last_name, 'email', c.email),
    'students', coalesce((
      select jsonb_agg(jsonb_build_object('id', st.id, 'first_name', st.first_name, 'last_name', st.last_name,
                                          'status', st.status, 'relation', cs.relation)
                       order by st.first_name)
        from public.ds_client_students cs
        join public.ds_students st on st.id = cs.student_id
       where cs.client_id = c.id and cs.is_active and public.fn_ds_link_counts(cs.relation, cs.student_id)), '[]'::jsonb),
    'pending', coalesce((
      select jsonb_agg(jsonb_build_object('first_name', r.first_name, 'requested_at', r.created_at) order by r.created_at)
        from public.ds_enrollment_requests r
       where r.client_id = c.id and r.status = 'pending'), '[]'::jsonb),
    'enroll_slug', (select pg.slug from public.ds_public_pages pg where pg.organization_id = c.organization_id and pg.enabled)
  );
end $$;


ALTER FUNCTION "public"."ds_client_home"("p_session" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_link"("p_student" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_relation" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
  v_client uuid;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.is_org_operator_or_above(v_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(v_org, 'student_portal');
  if p_relation not in ('self', 'guardian') then raise exception 'INVALID' using errcode = 'P0001'; end if;
  if length(btrim(coalesce(p_first_name, ''))) = 0 or length(btrim(coalesce(p_last_name, ''))) = 0 then
    raise exception 'NAME_REQUIRED' using errcode = 'P0001';
  end if;
  if p_relation = 'guardian' and not public.fn_ds_is_minor(p_student) then
    raise exception 'NOT_A_MINOR' using errcode = 'P0001';
  end if;
  if p_relation = 'self' and public.fn_ds_is_minor(p_student) then
    raise exception 'STUDENT_IS_MINOR' using errcode = 'P0001';
  end if;
  v_client := public.fn_ds_upsert_client(v_org, p_email, p_first_name, p_last_name, true);
  perform public.fn_ds_link_client(v_client, p_student, p_relation);
  return v_client;
end $$;


ALTER FUNCTION "public"."ds_client_link"("p_student" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_relation" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_link_info"("p_token" "text") RETURNS TABLE("organization_id" "uuid", "school" "text", "email" "text", "first_name" "text")
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
  select c.organization_id, coalesce(o.report_display_name, o.name), c.email, c.first_name
    from public.ds_client_tokens t
    join public.ds_clients c on c.id = t.client_id
    join public.organizations o on o.id = c.organization_id
   where t.token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
     and t.kind = 'link' and t.used_at is null and t.revoked_at is null and t.expires_at > now()
     and c.is_active;
$$;


ALTER FUNCTION "public"."ds_client_link_info"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_open_link"("p_token" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  t public.ds_client_tokens;
  v_session text := encode(gen_random_bytes(32), 'hex');
begin
  select * into t from public.ds_client_tokens
   where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex') and kind = 'link'
   for update;
  if t.id is null or t.used_at is not null or t.revoked_at is not null or t.expires_at <= now()
     or not exists (select 1 from public.ds_clients where id = t.client_id and is_active)
     or not public.fn_org_feature_internal(t.organization_id, 'student_portal') then
    return null;
  end if;
  update public.ds_client_tokens set used_at = now() where id = t.id;
  insert into public.ds_client_tokens (organization_id, client_id, kind, token_hash, expires_at)
  values (t.organization_id, t.client_id, 'session', encode(digest(v_session, 'sha256'), 'hex'), now() + interval '30 days');
  update public.ds_clients set last_seen_at = now() where id = t.client_id;
  return v_session;
end $$;


ALTER FUNCTION "public"."ds_client_open_link"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_request_links"("p_email" "text") RETURNS TABLE("school" "text", "first_name" "text", "token" "text")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  c record;
  v_token text;
begin
  for c in
    select cl.id, cl.organization_id, cl.first_name, coalesce(o.report_display_name, o.name) as school
      from public.ds_clients cl
      join public.organizations o on o.id = cl.organization_id
     where cl.email = lower(btrim(coalesce(p_email, ''))) and cl.is_active
       and public.fn_org_feature_internal(cl.organization_id, 'student_portal')
  loop
    v_token := encode(gen_random_bytes(24), 'hex');
    insert into public.ds_client_tokens (organization_id, client_id, kind, token_hash, expires_at)
    values (c.organization_id, c.id, 'link', encode(digest(v_token, 'sha256'), 'hex'), now() + interval '30 minutes');
    school := c.school;
    first_name := c.first_name;
    token := v_token;
    return next;
  end loop;
end $$;


ALTER FUNCTION "public"."ds_client_request_links"("p_email" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_revoke"("p_client" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.ds_clients where id = p_client;
  if v_org is null or not public.is_org_operator_or_above(v_org) then raise exception 'Not authorized'; end if;
  update public.ds_clients set is_active = false, revoked_at = now() where id = p_client;
  update public.ds_client_tokens set revoked_at = now() where client_id = p_client and revoked_at is null;
  update public.ds_client_students set is_active = false, ended_at = now(), ended_reason = 'revoked'
   where client_id = p_client and is_active;
end $$;


ALTER FUNCTION "public"."ds_client_revoke"("p_client" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_set_sms"("p_session" "text", "p_student" "uuid", "p_on" boolean, "p_phone" "text" DEFAULT NULL::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  perform public.fn_ds_portal_set_sms_for(public.fn_ds_client_student(p_session, p_student), p_on, p_phone);
end $$;


ALTER FUNCTION "public"."ds_client_set_sms"("p_session" "text", "p_student" "uuid", "p_on" boolean, "p_phone" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_sign_out"("p_session" "text") RETURNS "void"
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
  update public.ds_client_tokens set revoked_at = now()
   where token_hash = encode(digest(coalesce(p_session, ''), 'sha256'), 'hex') and kind = 'session' and revoked_at is null;
$$;


ALTER FUNCTION "public"."ds_client_sign_out"("p_session" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_slots"("p_session" "text", "p_student" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  return public.fn_ds_portal_slots_for(public.fn_ds_client_student(p_session, p_student));
end $$;


ALTER FUNCTION "public"."ds_client_slots"("p_session" "text", "p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_student_view"("p_session" "text", "p_student" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  return public.fn_ds_portal_payload(public.fn_ds_client_student(p_session, p_student));
end $$;


ALTER FUNCTION "public"."ds_client_student_view"("p_session" "text", "p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_unlink"("p_client" "uuid", "p_student" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.ds_clients where id = p_client;
  if v_org is null or not public.is_org_operator_or_above(v_org) then raise exception 'Not authorized'; end if;
  update public.ds_client_students set is_active = false, ended_at = now(), ended_reason = 'revoked'
   where client_id = p_client and student_id = p_student and is_active;
end $$;


ALTER FUNCTION "public"."ds_client_unlink"("p_client" "uuid", "p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_client_welcome_link"("p_client" "uuid") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  c public.ds_clients;
  v_token text := encode(gen_random_bytes(24), 'hex');
begin
  select * into c from public.ds_clients where id = p_client;
  if c.id is null or not public.is_org_operator_or_above(c.organization_id) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(c.organization_id, 'student_portal');
  if not c.is_active then raise exception 'CLIENT_REVOKED' using errcode = 'P0001'; end if;
  insert into public.ds_client_tokens (organization_id, client_id, kind, token_hash, expires_at)
  values (c.organization_id, c.id, 'link', encode(digest(v_token, 'sha256'), 'hex'), now() + interval '7 days');
  return v_token;
end $$;


ALTER FUNCTION "public"."ds_client_welcome_link"("p_client" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_create_portal_link"("p_student" "uuid") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_org uuid;
  v_token text;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.is_org_operator_or_above(v_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(v_org, 'student_portal');
  update public.ds_portal_links set revoked_at = now() where student_id = p_student and revoked_at is null;
  v_token := encode(gen_random_bytes(24), 'hex');
  insert into public.ds_portal_links (organization_id, student_id, token_hash, created_by)
  values (v_org, p_student, encode(digest(v_token, 'sha256'), 'hex'), auth.uid());
  return v_token;
end $$;


ALTER FUNCTION "public"."ds_create_portal_link"("p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_due_class_reminders"() RETURNS TABLE("shift_block_id" "uuid", "organization_id" "uuid", "school" "text", "timezone" "text", "block_date" "date", "start_time" time without time zone, "student_first_name" "text", "recipient" "text", "instructor" "text", "language" "text")
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select b.id, b.organization_id, coalesce(o.report_display_name, o.name), coalesce(o.timezone, 'America/New_York'),
         b.block_date, b.start_time, st.first_name, lower(btrim(r.email)),
         nullif(concat_ws(' ', p.first_name, left(p.last_name, 1)), ''), st.preferred_language
    from public.shift_blocks b
    join public.organizations o on o.id = b.organization_id
    join public.ds_students st on st.id = b.student_id and st.status in ('registered', 'active')
    left join public.ds_programs pr on pr.id = st.program_id
    left join public.ds_settings cfg on cfg.organization_id = b.organization_id
    left join public.profiles p on p.id = b.driver_id
    cross join lateral (values (st.email), (case when coalesce(pr.notify_guardian, true) then st.guardian_email end)) as r(email)
   where b.status = 'scheduled'
     and r.email is not null and btrim(r.email) <> ''
     and (b.block_date + b.start_time) at time zone coalesce(o.timezone, 'America/New_York')
         between now() and now() + make_interval(hours => coalesce(cfg.reminder_hours, 24))
     and public.fn_org_feature_internal(b.organization_id, 'class_reminders')
     and not exists (select 1 from public.ds_reminders_sent x
                      where x.shift_block_id = b.id and x.recipient = lower(btrim(r.email)));
$$;


ALTER FUNCTION "public"."ds_due_class_reminders"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_due_slot_notices"() RETURNS TABLE("notice_id" "uuid", "school" "text", "block_date" "date", "start_time" time without time zone, "instructor" "text", "recipient" "text", "first_name" "text", "language" "text")
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select n.id, coalesce(o.report_display_name, o.name), n.block_date, n.start_time,
         nullif(concat_ws(' ', p.first_name, left(p.last_name, 1)), ''), lower(btrim(r.email)), st.first_name,
         st.preferred_language
    from public.ds_slot_notices n
    join public.organizations o on o.id = n.organization_id
    join public.ds_settings cfg on cfg.organization_id = n.organization_id and cfg.booking_enabled
    left join public.ds_programs pr on pr.id = n.program_id
    left join public.profiles p on p.id = n.instructor_id
    join public.ds_students st on st.organization_id = n.organization_id and st.program_id = n.program_id
                              and st.status in ('registered', 'active') and st.id is distinct from n.freed_by_student
                              and exists (select 1 from public.ds_portal_links pl
                                           where pl.student_id = st.id and pl.revoked_at is null and pl.expires_at > now())
    cross join lateral (values (st.email), (case when coalesce(pr.notify_guardian, true) then st.guardian_email end)) as r(email)
   where n.sent_at is null
     and r.email is not null and btrim(r.email) <> ''
     and public.fn_org_feature_internal(n.organization_id, 'student_booking')
     and (n.block_date + n.start_time) at time zone coalesce(o.timezone, 'America/New_York') > now()
     and not exists (select 1 from public.shift_blocks b
                      where b.organization_id = n.organization_id and b.block_date = n.block_date
                        and b.status <> 'cancelled' and b.driver_id = n.instructor_id
                        and b.start_time < n.end_time and b.end_time > n.start_time);
$$;


ALTER FUNCTION "public"."ds_due_slot_notices"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_enrollment_approve"("p_id" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  r public.ds_enrollment_requests;
  v_student uuid;
  v_client uuid;
  v_first text;
  v_last text;
begin
  select * into r from public.ds_enrollment_requests where id = p_id for update;
  if r.id is null then raise exception 'That request is gone' using errcode = 'P0001'; end if;
  if not public.is_org_operator_or_above(r.organization_id) or not public.fn_org_has_feature(r.organization_id, 'student_portal') then
    raise exception 'Not authorized';
  end if;
  if r.status = 'approved' and r.student_id is not null then return r.student_id; end if;
  insert into public.ds_students (
    organization_id, first_name, last_name, birth_date, email, phone,
    guardian_name, guardian_email, guardian_phone, status, program_id, branch_id, notes,
    sms_consent_at, sms_consent_phone, sms_consent_source, created_by, preferred_language)
  values (
    r.organization_id, r.first_name, r.last_name, r.birth_date, r.email, r.phone,
    r.guardian_name, r.guardian_email, r.guardian_phone, 'registered', r.program_id, r.branch_id,
    left(concat_ws(E'\n',
      'Online request ' || to_char(r.created_at, 'YYYY-MM-DD') || ', consent by ' || r.consent_by || ' (' || r.consent_name || ').',
      r.message), 1000),
    case when r.sms_opt_in then r.consent_at end,
    case when r.sms_opt_in then r.sms_phone end,
    case when r.sms_opt_in then 'online_request' end,
    auth.uid(), r.preferred_language)
  returning id into v_student;
  update public.ds_enrollment_requests
     set status = 'approved', student_id = v_student, decided_at = now(), decided_by = auth.uid()
   where id = r.id;

  if public.fn_ds_is_minor(v_student) then
    if r.client_id is not null then
      v_client := (select id from public.ds_clients where id = r.client_id and is_active);
    elsif r.guardian_email is not null then
      v_first := split_part(btrim(coalesce(r.guardian_name, '')), ' ', 1);
      v_last := nullif(btrim(substr(btrim(coalesce(r.guardian_name, '')), length(v_first) + 1)), '');
      v_client := public.fn_ds_upsert_client(r.organization_id, r.guardian_email,
                                             coalesce(nullif(v_first, ''), r.last_name), coalesce(v_last, r.last_name), false);
    end if;
    if v_client is not null then perform public.fn_ds_link_client(v_client, v_student, 'guardian'); end if;
  elsif r.email is not null then
    v_client := public.fn_ds_upsert_client(r.organization_id, r.email, r.first_name, r.last_name, false);
    if v_client is not null then perform public.fn_ds_link_client(v_client, v_student, 'self'); end if;
  end if;
  return v_student;
end $$;


ALTER FUNCTION "public"."ds_enrollment_approve"("p_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_enrollment_decline"("p_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  r public.ds_enrollment_requests;
begin
  select * into r from public.ds_enrollment_requests where id = p_id for update;
  if r.id is null then return; end if;
  if not public.is_org_operator_or_above(r.organization_id) or not public.fn_org_has_feature(r.organization_id, 'student_portal') then
    raise exception 'Not authorized';
  end if;
  if r.status <> 'pending' then raise exception 'Only a waiting request can be declined' using errcode = 'P0001'; end if;
  update public.ds_enrollment_requests set status = 'declined', decided_at = now(), decided_by = auth.uid() where id = r.id;
end $$;


ALTER FUNCTION "public"."ds_enrollment_decline"("p_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_enrollment_undo"("p_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  r public.ds_enrollment_requests;
begin
  select * into r from public.ds_enrollment_requests where id = p_id for update;
  if r.id is null then raise exception 'That request is gone' using errcode = 'P0001'; end if;
  if not public.is_org_operator_or_above(r.organization_id) or not public.fn_org_has_feature(r.organization_id, 'student_portal') then
    raise exception 'Not authorized';
  end if;
  if r.status = 'approved' and r.student_id is not null then
    if exists (select 1 from public.shift_blocks where student_id = r.student_id)
       or exists (select 1 from public.ds_student_packages where student_id = r.student_id)
       or exists (select 1 from public.ds_evaluations where student_id = r.student_id)
       or exists (select 1 from public.ds_certificates where student_id = r.student_id)
       or exists (select 1 from public.ds_portal_links where student_id = r.student_id) then
      raise exception 'This student already has classes, packages or a portal link. Mark them Dropped instead.' using errcode = 'P0001';
    end if;
    delete from public.ds_students where id = r.student_id;
  end if;
  update public.ds_enrollment_requests
     set status = 'pending', student_id = null, decided_at = null, decided_by = null
   where id = r.id;
end $$;


ALTER FUNCTION "public"."ds_enrollment_undo"("p_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_ensure_default_programs"("p_org" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_member(p_org) and auth.uid() is not null then raise exception 'Not authorized'; end if;
  if exists (select 1 from public.ds_programs where organization_id = p_org) then return; end if;
  insert into public.ds_programs (organization_id, name, required_minutes, required_night_minutes, class_minutes, notify_guardian, sort)
  values (p_org, 'Teen', 360, 0, 60, true, 1),
         (p_org, 'Adult', 0, 0, 60, false, 2);
end $$;


ALTER FUNCTION "public"."ds_ensure_default_programs"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_ensure_default_skills"("p_org" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_member(p_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(p_org, 'student_evaluations');
  if exists (select 1 from public.ds_skills where organization_id = p_org) then return; end if;
  insert into public.ds_skills (organization_id, category, name, sort)
  select p_org, c, n, row_number() over () from (values
    ('Vehicle control', 'Steering'), ('Vehicle control', 'Smooth braking'), ('Vehicle control', 'Smooth acceleration'),
    ('Vehicle control', 'Mirrors and blind spots'),
    ('Intersections', 'Stop signs and signals'), ('Intersections', 'Right-of-way'), ('Intersections', 'Turns'),
    ('Lanes', 'Lane position'), ('Lanes', 'Lane changes'), ('Lanes', 'Merging'),
    ('Speed and space', 'Speed control'), ('Speed and space', 'Following distance'), ('Speed and space', 'Hazard awareness'),
    ('Parking', 'Parallel parking'), ('Parking', 'Angle and perpendicular parking'), ('Parking', 'Backing up'),
    ('Highway', 'Entering and exiting'), ('Highway', 'Highway lane changes'),
    ('Rules', 'Signaling'), ('Rules', 'Traffic signs'), ('Rules', 'Pedestrians and school zones')
  ) as t(c, n);
end $$;


ALTER FUNCTION "public"."ds_ensure_default_skills"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_issue_certificate"("p_student" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_org uuid;
  v jsonb;
  v_id uuid := gen_random_uuid();
  v_number text;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(v_org, 'student_certificates');
  v := public.fn_ds_student_snapshot(p_student);
  if (v->>'minutes')::numeric < (v->>'required_minutes')::numeric
     or (v->>'night_minutes')::numeric < (v->>'required_night_minutes')::numeric
     or jsonb_array_length(v->'classes') = 0 then
    raise exception 'REQUIRED_HOURS_NOT_MET';
  end if;
  v_number := 'CM-' || to_char(now() at time zone (v->>'timezone'), 'YYYYMMDD') || '-' || upper(substr(replace(v_id::text, '-', ''), 1, 6));
  v := (v - 'upcoming') || jsonb_build_object('number', v_number, 'issued_at', now());
  insert into public.ds_certificates (id, number, organization_id, student_id, data, sha256, issued_by)
  values (v_id, v_number, v_org, p_student, v, encode(digest(v::text, 'sha256'), 'hex'), auth.uid());
  return v_id;
end $$;


ALTER FUNCTION "public"."ds_issue_certificate"("p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_mark_custom_domain"("p_org" "uuid", "p_status" "text", "p_message" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_admin_or_owner(p_org) or not public.fn_org_has_feature(p_org, 'student_portal') then
    raise exception 'Not authorized';
  end if;
  if p_status not in ('pending', 'verified', 'error') then raise exception 'Bad status'; end if;
  update public.ds_public_pages
     set domain_status = p_status,
         domain_message = left(p_message, 300),
         domain_checked_at = now(),
         domain_verified_at = case when p_status = 'verified' then coalesce(domain_verified_at, now()) else null end
   where organization_id = p_org and custom_domain is not null;
end $$;


ALTER FUNCTION "public"."ds_mark_custom_domain"("p_org" "uuid", "p_status" "text", "p_message" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_office_add_block"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_student" "uuid", "p_note" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_conflict text;
  v_id uuid;
begin
  if not public.is_org_operator_or_above(p_org) then raise exception 'FORBIDDEN'; end if;
  if not public.fn_org_has_classes(p_org) then raise exception 'FORBIDDEN'; end if;
  if p_end <= p_start then raise exception 'BAD_TIME'; end if;
  if not exists (select 1 from public.organization_members m
                  where m.organization_id = p_org and m.user_id = p_driver and m.is_active) then
    raise exception 'BAD_INSTRUCTOR';
  end if;
  if p_vehicle is not null and not exists (select 1 from public.vehicles v where v.id = p_vehicle and v.organization_id = p_org) then
    raise exception 'BAD_CAR';
  end if;
  perform pg_advisory_xact_lock(hashtext(p_org::text || p_date::text));
  v_conflict := public.fn_ds_conflict(p_org, p_driver, p_vehicle, p_date, p_start, p_end, null);
  if v_conflict is not null then raise exception '%', v_conflict; end if;
  insert into public.shift_blocks (organization_id, driver_id, vehicle_id, block_date, start_time, end_time, note,
                                   source, status, student_id, booked_via, created_by)
  values (p_org, p_driver, p_vehicle, p_date, p_start, p_end, p_note, 'one_off', 'scheduled',
          case when public.fn_org_feature_internal(p_org, 'students') then p_student end, 'office', auth.uid())
  returning id into v_id;
  return v_id;
end $$;


ALTER FUNCTION "public"."ds_office_add_block"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_student" "uuid", "p_note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_office_move_block"("p_block" "uuid", "p_date" "date", "p_start" time without time zone, "p_driver" "uuid", "p_vehicle" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  b public.shift_blocks;
  v_end time;
  v_conflict text;
  v_id uuid;
begin
  select * into b from public.shift_blocks where id = p_block;
  if b.id is null then raise exception 'NOT_FOUND'; end if;
  if not public.is_org_operator_or_above(b.organization_id) then raise exception 'FORBIDDEN'; end if;
  if b.status <> 'scheduled' then raise exception 'NOT_MOVABLE'; end if;
  if not exists (select 1 from public.organization_members m
                  where m.organization_id = b.organization_id and m.user_id = p_driver and m.is_active) then
    raise exception 'BAD_INSTRUCTOR';
  end if;
  if p_vehicle is not null and not exists (select 1 from public.vehicles v where v.id = p_vehicle and v.organization_id = b.organization_id) then
    raise exception 'BAD_CAR';
  end if;
  v_end := p_start + (b.end_time - b.start_time);
  if v_end <= p_start then raise exception 'BAD_TIME'; end if;
  perform pg_advisory_xact_lock(hashtext(b.organization_id::text || p_date::text));
  v_conflict := public.fn_ds_conflict(b.organization_id, p_driver, p_vehicle, p_date, p_start, v_end, b.id);
  if v_conflict is not null then raise exception '%', v_conflict; end if;
  if b.source = 'template' then
    insert into public.shift_blocks (organization_id, driver_id, vehicle_id, block_date, start_time, end_time, note,
                                     source, status, student_id, booked_via, created_by)
    values (b.organization_id, p_driver, p_vehicle, p_date, p_start, v_end, b.note, 'one_off', 'scheduled',
            b.student_id, 'office', auth.uid())
    returning id into v_id;
    update public.shift_blocks set status = 'cancelled' where id = b.id;
    return v_id;
  end if;
  update public.shift_blocks
     set block_date = p_date, start_time = p_start, end_time = v_end, driver_id = p_driver, vehicle_id = p_vehicle
   where id = b.id;
  return b.id;
end $$;


ALTER FUNCTION "public"."ds_office_move_block"("p_block" "uuid", "p_date" "date", "p_start" time without time zone, "p_driver" "uuid", "p_vehicle" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_portal_book"("p_token" "text", "p_date" "date", "p_start" time without time zone) RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  l public.ds_portal_links := public.fn_ds_portal_link(p_token);
begin
  if l.id is null then raise exception 'LINK_NOT_ACTIVE'; end if;
  return public.fn_ds_portal_book_for(l.student_id, p_date, p_start);
end $$;


ALTER FUNCTION "public"."ds_portal_book"("p_token" "text", "p_date" "date", "p_start" time without time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_portal_cancel"("p_token" "text", "p_block" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  l public.ds_portal_links := public.fn_ds_portal_link(p_token);
begin
  if l.id is null then raise exception 'LINK_NOT_ACTIVE'; end if;
  return public.fn_ds_portal_cancel_for(l.student_id, p_block);
end $$;


ALTER FUNCTION "public"."ds_portal_cancel"("p_token" "text", "p_block" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_portal_certificate"("p_token" "text", "p_number" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  l public.ds_portal_links := public.fn_ds_portal_link(p_token);
begin
  if l.id is null then return null; end if;
  return public.fn_ds_portal_certificate_for(l.student_id, p_number);
end $$;


ALTER FUNCTION "public"."ds_portal_certificate"("p_token" "text", "p_number" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_portal_set_sms"("p_token" "text", "p_on" boolean, "p_phone" "text" DEFAULT NULL::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  l public.ds_portal_links := public.fn_ds_portal_link(p_token);
begin
  if l.id is null then raise exception 'LINK_NOT_ACTIVE'; end if;
  perform public.fn_ds_portal_set_sms_for(l.student_id, p_on, p_phone);
end $$;


ALTER FUNCTION "public"."ds_portal_set_sms"("p_token" "text", "p_on" boolean, "p_phone" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_portal_slots"("p_token" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  l public.ds_portal_links := public.fn_ds_portal_link(p_token);
begin
  if l.id is null then return null; end if;
  return public.fn_ds_portal_slots_for(l.student_id);
end $$;


ALTER FUNCTION "public"."ds_portal_slots"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_portal_view"("p_token" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  l public.ds_portal_links := public.fn_ds_portal_link(p_token);
begin
  if l.id is null then return null; end if;
  return public.fn_ds_portal_payload(l.student_id);
end $$;


ALTER FUNCTION "public"."ds_portal_view"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_public_enroll"("p_slug" "text", "p" "jsonb") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
declare
  v_org uuid;
  v_min smallint;
  v_birth date;
  v_age int;
  v_minor boolean;
  v_email text := nullif(lower(btrim(p->>'email')), '');
  v_phone text := nullif(btrim(p->>'phone'), '');
  v_g_name text := nullif(btrim(p->>'guardian_name'), '');
  v_g_email text := nullif(lower(btrim(p->>'guardian_email')), '');
  v_g_phone text := nullif(btrim(p->>'guardian_phone'), '');
  v_program uuid;
  v_branch uuid;
  v_sms boolean := coalesce((p->>'sms_opt_in')::boolean, false);
  v_consent_by text := p->>'consent_by';
  v_email_re text := '^[^@\s]+@[^@\s]+\.[^@\s]+$';
  v_lang text := case when p->>'preferred_language' in ('en', 'es') then p->>'preferred_language' end;
begin
  select pg.organization_id, pg.min_age into v_org, v_min
    from public.ds_public_pages pg
   where pg.slug = lower(p_slug) and pg.enabled
     and public.fn_org_feature_internal(pg.organization_id, 'student_portal');
  if v_org is null then raise exception 'NOT_AVAILABLE' using errcode = 'P0001'; end if;

  delete from public.ds_enrollment_requests where organization_id = v_org and created_at < now() - interval '90 days';

  if nullif(btrim(p->>'first_name'), '') is null or nullif(btrim(p->>'last_name'), '') is null then
    raise exception 'NAME_REQUIRED' using errcode = 'P0001';
  end if;
  begin
    v_birth := (p->>'birth_date')::date;
  exception when others then
    raise exception 'BIRTH_DATE' using errcode = 'P0001';
  end;
  if v_birth is null or v_birth > current_date then raise exception 'BIRTH_DATE' using errcode = 'P0001'; end if;
  v_age := extract(year from age(current_date, v_birth))::int;
  if v_age > 100 then raise exception 'BIRTH_DATE' using errcode = 'P0001'; end if;
  if v_age < greatest(v_min, 13) then raise exception 'TOO_YOUNG' using errcode = 'P0001'; end if;
  v_minor := v_age < coalesce((select age_of_majority from public.ds_settings where organization_id = v_org), 18);

  if (v_email is not null and v_email !~ v_email_re) or (v_g_email is not null and v_g_email !~ v_email_re) then
    raise exception 'EMAIL' using errcode = 'P0001';
  end if;
  if v_minor then
    if v_g_name is null or (v_g_email is null and v_g_phone is null) then
      raise exception 'GUARDIAN_REQUIRED' using errcode = 'P0001';
    end if;
    if v_consent_by is distinct from 'guardian' then raise exception 'GUARDIAN_CONSENT' using errcode = 'P0001'; end if;
  else
    if v_email is null and v_phone is null then raise exception 'CONTACT_REQUIRED' using errcode = 'P0001'; end if;
    if v_consent_by is null or v_consent_by not in ('student', 'guardian') then raise exception 'CONSENT' using errcode = 'P0001'; end if;
  end if;
  if coalesce((p->>'consent')::boolean, false) is not true or length(btrim(coalesce(p->>'consent_name', ''))) < 2 then
    raise exception 'CONSENT' using errcode = 'P0001';
  end if;
  if v_sms and coalesce(nullif(btrim(p->>'sms_phone'), ''), v_phone, v_g_phone) is null then
    raise exception 'SMS_PHONE' using errcode = 'P0001';
  end if;

  begin
    v_program := nullif(p->>'program_id', '')::uuid;
    v_branch := nullif(p->>'branch_id', '')::uuid;
  exception when others then
    raise exception 'INVALID' using errcode = 'P0001';
  end;
  if v_program is not null and not exists (select 1 from public.ds_programs where id = v_program and organization_id = v_org and is_active) then
    v_program := null;
  end if;
  if v_branch is not null and not exists (select 1 from public.branches where id = v_branch and organization_id = v_org and not is_archived) then
    v_branch := null;
  end if;

  if (select count(*) from public.ds_enrollment_requests
       where organization_id = v_org and created_at > now() - interval '1 hour') >= 30 then
    raise exception 'BUSY' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.ds_enrollment_requests r
              where r.organization_id = v_org and r.created_at > now() - interval '24 hours'
                and lower(r.first_name) = lower(btrim(p->>'first_name')) and lower(r.last_name) = lower(btrim(p->>'last_name'))
                and r.birth_date = v_birth) then
    return 'ok';
  end if;
  if (select count(*) from public.ds_enrollment_requests r
       where r.organization_id = v_org and r.created_at > now() - interval '24 hours'
         and ((v_email is not null and (r.email = v_email or r.guardian_email = v_email))
           or (v_g_email is not null and (r.email = v_g_email or r.guardian_email = v_g_email))
           or (v_phone is not null and (r.phone = v_phone or r.guardian_phone = v_phone))
           or (v_g_phone is not null and (r.phone = v_g_phone or r.guardian_phone = v_g_phone)))) >= 5 then
    raise exception 'BUSY' using errcode = 'P0001';
  end if;

  insert into public.ds_enrollment_requests (
    organization_id, first_name, last_name, birth_date, email, phone,
    guardian_name, guardian_email, guardian_phone, program_id, branch_id, message,
    is_minor, consent_by, consent_name, sms_opt_in, sms_phone, preferred_language)
  values (
    v_org, btrim(p->>'first_name'), btrim(p->>'last_name'), v_birth, v_email, v_phone,
    v_g_name, v_g_email, v_g_phone, v_program, v_branch, left(nullif(btrim(p->>'message'), ''), 500),
    v_minor, case when v_minor then 'guardian' else v_consent_by end, left(btrim(p->>'consent_name'), 120),
    v_sms, case when v_sms then coalesce(nullif(btrim(p->>'sms_phone'), ''), v_phone, v_g_phone) end, v_lang);
  return 'ok';
end $_$;


ALTER FUNCTION "public"."ds_public_enroll"("p_slug" "text", "p" "jsonb") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_public_origins"("p_slug" "text") RETURNS "text"[]
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select pg.allowed_origins
    from public.ds_public_pages pg
   where pg.slug = lower(p_slug) and pg.enabled
     and public.fn_org_feature_internal(pg.organization_id, 'student_portal');
$$;


ALTER FUNCTION "public"."ds_public_origins"("p_slug" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_public_page"("p_slug" "text") RETURNS "jsonb"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select jsonb_build_object(
           'school', coalesce(nullif(btrim(o.report_display_name), ''), o.name),
           'intro', pg.intro,
           'min_age', pg.min_age,
           'age_of_majority', coalesce((select s.age_of_majority from public.ds_settings s where s.organization_id = o.id), 18),
           'terms_url', pg.terms_url,
           'programs', coalesce((select jsonb_agg(jsonb_build_object('id', p.id, 'name', p.name) order by p.sort, p.name)
                                   from public.ds_programs p where p.organization_id = o.id and p.is_active), '[]'::jsonb),
           'branches', coalesce((select jsonb_agg(jsonb_build_object('id', b.id, 'name', b.name) order by b.name)
                                   from public.branches b where b.organization_id = o.id and not b.is_archived), '[]'::jsonb))
    from public.ds_public_pages pg
    join public.organizations o on o.id = pg.organization_id
   where pg.slug = lower(p_slug) and pg.enabled
     and public.fn_org_feature_internal(o.id, 'student_portal');
$$;


ALTER FUNCTION "public"."ds_public_page"("p_slug" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_public_slug_for_host"("p_host" "text") RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select pg.slug
    from public.ds_public_pages pg
   where pg.custom_domain = lower(p_host) and pg.domain_status = 'verified' and pg.enabled
     and public.fn_org_feature_internal(pg.organization_id, 'student_portal');
$$;


ALTER FUNCTION "public"."ds_public_slug_for_host"("p_host" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_record_payment"("p_package" "uuid", "p_amount_cents" integer) RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  r public.ds_student_packages;
  v_status text;
begin
  select * into r from public.ds_student_packages where id = p_package for update;
  if r.id is null then raise exception 'PACKAGE_NOT_FOUND' using errcode = 'P0001'; end if;
  if not public.is_org_operator_or_above(r.organization_id) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(r.organization_id, 'student_packages');
  if p_amount_cents is null or p_amount_cents <= 0 then raise exception 'AMOUNT_REQUIRED' using errcode = 'P0001'; end if;
  if r.amount_paid_cents + p_amount_cents > r.price_cents then
    raise exception 'PAYMENT_EXCEEDS_BALANCE' using errcode = 'P0001';
  end if;
  v_status := case when r.amount_paid_cents + p_amount_cents >= r.price_cents then 'paid' else 'partial' end;
  update public.ds_student_packages
     set amount_paid_cents = amount_paid_cents + p_amount_cents, payment_status = v_status
   where id = r.id;
  return v_status;
end $$;


ALTER FUNCTION "public"."ds_record_payment"("p_package" "uuid", "p_amount_cents" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_revoke_portal_link"("p_student" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare v_org uuid;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.is_org_operator_or_above(v_org) then raise exception 'Not authorized'; end if;
  update public.ds_portal_links set revoked_at = now() where student_id = p_student and revoked_at is null;
end $$;


ALTER FUNCTION "public"."ds_revoke_portal_link"("p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_set_custom_domain"("p_org" "uuid", "p_domain" "text") RETURNS "text"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
declare
  v_domain text := lower(btrim(p_domain));
  v_token text := replace(gen_random_uuid()::text, '-', '');
begin
  if not public.is_org_admin_or_owner(p_org) or not public.fn_org_has_feature(p_org, 'student_portal') then
    raise exception 'Not authorized';
  end if;
  if v_domain !~ '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.){2,}[a-z0-9]([a-z0-9-]*[a-z0-9])?$' or length(v_domain) > 253 then
    raise exception 'Use a subdomain like book.yourschool.com' using errcode = 'P0001';
  end if;
  if v_domain like '%controlmiles.com' or v_domain like '%vercel.app' then
    raise exception 'Use an address on your own domain' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.ds_public_pages where custom_domain = v_domain and organization_id <> p_org) then
    raise exception 'That address is already connected to another school' using errcode = 'P0001';
  end if;
  update public.ds_public_pages
     set custom_domain = v_domain, domain_token = v_token, domain_status = 'pending',
         domain_message = null, domain_checked_at = null, domain_verified_at = null, updated_at = now()
   where organization_id = p_org;
  if not found then raise exception 'Save your page settings first' using errcode = 'P0001'; end if;
  return v_token;
end $_$;


ALTER FUNCTION "public"."ds_set_custom_domain"("p_org" "uuid", "p_domain" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_set_emancipation"("p_student" "uuid", "p_emancipated" boolean, "p_note" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(v_org, 'students');
  if p_emancipated then
    if length(btrim(coalesce(p_note, ''))) < 3 then raise exception 'NOTE_REQUIRED' using errcode = 'P0001'; end if;
    update public.ds_students
       set emancipated_at = now(), emancipated_by = auth.uid(), emancipation_note = left(btrim(p_note), 300)
     where id = p_student;
    update public.ds_client_students set is_active = false, ended_at = now(), ended_reason = 'emancipated'
     where student_id = p_student and relation = 'guardian' and is_active;
  else
    update public.ds_students set emancipated_at = null, emancipated_by = null, emancipation_note = null
     where id = p_student;
  end if;
end $$;


ALTER FUNCTION "public"."ds_set_emancipation"("p_student" "uuid", "p_emancipated" boolean, "p_note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_student_classes"("p_student" "uuid") RETURNS TABLE("block_id" "uuid", "block_date" "date", "start_time" time without time zone, "end_time" time without time zone, "status" "text", "instructor_id" "uuid", "vehicle_id" "uuid", "session_id" "uuid", "map_token" "text", "minutes" numeric, "night_minutes" numeric, "miles" numeric, "evaluated" boolean)
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare v_org uuid;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.is_org_operator_or_above(v_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(v_org, 'students');
  return query
  select b.id, b.block_date, b.start_time, b.end_time, b.status, b.driver_id, b.vehicle_id, b.session_id, s.map_token::text,
         n.minutes, n.night_minutes, n.miles,
         exists (select 1 from public.ds_evaluations e where e.shift_block_id = b.id)
    from public.shift_blocks b
    left join public.sessions s on s.id = b.session_id
    cross join lateral public.fn_ds_class_numbers(b.id) n
   where b.student_id = p_student and b.status <> 'cancelled'
   order by b.block_date desc, b.start_time desc;
end $$;


ALTER FUNCTION "public"."ds_student_classes"("p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_student_progress"("p_org" "uuid", "p_student" "uuid" DEFAULT NULL::"uuid") RETURNS TABLE("student_id" "uuid", "classes_done" integer, "minutes" numeric, "night_minutes" numeric, "miles" numeric, "last_class" "date", "next_class" timestamp with time zone, "purchased_minutes" numeric, "evaluations" integer)
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_tz text;
begin
  if not public.is_org_operator_or_above(p_org) then raise exception 'Not authorized'; end if;
  perform public.fn_require_org_feature(p_org, 'students');
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_org;
  return query
  with done as (
    select b.student_id sid, b.block_date, n.minutes, n.night_minutes, n.miles
      from public.shift_blocks b, lateral public.fn_ds_class_numbers(b.id) n
     where b.organization_id = p_org and b.student_id is not null and b.status = 'done'
       and (p_student is null or b.student_id = p_student)
  )
  select st.id,
         coalesce((select count(*)::int from done where sid = st.id), 0),
         coalesce((select sum(d.minutes) from done d where d.sid = st.id), 0),
         coalesce((select sum(d.night_minutes) from done d where d.sid = st.id), 0),
         coalesce((select round(sum(d.miles), 1) from done d where d.sid = st.id), 0),
         (select max(d.block_date) from done d where d.sid = st.id),
         (select min((b.block_date + b.start_time) at time zone v_tz) from public.shift_blocks b
           where b.student_id = st.id and b.status = 'scheduled'
             and (b.block_date + b.start_time) at time zone v_tz > now()),
         coalesce((select sum(sp.minutes)::numeric from public.ds_student_packages sp where sp.student_id = st.id), 0),
         coalesce((select count(*)::int from public.ds_evaluations e where e.student_id = st.id), 0)
    from public.ds_students st
   where st.organization_id = p_org and (p_student is null or st.id = p_student);
end $$;


ALTER FUNCTION "public"."ds_student_progress"("p_org" "uuid", "p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ds_submit_evaluation"("p_block_id" "uuid", "p_scores" "jsonb", "p_note" "text" DEFAULT NULL::"text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  b public.shift_blocks;
  v_eval uuid;
  r record;
begin
  select * into b from public.shift_blocks where id = p_block_id;
  if b.id is null or not (b.driver_id = auth.uid() or public.is_org_operator_or_above(b.organization_id)) then
    raise exception 'Not authorized';
  end if;
  perform public.fn_require_org_feature(b.organization_id, 'student_evaluations');
  if b.student_id is null then raise exception 'CLASS_HAS_NO_STUDENT'; end if;
  if b.status not in ('in_progress', 'done') then raise exception 'CLASS_NOT_STARTED'; end if;
  if p_scores is null or jsonb_typeof(p_scores) <> 'object' or p_scores = '{}'::jsonb then
    raise exception 'RATE_AT_LEAST_ONE_SKILL';
  end if;

  insert into public.ds_evaluations (organization_id, shift_block_id, student_id, instructor_id, note)
  values (b.organization_id, b.id, b.student_id, b.driver_id, nullif(btrim(p_note), ''))
  on conflict (shift_block_id) do update set note = excluded.note
  returning id into v_eval;

  delete from public.ds_evaluation_scores where evaluation_id = v_eval;
  for r in select key, value from jsonb_each_text(p_scores) loop
    if not exists (select 1 from public.ds_skills k where k.id = r.key::uuid and k.organization_id = b.organization_id) then
      raise exception 'Unknown skill';
    end if;
    insert into public.ds_evaluation_scores (evaluation_id, skill_id, score)
    values (v_eval, r.key::uuid, r.value::smallint);
  end loop;
  return v_eval;
end $$;


ALTER FUNCTION "public"."ds_submit_evaluation"("p_block_id" "uuid", "p_scores" "jsonb", "p_note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."end_shift_block"("p_block_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  perform set_config('cm.shift_block_rpc', 'on', true);
  update public.shift_blocks
     set status = 'done', ended_at = now()
   where id = p_block_id and driver_id = auth.uid() and status = 'in_progress';
  perform set_config('cm.shift_block_rpc', 'off', true);
end $$;


ALTER FUNCTION "public"."end_shift_block"("p_block_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."enforce_fleet_org_membership"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  IF NEW.account_type IN ('fleet_admin', 'fleet_driver') 
     AND NOT EXISTS (
       SELECT 1 FROM public.organization_members 
       WHERE user_id = NEW.id AND is_active = true
     ) THEN
    RAISE EXCEPTION 'Los usuarios fleet_admin y fleet_driver DEBEN pertenecer a una organización activa';
  END IF;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."enforce_fleet_org_membership"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."expire_lapsed_play_subscriptions"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  r record;
  n integer := 0;
begin
  for r in
    select distinct p.id
      from public.profiles p
      join public.play_subscriptions s on s.user_id = p.id
     where (p.base_entitled or p.premium_entitled)
       and s.expiry_time <= now()
  loop
    perform public.recompute_personal_entitlements(r.id);
    n := n + 1;
  end loop;
  return n;
end;
$$;


ALTER FUNCTION "public"."expire_lapsed_play_subscriptions"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_assign_driver_slot_display_id"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_new_id text;
  v_attempts int := 0;
begin
  if new.display_id is null or btrim(new.display_id) = '' then
    loop
      v_new_id := 'CM-D' || lpad(floor(random() * 1000000)::text, 6, '0');
      exit when not exists (select 1 from public.fleet_driver_slots where display_id = v_new_id)
            and not public.fn_display_id_blocked(v_new_id);
      v_attempts := v_attempts + 1;
      if v_attempts >= 200 then
        raise exception '[ControlMiles] Could not generate a unique driver ID after % attempts.', v_attempts;
      end if;
    end loop;
    new.display_id := v_new_id;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_assign_driver_slot_display_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_assign_guardian_display_id"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_new_id text;
  v_attempts int := 0;
begin
  if new.display_id is null or btrim(new.display_id) = '' then
    loop
      v_new_id := 'CM-' || lpad(floor(random() * 1000000)::text, 6, '0');
      exit when not exists (select 1 from public.school_guardians where display_id = v_new_id)
            and not public.fn_display_id_blocked(v_new_id);
      v_attempts := v_attempts + 1;
      if v_attempts >= 200 then
        raise exception '[ControlMiles] Could not generate a unique guardian ID after % attempts.', v_attempts;
      end if;
    end loop;
    new.display_id := v_new_id;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_assign_guardian_display_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_assign_profile_display_id"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_letter   char(1);
  v_digits   text;
  v_new_id   text;
  v_attempts int := 0;
  v_max      int := 200;
begin
  if new.display_id is null or btrim(new.display_id) = '' then
    loop
      v_letter := chr(65 + floor(random() * 26)::int);
      v_digits := lpad(floor(random() * 1000000)::text, 6, '0');
      v_new_id := 'CM-' || v_letter || v_digits;
      exit when not exists (select 1 from public.profiles where display_id = v_new_id)
            and not public.fn_display_id_blocked(v_new_id);
      v_attempts := v_attempts + 1;
      if v_attempts >= v_max then
        raise exception '[ControlMiles] Could not generate a unique CM User ID after % attempts.', v_max;
      end if;
    end loop;
    new.display_id := v_new_id;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_assign_profile_display_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_assign_vehicle_display_id"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_new_id text;
  v_attempts int := 0;
begin
  if new.display_id is null or btrim(new.display_id) = '' then
    loop
      v_new_id := 'CM-T' || lpad(floor(random() * 1000000)::text, 6, '0');
      exit when not exists (select 1 from public.vehicles where display_id = v_new_id)
            and not public.fn_display_id_blocked(v_new_id);
      v_attempts := v_attempts + 1;
      if v_attempts >= 200 then
        raise exception '[ControlMiles] Could not generate a unique vehicle ID after % attempts.', v_attempts;
      end if;
    end loop;
    new.display_id := v_new_id;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_assign_vehicle_display_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_block_cross_app_open_trip"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.is_closed is distinct from true and exists (
    select 1 from public.sessions s
    where s.user_id = new.user_id
      and s.is_closed is distinct from true
      and s.id <> new.id
      and (s.organization_id is null) <> (new.organization_id is null)
  ) then
    if new.organization_id is null then
      raise exception 'ACTIVE_FLEET_TRIP';
    else
      raise exception 'ACTIVE_PERSONAL_TRIP';
    end if;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_block_cross_app_open_trip"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_block_vehicle_switch_during_active_session"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
declare
  v_owner uuid;
  v_has_open_session boolean;
begin
  if tg_op = 'INSERT' then
    if new.is_active is distinct from true then
      return new;
    end if;
    v_owner := new.owner_user_id;
  elsif tg_op = 'UPDATE' then
    if new.is_active is not distinct from old.is_active then
      return new;
    end if;
    v_owner := coalesce(new.owner_user_id, old.owner_user_id);
  end if;

  if v_owner is null then
    return new;
  end if;

  select exists (
    select 1 from public.sessions
    where user_id = v_owner and is_closed = false
  ) into v_has_open_session;

  if v_has_open_session then
    raise exception 'No puedes cambiar de vehículo activo mientras tienes un viaje en curso. Termina el viaje actual primero.';
  end if;

  return new;
end;
$$;


ALTER FUNCTION "public"."fn_block_vehicle_switch_during_active_session"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_branches_plan_limit"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  a record;
begin
  if new.is_archived then return new; end if;
  if tg_op = 'UPDATE' and not old.is_archived then return new; end if;
  select * into a from public.fn_org_branch_allowance_internal(new.organization_id);
  if a.max_branches is not null and a.active >= a.max_branches then
    raise exception 'Your plan allows up to % %. Upgrade your plan to add more.',
      a.max_branches, case when a.max_branches = 1 then 'branch' else 'branches' end
      using errcode = 'P0001';
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_branches_plan_limit"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_check_route_monitor"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.monitor_id is not null and not exists (
    select 1 from public.organization_members
     where organization_id = new.organization_id and user_id = new.monitor_id
       and member_role = 'monitor' and is_active
  ) then
    raise exception 'The bus monitor must be an active monitor of this fleet';
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_check_route_monitor"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_classify_section_on_close"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_settings public.trip_classification_settings%rowtype;
  v_has_settings boolean;
  v_rule_purpose text;
  v_local timestamp;
  v_minute integer;
  v_today integer;
  v_yesterday integer;
  v_inside boolean;
begin
  if OLD.section_status in ('closed', 'switched') then
    if NEW.irs_purpose is distinct from OLD.irs_purpose
       and NEW.auto_purpose_source is not distinct from OLD.auto_purpose_source then
      NEW.auto_purpose_source := null;
    end if;
    return NEW;
  end if;

  if NEW.section_status is distinct from 'closed'
     or NEW.gig_app is distinct from 'custom'
     or NEW.organization_id is not null
     or NEW.irs_purpose is not null then
    return NEW;
  end if;

  begin
    if not exists (select 1 from public.profiles p where p.id = NEW.user_id and p.premium_entitled) then
      return NEW;
    end if;

    select * into v_settings from public.trip_classification_settings s where s.user_id = NEW.user_id;
    v_has_settings := found;

    if not v_has_settings or v_settings.regular_enabled then
      select r.purpose into v_rule_purpose
      from public.regular_trips r
      where r.user_id = NEW.user_id
        and public.fn_regular_trip_covers(r, NEW.start_latitude, NEW.start_longitude, NEW.end_latitude, NEW.end_longitude)
      order by r.start_any, r.created_at desc
      limit 1;
      if v_rule_purpose is not null then
        NEW.irs_purpose := v_rule_purpose;
        NEW.auto_purpose_source := 'regular_trip';
        return NEW;
      end if;
    end if;

    if v_has_settings and (v_settings.work_hours_inside or v_settings.work_hours_outside) then
      v_local := NEW.start_time at time zone v_settings.time_zone;
      v_minute := extract(hour from v_local)::integer * 60 + extract(minute from v_local)::integer;
      v_today := extract(isodow from v_local)::integer;
      v_yesterday := case when v_today = 1 then 7 else v_today - 1 end;
      if v_settings.work_start_minute < v_settings.work_end_minute then
        v_inside := v_today = any(v_settings.work_days)
          and v_minute >= v_settings.work_start_minute and v_minute < v_settings.work_end_minute;
      else
        v_inside := (v_today = any(v_settings.work_days) and v_minute >= v_settings.work_start_minute)
          or (v_yesterday = any(v_settings.work_days) and v_minute < v_settings.work_end_minute);
      end if;
      if v_inside and v_settings.work_hours_inside then
        NEW.irs_purpose := 'business';
        NEW.auto_purpose_source := 'work_hours';
      elsif not v_inside and v_settings.work_hours_outside then
        NEW.irs_purpose := 'personal';
        NEW.auto_purpose_source := 'work_hours';
      end if;
    end if;
  exception when others then
    raise warning 'fn_classify_section_on_close failed for %: %', NEW.id, sqlerrm;
  end;
  return NEW;
end;
$$;


ALTER FUNCTION "public"."fn_classify_section_on_close"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_cm_distance_m"("lat1" double precision, "lng1" double precision, "lat2" double precision, "lng2" double precision) RETURNS double precision
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  select 6371000 * 2 * asin(least(1, sqrt(
    power(sin(radians(lat2 - lat1) / 2), 2)
    + cos(radians(lat1)) * cos(radians(lat2)) * power(sin(radians(lng2 - lng1) / 2), 2)
  )));
$$;


ALTER FUNCTION "public"."fn_cm_distance_m"("lat1" double precision, "lng1" double precision, "lat2" double precision, "lng2" double precision) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_delete_personal_rows_on_profile_delete"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  perform set_config('cm.account_deletion', 'on', true);
  delete from public.vehicle_inspections where user_id = old.id and organization_id is null;
  delete from public.trip_incidents where user_id = old.id and organization_id is null;
  delete from public.fuel_purchases where user_id = old.id and organization_id is null;
  delete from public.session_gps_breadcrumbs where user_id = old.id and organization_id is null;
  return old;
end $$;


ALTER FUNCTION "public"."fn_delete_personal_rows_on_profile_delete"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_discard_zero_mile_trip"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if coalesce(new.total_miles, 0) < 1
     and coalesce((select sum(ss.total_miles) from public.session_sections ss
                   where ss.session_id = new.id), 0) < 1 then
    delete from public.sessions where id = new.id;
  else
    perform public.fn_fold_empty_trip_sections(new.id);
  end if;
  return null;
end;
$$;


ALTER FUNCTION "public"."fn_discard_zero_mile_trip"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_display_id_blocked"("p_id" "text") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select exists (
    select 1
      from public.retired_display_ids r
      cross join public.platform_id_policy pol
     where r.display_id = p_id
       and (pol.reuse_after_days is null
            or r.retired_at > now() - make_interval(days => pol.reuse_after_days))
  );
$$;


ALTER FUNCTION "public"."fn_display_id_blocked"("p_id" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_drop_empty_switched_section"("p_section_id" "uuid", "p_into_section_id" "uuid") RETURNS boolean
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  s public.session_sections%rowtype;
begin
  select * into s from public.session_sections where id = p_section_id;
  if not found
     or s.user_id is distinct from auth.uid()
     or s.section_status <> 'switched'
     or coalesce(s.total_miles, 0) >= 0.05
     or nullif(btrim(coalesce(s.notes, '')), '') is not null
     or s.start_odometer_image_url is not null
     or s.end_odometer_image_url is not null then
    return false;
  end if;

  if not exists (
    select 1 from public.session_sections t
     where t.id = p_into_section_id
       and t.id <> s.id
       and t.session_id = s.session_id
       and t.user_id = auth.uid()
  ) then
    return false;
  end if;

  update public.audit_events set section_id = p_into_section_id where section_id = s.id;
  update public.session_gps_breadcrumbs set section_id = p_into_section_id where section_id = s.id;
  delete from public.session_sections where id = s.id;
  return true;
end;
$$;


ALTER FUNCTION "public"."fn_drop_empty_switched_section"("p_section_id" "uuid", "p_into_section_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_balance"("p_student" "uuid", OUT "purchased" integer, OUT "used" integer, OUT "booked" integer, OUT "available" integer) RETURNS "record"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select x.p, x.u, x.b, x.p - x.u - x.b from (
    select coalesce((select sum(minutes)::int from public.ds_student_packages where student_id = p_student), 0) p,
           coalesce((select (sum(extract(epoch from (end_time - start_time))) / 60)::int from public.shift_blocks
                      where student_id = p_student and (status = 'done' or (status = 'cancelled' and late_cancel))), 0) u,
           coalesce((select (sum(extract(epoch from (end_time - start_time))) / 60)::int from public.shift_blocks
                      where student_id = p_student and status in ('scheduled', 'in_progress')), 0) b
  ) x
$$;


ALTER FUNCTION "public"."fn_ds_balance"("p_student" "uuid", OUT "purchased" integer, OUT "used" integer, OUT "booked" integer, OUT "available" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_block_student_same_org"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.student_id is not null and not exists (
    select 1 from public.ds_students s where s.id = new.student_id and s.organization_id = new.organization_id
  ) then
    raise exception 'Student not found';
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_ds_block_student_same_org"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_certificates_immutable"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  raise exception 'CERTIFICATE_IMMUTABLE';
end $$;


ALTER FUNCTION "public"."fn_ds_certificates_immutable"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_class_numbers"("p_block_id" "uuid", OUT "minutes" numeric, OUT "night_minutes" numeric, OUT "miles" numeric, OUT "started" timestamp with time zone, OUT "ended" timestamp with time zone) RETURNS "record"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  b public.shift_blocks;
  s public.sessions;
  v_lat double precision;
  v_lng double precision;
  v_tz text;
  st record;
  v_dark_end timestamptz;
  v_dark_start timestamptz;
begin
  select * into b from public.shift_blocks where id = p_block_id;
  if b.id is null then return; end if;
  if b.session_id is not null then
    select * into s from public.sessions where id = b.session_id;
  end if;
  started := coalesce(s.start_time, b.started_at);
  ended := coalesce(s.end_time, b.ended_at);
  miles := coalesce(s.total_miles, 0);
  if started is null or ended is null or ended <= started then
    minutes := 0; night_minutes := 0; return;
  end if;
  minutes := round(extract(epoch from (ended - started)) / 60, 1);

  if s.id is not null then
    select latitude, longitude into v_lat, v_lng from public.session_gps_breadcrumbs
     where session_id = s.id order by recorded_at limit 1;
  end if;
  if v_lat is not null then
    st := public.fn_sun_times(v_lat, v_lng, started);
    v_dark_end := st.sunrise;
    v_dark_start := st.sunset;
  else
    select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = b.organization_id;
    v_dark_end := ((started at time zone v_tz)::date + time '06:00') at time zone v_tz;
    v_dark_start := ((started at time zone v_tz)::date + time '20:00') at time zone v_tz;
  end if;
  night_minutes := round((
      greatest(0, extract(epoch from (least(ended, v_dark_end) - started)))
    + greatest(0, extract(epoch from (ended - greatest(started, v_dark_start))))
  ) / 60, 1);
  night_minutes := least(night_minutes, minutes);
end $$;


ALTER FUNCTION "public"."fn_ds_class_numbers"("p_block_id" "uuid", OUT "minutes" numeric, OUT "night_minutes" numeric, OUT "miles" numeric, OUT "started" timestamp with time zone, OUT "ended" timestamp with time zone) OWNER TO "postgres";

SET default_tablespace = '';

SET default_table_access_method = "heap";


CREATE TABLE IF NOT EXISTS "public"."ds_clients" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "email" "text" NOT NULL,
    "first_name" "text" NOT NULL,
    "last_name" "text" NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revoked_at" timestamp with time zone,
    "last_seen_at" timestamp with time zone,
    CONSTRAINT "ds_clients_email_check" CHECK ((("email" = "lower"("btrim"("email"))) AND ("length"("email") <= 120) AND ("email" ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$'::"text"))),
    CONSTRAINT "ds_clients_first_name_check" CHECK ((("length"("btrim"("first_name")) >= 1) AND ("length"("btrim"("first_name")) <= 60))),
    CONSTRAINT "ds_clients_last_name_check" CHECK ((("length"("btrim"("last_name")) >= 1) AND ("length"("btrim"("last_name")) <= 60)))
);


ALTER TABLE "public"."ds_clients" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_client_session"("p_session" "text") RETURNS "public"."ds_clients"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
  select c.* from public.ds_client_tokens t
    join public.ds_clients c on c.id = t.client_id
   where t.token_hash = encode(digest(coalesce(p_session, ''), 'sha256'), 'hex')
     and t.kind = 'session' and t.revoked_at is null and t.expires_at > now()
     and c.is_active and public.fn_org_feature_internal(c.organization_id, 'student_portal');
$$;


ALTER FUNCTION "public"."fn_ds_client_session"("p_session" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_client_student"("p_session" "text", "p_student" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  c public.ds_clients := public.fn_ds_client_session(p_session);
  v uuid;
begin
  if c.id is null then raise exception 'SESSION_ENDED'; end if;
  select cs.student_id into v from public.ds_client_students cs
   where cs.client_id = c.id and cs.student_id = p_student and cs.is_active
     and public.fn_ds_link_counts(cs.relation, cs.student_id);
  if v is null then raise exception 'NO_ACCESS'; end if;
  return v;
end $$;


ALTER FUNCTION "public"."fn_ds_client_student"("p_session" "text", "p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_close_guardian_links"() RETURNS "void"
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  update public.ds_client_students cs
     set is_active = false, ended_at = now(),
         ended_reason = case when st.emancipated_at is not null then 'emancipated' else 'majority' end
    from public.ds_students st
   where st.id = cs.student_id and cs.relation = 'guardian' and cs.is_active
     and not public.fn_ds_is_minor(cs.student_id);
$$;


ALTER FUNCTION "public"."fn_ds_close_guardian_links"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_conflict"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_exclude" "uuid") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_label text;
begin
  select coalesce(h.label, '') into v_label
    from public.ds_blocked_hours h
   where h.organization_id = p_org
     and (h.instructor_id is null or h.instructor_id = p_driver)
     and (h.weekday is null or h.weekday = extract(dow from p_date)::int)
     and (h.on_date is null or h.on_date = p_date)
     and h.start_time < p_end and h.end_time > p_start
   limit 1;
  if found then return 'BLOCKED:' || v_label; end if;
  if exists (select 1 from public.ds_time_off t
              where t.organization_id = p_org and t.instructor_id = p_driver and p_date between t.date_from and t.date_to) then
    return 'TIME_OFF';
  end if;
  if exists (select 1 from public.shift_blocks b
              where b.organization_id = p_org and b.block_date = p_date and b.status <> 'cancelled'
                and (p_exclude is null or b.id <> p_exclude)
                and b.driver_id = p_driver and b.start_time < p_end and b.end_time > p_start) then
    return 'INSTRUCTOR_BUSY';
  end if;
  if p_vehicle is not null and exists (select 1 from public.shift_blocks b
              where b.organization_id = p_org and b.block_date = p_date and b.status <> 'cancelled'
                and (p_exclude is null or b.id <> p_exclude)
                and b.vehicle_id = p_vehicle and b.start_time < p_end and b.end_time > p_start) then
    return 'CAR_BUSY';
  end if;
  return null;
end $$;


ALTER FUNCTION "public"."fn_ds_conflict"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_exclude" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_free_slots"("p_org" "uuid", "p_minutes" integer, "p_from" "date", "p_days" integer, "p_lead_hours" integer) RETURNS TABLE("instructor_id" "uuid", "vehicle_id" "uuid", "block_date" "date", "start_time" time without time zone, "end_time" time without time zone, "starts_at" timestamp with time zone)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select g.instructor_id, g.vehicle_id, g.block_date, g.start_time, g.end_time, g.starts_at
    from public.fn_ds_slot_grid(p_org, p_minutes, p_from, p_days, p_lead_hours) g
   where g.status = 'free'
   order by g.block_date, g.start_time, g.instructor_id;
$$;


ALTER FUNCTION "public"."fn_ds_free_slots"("p_org" "uuid", "p_minutes" integer, "p_from" "date", "p_days" integer, "p_lead_hours" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_is_minor"("p_student" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select coalesce((
    select st.emancipated_at is null
       and coalesce(st.birth_date, pv.date_of_birth) is not null
       and coalesce(st.birth_date, pv.date_of_birth) + make_interval(years => coalesce(cfg.age_of_majority, 18))
           > (now() at time zone coalesce(o.timezone, 'America/New_York'))::date
      from public.ds_students st
      join public.organizations o on o.id = st.organization_id
      left join public.ds_student_private pv on pv.student_id = st.id
      left join public.ds_settings cfg on cfg.organization_id = st.organization_id
     where st.id = p_student), false);
$$;


ALTER FUNCTION "public"."fn_ds_is_minor"("p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_link_client"("p_client" "uuid", "p_student" "uuid", "p_relation" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if p_relation = 'self' then
    update public.ds_client_students set is_active = false, ended_at = now(), ended_reason = 'revoked'
     where student_id = p_student and relation = 'self' and is_active and client_id <> p_client;
  end if;
  insert into public.ds_client_students (organization_id, client_id, student_id, relation)
  values (v_org, p_client, p_student, p_relation)
  on conflict (client_id, student_id) do update
    set relation = excluded.relation, is_active = true, ended_at = null, ended_reason = null;
end $$;


ALTER FUNCTION "public"."fn_ds_link_client"("p_client" "uuid", "p_student" "uuid", "p_relation" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_link_counts"("p_relation" "text", "p_student" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select case p_relation
           when 'guardian' then public.fn_ds_is_minor(p_student)
           when 'self' then not public.fn_ds_is_minor(p_student)
           else false end;
$$;


ALTER FUNCTION "public"."fn_ds_link_counts"("p_relation" "text", "p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_portal_book_for"("p_student" "uuid", "p_date" "date", "p_start" time without time zone) RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  st public.ds_students;
  pr public.ds_programs;
  cfg public.ds_settings;
  v_tz text;
  s record;
  bal record;
  v_upcoming int;
  v_id uuid;
begin
  select * into st from public.ds_students where id = p_student;
  if st.id is null then raise exception 'LINK_NOT_ACTIVE'; end if;
  perform public.fn_require_org_feature(st.organization_id, 'student_booking');
  select * into cfg from public.ds_settings where organization_id = st.organization_id;
  if not coalesce(cfg.booking_enabled, false) then raise exception 'BOOKING_OFF'; end if;
  select * into pr from public.ds_programs where id = st.program_id and is_active;
  if pr.id is null or st.status not in ('registered', 'active') then raise exception 'BOOKING_OFF'; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = st.organization_id;

  perform pg_advisory_xact_lock(hashtext(st.organization_id::text || p_date::text || p_start::text));

  select count(*) into v_upcoming from public.shift_blocks
   where student_id = st.id and status = 'scheduled' and (block_date + start_time) at time zone v_tz > now();
  if v_upcoming >= cfg.booking_max_upcoming then raise exception 'TOO_MANY_UPCOMING'; end if;

  if public.fn_org_feature_internal(st.organization_id, 'student_packages')
     and exists (select 1 from public.ds_packages where organization_id = st.organization_id and is_active) then
    bal := public.fn_ds_balance(st.id);
    if bal.purchased - bal.used - bal.booked < pr.class_minutes then raise exception 'NO_BALANCE'; end if;
  end if;

  select f.* into s
    from public.fn_ds_free_slots(st.organization_id, pr.class_minutes, p_date, 1, cfg.booking_lead_hours) f
    join public.organization_members m on m.organization_id = st.organization_id and m.user_id = f.instructor_id
   where f.start_time = p_start
     and p_date <= (now() at time zone v_tz)::date + cfg.booking_horizon_days
     and (st.preferred_language is null or st.preferred_language = any (m.languages))
     and (st.branch_id is null or m.any_branch or m.branch_id is null or m.branch_id = st.branch_id)
   order by random()
   limit 1;
  if s.instructor_id is null then raise exception 'SLOT_TAKEN'; end if;

  insert into public.shift_blocks (organization_id, driver_id, vehicle_id, block_date, start_time, end_time, source,
                                   status, student_id, booked_via, note)
  values (st.organization_id, s.instructor_id, s.vehicle_id, s.block_date, s.start_time, s.end_time, 'one_off',
          'scheduled', st.id, 'portal', 'Booked online')
  returning id into v_id;
  return v_id;
end $$;


ALTER FUNCTION "public"."fn_ds_portal_book_for"("p_student" "uuid", "p_date" "date", "p_start" time without time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_portal_cancel_for"("p_student" "uuid", "p_block" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  b public.shift_blocks;
  cfg public.ds_settings;
  st public.ds_students;
  v_tz text;
  v_starts timestamptz;
  v_late boolean;
begin
  select * into st from public.ds_students where id = p_student;
  if st.id is null then raise exception 'LINK_NOT_ACTIVE'; end if;
  perform public.fn_require_org_feature(st.organization_id, 'student_booking');
  select * into b from public.shift_blocks where id = p_block and student_id = st.id;
  if b.id is null or b.status <> 'scheduled' then raise exception 'CLASS_NOT_CANCELLABLE'; end if;
  select * into cfg from public.ds_settings where organization_id = st.organization_id;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = st.organization_id;
  v_starts := (b.block_date + b.start_time) at time zone v_tz;
  if v_starts <= now() then raise exception 'CLASS_NOT_CANCELLABLE'; end if;
  v_late := v_starts - now() < make_interval(hours => coalesce(cfg.cancel_free_hours, 24));

  update public.shift_blocks set status = 'cancelled', cancelled_at = now(), late_cancel = v_late where id = b.id;

  if v_starts > now() + make_interval(hours => coalesce(cfg.booking_lead_hours, 24)) then
    insert into public.ds_slot_notices (organization_id, program_id, instructor_id, vehicle_id, block_date, start_time, end_time, freed_by_student)
    values (st.organization_id, st.program_id, b.driver_id, b.vehicle_id, b.block_date, b.start_time, b.end_time, st.id);
  end if;
  return jsonb_build_object('late', v_late);
end $$;


ALTER FUNCTION "public"."fn_ds_portal_cancel_for"("p_student" "uuid", "p_block" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_portal_certificate_for"("p_student" "uuid", "p_number" "text") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  c public.ds_certificates;
  v_org uuid;
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null or not public.fn_org_feature_internal(v_org, 'student_portal') then return null; end if;
  select * into c from public.ds_certificates where student_id = p_student and number = p_number;
  if c.id is null then return null; end if;
  return jsonb_build_object('data', c.data, 'sha256', c.sha256, 'number', c.number, 'issued_at', c.issued_at);
end $$;


ALTER FUNCTION "public"."fn_ds_portal_certificate_for"("p_student" "uuid", "p_number" "text") OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_portal_links" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "student_id" "uuid" NOT NULL,
    "token_hash" "text" NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "expires_at" timestamp with time zone DEFAULT ("now"() + '180 days'::interval) NOT NULL,
    "revoked_at" timestamp with time zone
);


ALTER TABLE "public"."ds_portal_links" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_portal_link"("p_token" "text") RETURNS "public"."ds_portal_links"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
  select * from public.ds_portal_links
   where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex')
     and revoked_at is null and expires_at > now();
$$;


ALTER FUNCTION "public"."fn_ds_portal_link"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_portal_payload"("p_student" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  st public.ds_students;
  cfg public.ds_settings;
  bal record;
  v_booking boolean;
begin
  select * into st from public.ds_students where id = p_student;
  if st.id is null or not public.fn_org_feature_internal(st.organization_id, 'student_portal') then return null; end if;
  select * into cfg from public.ds_settings where organization_id = st.organization_id;
  bal := public.fn_ds_balance(st.id);
  v_booking := public.fn_org_feature_internal(st.organization_id, 'student_booking') and coalesce(cfg.booking_enabled, false)
               and st.status in ('registered', 'active') and st.program_id is not null;
  return public.fn_ds_student_snapshot(st.id) || jsonb_build_object(
    'certificates', coalesce((select jsonb_agg(jsonb_build_object('number', c.number, 'issued_at', c.issued_at, 'sha256', c.sha256) order by c.issued_at)
                                from public.ds_certificates c where c.student_id = st.id), '[]'::jsonb),
    'booking', jsonb_build_object(
       'enabled', v_booking,
       'cancel_free_hours', coalesce(cfg.cancel_free_hours, 24),
       'policy', cfg.cancellation_policy,
       'max_upcoming', coalesce(cfg.booking_max_upcoming, 2)),
    'balance', case when public.fn_org_feature_internal(st.organization_id, 'student_packages')
                     and (exists (select 1 from public.ds_student_packages where student_id = st.id)
                          or exists (select 1 from public.ds_packages where organization_id = st.organization_id and is_active))
                    then jsonb_build_object('purchased', bal.purchased, 'used', bal.used, 'booked', bal.booked,
                                            'available', bal.purchased - bal.used - bal.booked)
                    else null end,
    'sms', jsonb_build_object('available', public.fn_org_feature_internal(st.organization_id, 'sms_reminders'),
                              'consent', st.sms_consent_at is not null,
                              'phone', st.sms_consent_phone)
  );
end $$;


ALTER FUNCTION "public"."fn_ds_portal_payload"("p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_portal_set_sms_for"("p_student" "uuid", "p_on" boolean, "p_phone" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
  v_phone text := nullif(regexp_replace(coalesce(p_phone, ''), '[^0-9+]', '', 'g'), '');
begin
  select organization_id into v_org from public.ds_students where id = p_student;
  if v_org is null then raise exception 'LINK_NOT_ACTIVE'; end if;
  perform public.fn_require_org_feature(v_org, 'sms_reminders');
  if p_on then
    if v_phone is null or length(v_phone) < 10 then raise exception 'PHONE_REQUIRED'; end if;
    update public.ds_students set sms_consent_at = now(), sms_consent_phone = v_phone, sms_consent_source = 'portal'
     where id = p_student;
  else
    update public.ds_students set sms_consent_at = null, sms_consent_phone = null, sms_consent_source = null
     where id = p_student;
  end if;
end $$;


ALTER FUNCTION "public"."fn_ds_portal_set_sms_for"("p_student" "uuid", "p_on" boolean, "p_phone" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_portal_slots_for"("p_student" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  st public.ds_students;
  pr public.ds_programs;
  cfg public.ds_settings;
  v_tz text;
begin
  select * into st from public.ds_students where id = p_student;
  if st.id is null then return null; end if;
  if not public.fn_org_feature_internal(st.organization_id, 'student_booking') then return null; end if;
  select * into cfg from public.ds_settings where organization_id = st.organization_id;
  if not coalesce(cfg.booking_enabled, false) then return null; end if;
  select * into pr from public.ds_programs where id = st.program_id and is_active;
  if pr.id is null or st.status not in ('registered', 'active') then return null; end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = st.organization_id;
  return (
    with g as (
      select s.block_date, s.start_time, s.end_time, s.status
        from public.fn_ds_slot_grid(st.organization_id, pr.class_minutes, (now() at time zone v_tz)::date,
                                    cfg.booking_horizon_days, cfg.booking_lead_hours) s
        join public.organization_members m
          on m.organization_id = st.organization_id and m.user_id = s.instructor_id
       where s.status <> 'past'
         and (st.preferred_language is null or st.preferred_language = any (m.languages))
         and (st.branch_id is null or m.any_branch or m.branch_id is null or m.branch_id = st.branch_id)
    ),
    cell as (
      select block_date, start_time, end_time,
             case when bool_or(status = 'free') then 'free'
                  when bool_and(status = 'break') then 'break'
                  else 'busy' end status
        from g group by block_date, start_time, end_time
    )
    select jsonb_build_object(
      'minutes', pr.class_minutes,
      'language', st.preferred_language,
      'slots', coalesce((select jsonb_agg(jsonb_build_object('date', block_date, 'start', start_time, 'end', end_time)
                                          order by block_date, start_time)
                           from cell where status = 'free'), '[]'::jsonb),
      'grid', coalesce((select jsonb_agg(jsonb_build_object('date', block_date, 'start', start_time, 'end', end_time, 'status', status)
                                         order by block_date, start_time)
                          from cell), '[]'::jsonb)
    )
  );
end $$;


ALTER FUNCTION "public"."fn_ds_portal_slots_for"("p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_purge_client_tokens"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_deleted integer;
begin
  delete from public.ds_client_tokens
   where expires_at < now() - interval '7 days'
      or used_at < now() - interval '7 days'
      or revoked_at < now() - interval '7 days';
  get diagnostics v_deleted = row_count;
  return v_deleted;
end
$$;


ALTER FUNCTION "public"."fn_ds_purge_client_tokens"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_purge_enrollment_requests"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_deleted integer;
begin
  delete from public.ds_enrollment_requests where created_at < now() - interval '90 days';
  get diagnostics v_deleted = row_count;
  return v_deleted;
end
$$;


ALTER FUNCTION "public"."fn_ds_purge_enrollment_requests"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_slot_grid"("p_org" "uuid", "p_minutes" integer, "p_from" "date", "p_days" integer, "p_lead_hours" integer) RETURNS TABLE("instructor_id" "uuid", "vehicle_id" "uuid", "block_date" "date", "start_time" time without time zone, "end_time" time without time zone, "starts_at" timestamp with time zone, "status" "text")
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  with org as (
    select coalesce(timezone, 'America/New_York') tz from public.organizations where id = p_org
  ),
  cfg as (
    select s.booking_open_time o, s.booking_close_time c from public.ds_settings s where s.organization_id = p_org
  ),
  fleet as (
    select exists (select 1 from public.vehicles v where v.organization_id = p_org and not v.is_archived) has_cars
  ),
  days as (
    select (p_from + g)::date d from generate_series(0, greatest(p_days, 1) - 1) g
  ),
  av as (
    select a.instructor_id, a.start_time a_start, a.end_time a_end, d.d,
           coalesce(a.vehicle_id, (select v.id from public.vehicles v
                                    where v.organization_id = p_org and v.assigned_driver_id = a.instructor_id
                                      and not v.is_archived order by v.created_at limit 1)) vid
      from public.ds_availability a
      join days d on a.weekday = extract(dow from d.d)::int
     where a.organization_id = p_org
       and exists (select 1 from public.organization_members m
                    where m.organization_id = p_org and m.user_id = a.instructor_id and m.is_active)
       and not exists (select 1 from public.ds_time_off t
                        where t.organization_id = p_org and t.instructor_id = a.instructor_id
                          and d.d between t.date_from and t.date_to)
  ),
  slots as (
    select av.instructor_id, av.vid, av.d, av.a_end,
           (av.a_start + make_interval(mins => k * p_minutes))::time st,
           (av.a_start + make_interval(mins => (k + 1) * p_minutes))::time en
      from av,
           generate_series(0, greatest(0, (extract(epoch from (av.a_end - av.a_start)) / 60)::int / p_minutes - 1)) k
  ),
  cand as (
    select s.instructor_id, s.vid, s.d, s.st, s.en,
           (s.d + s.st) at time zone (select tz from org) starts_at
      from slots s
     where s.en > s.st and s.en <= s.a_end
  ),
  picked as (
    select c.*, case when c.vid is not null then c.vid else pool.id end car
      from cand c
      left join lateral (
        select v.id from public.vehicles v
         where c.vid is null and v.organization_id = p_org and not v.is_archived
           and not exists (select 1 from public.shift_blocks b
                            where b.organization_id = p_org and b.block_date = c.d and b.status <> 'cancelled'
                              and b.vehicle_id = v.id and b.start_time < c.en and b.end_time > c.st)
         order by v.created_at limit 1) pool on true
  )
  select p.instructor_id, p.car, p.d, p.st, p.en, p.starts_at,
         case
           when p.starts_at < now() then 'past'
           when (select o from cfg) is not null and (p.st < (select o from cfg) or p.en > (select c from cfg)) then 'break'
           when exists (select 1 from public.ds_blocked_hours h
                         where h.organization_id = p_org
                           and (h.instructor_id is null or h.instructor_id = p.instructor_id)
                           and (h.weekday is null or h.weekday = extract(dow from p.d)::int)
                           and (h.on_date is null or h.on_date = p.d)
                           and h.start_time < p.en and h.end_time > p.st) then 'break'
           when p.starts_at < now() + make_interval(hours => p_lead_hours) then 'busy'
           when exists (select 1 from public.shift_blocks b
                         where b.organization_id = p_org and b.block_date = p.d and b.status <> 'cancelled'
                           and b.driver_id = p.instructor_id and b.start_time < p.en and b.end_time > p.st) then 'busy'
           when p.vid is not null and exists (select 1 from public.shift_blocks b
                         where b.organization_id = p_org and b.block_date = p.d and b.status <> 'cancelled'
                           and b.vehicle_id = p.vid and b.start_time < p.en and b.end_time > p.st) then 'busy'
           when p.vid is null and (select has_cars from fleet) and p.car is null then 'busy'
           else 'free'
         end
    from picked p
   order by p.d, p.st, p.instructor_id;
$$;


ALTER FUNCTION "public"."fn_ds_slot_grid"("p_org" "uuid", "p_minutes" integer, "p_from" "date", "p_days" integer, "p_lead_hours" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_student_program_same_org"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.program_id is not null and not exists (
    select 1 from public.ds_programs p where p.id = new.program_id and p.organization_id = new.organization_id
  ) then
    raise exception 'Program not found';
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_ds_student_program_same_org"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_student_snapshot"("p_student" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  st public.ds_students;
  pr public.ds_programs;
  v_tz text;
  v_org_name text;
  v_classes jsonb;
  v_upcoming jsonb;
begin
  select * into st from public.ds_students where id = p_student;
  if st.id is null then return null; end if;
  select * into pr from public.ds_programs where id = st.program_id;
  select coalesce(timezone, 'America/New_York'), coalesce(report_display_name, name) into v_tz, v_org_name
    from public.organizations where id = st.organization_id;

  select coalesce(jsonb_agg(jsonb_build_object(
           'date', b.block_date, 'start', b.start_time, 'end', b.end_time,
           'instructor', nullif(concat_ws(' ', p.first_name, left(p.last_name, 1)), ''),
           'vehicle', nullif(concat_ws(' ', v.make, v.model), ''), 'vehicle_id', v.display_id,
           'minutes', n.minutes, 'night_minutes', n.night_minutes, 'miles', n.miles,
           'map_token', s.map_token, 'session_id', b.session_id,
           'evaluation', (select jsonb_build_object('note', e.note, 'scores',
                            coalesce((select jsonb_agg(jsonb_build_object('skill', k.name, 'category', k.category, 'score', sc.score) order by k.sort)
                                        from public.ds_evaluation_scores sc join public.ds_skills k on k.id = sc.skill_id
                                       where sc.evaluation_id = e.id), '[]'::jsonb))
                          from public.ds_evaluations e where e.shift_block_id = b.id)
         ) order by b.block_date, b.start_time), '[]'::jsonb)
    into v_classes
    from public.shift_blocks b
    cross join lateral public.fn_ds_class_numbers(b.id) n
    left join public.profiles p on p.id = b.driver_id
    left join public.vehicles v on v.id = b.vehicle_id
    left join public.sessions s on s.id = b.session_id
   where b.student_id = p_student and b.status = 'done';

  select coalesce(jsonb_agg(jsonb_build_object('id', b.id, 'date', b.block_date, 'start', b.start_time, 'end', b.end_time,
           'instructor', nullif(concat_ws(' ', p.first_name, left(p.last_name, 1)), ''),
           'starts_at', (b.block_date + b.start_time) at time zone v_tz)
         order by b.block_date, b.start_time), '[]'::jsonb)
    into v_upcoming
    from public.shift_blocks b
    left join public.profiles p on p.id = b.driver_id
   where b.student_id = p_student and b.status = 'scheduled'
     and (b.block_date + b.start_time) at time zone v_tz > now();

  return jsonb_build_object(
    'school', v_org_name,
    'timezone', v_tz,
    'student', jsonb_build_object('first_name', st.first_name, 'last_name', st.last_name, 'status', st.status),
    'program', coalesce(pr.name, ''),
    'required_minutes', coalesce(pr.required_minutes, 0),
    'required_night_minutes', coalesce(pr.required_night_minutes, 0),
    'classes', v_classes,
    'upcoming', v_upcoming,
    'minutes', (select coalesce(sum((c->>'minutes')::numeric), 0) from jsonb_array_elements(v_classes) c),
    'night_minutes', (select coalesce(sum((c->>'night_minutes')::numeric), 0) from jsonb_array_elements(v_classes) c),
    'miles', (select coalesce(round(sum((c->>'miles')::numeric), 1), 0) from jsonb_array_elements(v_classes) c)
  );
end $$;


ALTER FUNCTION "public"."fn_ds_student_snapshot"("p_student" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_touch"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  new.updated_at := now();
  return new;
end $$;


ALTER FUNCTION "public"."fn_ds_touch"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ds_upsert_client"("p_org" "uuid", "p_email" "text", "p_first" "text", "p_last" "text", "p_reactivate" boolean) RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $_$
declare
  v_email text := lower(btrim(coalesce(p_email, '')));
  v_id uuid;
  v_active boolean;
begin
  if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' or length(v_email) > 120 then raise exception 'EMAIL' using errcode = 'P0001'; end if;
  select id, is_active into v_id, v_active from public.ds_clients where organization_id = p_org and email = v_email;
  if v_id is null then
    insert into public.ds_clients (organization_id, email, first_name, last_name, created_by)
    values (p_org, v_email, left(btrim(p_first), 60), left(btrim(p_last), 60), auth.uid())
    returning id into v_id;
  elsif not v_active then
    if not p_reactivate then return null; end if;
    update public.ds_clients set is_active = true, revoked_at = null where id = v_id;
  end if;
  return v_id;
end $_$;


ALTER FUNCTION "public"."fn_ds_upsert_client"("p_org" "uuid", "p_email" "text", "p_first" "text", "p_last" "text", "p_reactivate" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_enforce_active_org_membership"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_is_active boolean;
begin
  if new.organization_id is null then
    return new;
  end if;

  select is_active into v_is_active
  from public.organization_members
  where organization_id = new.organization_id and user_id = new.user_id;

  if v_is_active is not true then
    raise exception 'ORG_MEMBERSHIP_REVOKED';
  end if;

  return new;
end;
$$;


ALTER FUNCTION "public"."fn_enforce_active_org_membership"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_enforce_odometer_cycle_tier"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_premium boolean;
  v_exempt boolean;
begin
  if new.organization_id is not null then
    return new;
  end if;

  -- Natively annual, whatever the plan: Premium changes it afterwards.
  if tg_op = 'INSERT' then
    new.odometer_cycle := 'annual';
    return new;
  end if;

  if new.odometer_cycle = 'annual' or new.odometer_cycle is not distinct from old.odometer_cycle then
    return new;
  end if;

  select premium_entitled, tier_enforcement_exempt
    into v_premium, v_exempt
    from public.profiles
    where id = new.owner_user_id;

  if coalesce(v_exempt, false) or coalesce(v_premium, false) then
    return new;
  end if;

  raise exception 'PREMIUM_REQUIRED_FOR_ODOMETER_CYCLE';
end;
$$;


ALTER FUNCTION "public"."fn_enforce_odometer_cycle_tier"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_enforce_org_feature_switches"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.allow_driver_owned_vehicles and not coalesce(old.allow_driver_owned_vehicles, false)
     and not public.fn_org_feature_internal(new.id, 'owner_operators') then
    raise exception 'FEATURE_NOT_IN_PLAN';
  end if;
  if new.use_shift_schedules and not coalesce(old.use_shift_schedules, false)
     and not public.fn_org_feature_internal(new.id, 'shift_schedules') then
    raise exception 'FEATURE_NOT_IN_PLAN';
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_enforce_org_feature_switches"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_enforce_trial_or_subscription"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_created_at timestamptz;
  v_base boolean;
  v_premium boolean;
  v_exempt boolean;
begin
  -- Fleet trip: membership is checked by tr_sessions_enforce_active_org_membership.
  if new.organization_id is not null then
    return new;
  end if;

  select created_at, base_entitled, premium_entitled, tier_enforcement_exempt
    into v_created_at, v_base, v_premium, v_exempt
    from public.profiles
    where id = new.user_id;

  if v_exempt is true then
    return new;
  end if;

  if v_base is true or v_premium is true then
    return new;
  end if;

  if v_created_at is not null and now() - v_created_at > interval '15 days' then
    raise exception 'FREE_TRIAL_EXPIRED';
  end if;

  return new;
end;
$$;


ALTER FUNCTION "public"."fn_enforce_trial_or_subscription"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_enforce_vehicle_assignment_mode_tier"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.vehicle_assignment_mode = 'open'
     and new.vehicle_assignment_mode is distinct from old.vehicle_assignment_mode
     and not public.fn_org_feature_internal(new.id, 'open_assignment') then
    raise exception 'FEATURE_NOT_IN_PLAN';
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_enforce_vehicle_assignment_mode_tier"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_enforce_vehicle_count_limit"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_base boolean;
  v_premium boolean;
  v_exempt boolean;
  v_max int;
  v_current_count int;
begin
  -- Fleet vehicles (including a driver-owned truck registered with a fleet)
  -- don't count against the personal plan.
  if new.owner_user_id is null or new.organization_id is not null then
    return new;
  end if;

  select base_entitled, premium_entitled, tier_enforcement_exempt
    into v_base, v_premium, v_exempt
    from public.profiles
    where id = new.owner_user_id;

  if v_exempt is true then
    return new;
  end if;

  v_max := case when v_premium is true then 5 else 1 end;

  select count(*) into v_current_count
  from public.vehicles
  where owner_user_id = new.owner_user_id
    and organization_id is null
    and is_archived = false;

  if v_current_count >= v_max then
    raise exception 'VEHICLE_LIMIT_REACHED:%', v_max;
  end if;

  return new;
end;
$$;


ALTER FUNCTION "public"."fn_enforce_vehicle_count_limit"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_enforce_vehicle_odometer_floor"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
declare
  v_floor numeric;
begin
  if new.owner_user_id is null then
    return new;
  end if;

  if new.vin is null or btrim(new.vin) = '' then
    return new;
  end if;

  if tg_op = 'UPDATE' and new.odometer is not distinct from old.odometer then
    return new;
  end if;

  if new.odometer is null then
    return new;
  end if;

  select max(v.odometer + coalesce(s.tracked, 0))
  into v_floor
  from public.vehicles v
  left join (
    select vehicle_id, sum(total_miles) as tracked
    from public.sessions
    where vehicle_id is not null
    group by vehicle_id
  ) s on s.vehicle_id = v.id
  where v.owner_user_id = new.owner_user_id
    and v.vin = new.vin
    and v.id <> coalesce(new.id, '00000000-0000-0000-0000-000000000000'::uuid)
    and v.odometer is not null;

  if v_floor is not null and new.odometer < v_floor then
    raise exception 'ODOMETER_BELOW_FLOOR:%', v_floor;
  end if;

  return new;
end;
$$;


ALTER FUNCTION "public"."fn_enforce_vehicle_odometer_floor"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_evaluate_fuel_purchase"("p_purchase_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $_$
declare
  p public.fuel_purchases;
  v public.vehicles;
  found_kinds text[] := '{}';
  v_day_total numeric;
  v_dup boolean;
  v_points int;
  v_in_state boolean;
  v_states text;
  v_trips int;
  v_prev public.fuel_purchases;
  v_miles numeric;
  v_mpg numeric;
  v_baseline numeric;
  v_floor numeric;
  v_median_ppg numeric;
  v_samples int;
  v_checked_location boolean;
begin
  select * into p from public.fuel_purchases where id = p_purchase_id;
  if not found or p.organization_id is null then
    return;
  end if;
  select * into v from public.vehicles where id = p.vehicle_id;

  select exists (
    select 1 from public.fuel_purchases o
    where o.vehicle_id = p.vehicle_id and o.id <> p.id
      and o.created_at < p.created_at
      and (o.file_hash = p.file_hash
           or (o.purchase_date = p.purchase_date and abs(o.gallons - p.gallons) < 0.01))
  ) into v_dup;
  if v_dup then
    found_kinds := array_append(found_kinds, 'duplicate');
    insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
    values (p.organization_id, p.id, p.vehicle_id, 'duplicate', 'high',
      format('Looks like a duplicate: another receipt for this vehicle has the same %s.',
        case when exists (select 1 from public.fuel_purchases o where o.vehicle_id = p.vehicle_id and o.id <> p.id and o.created_at < p.created_at and o.file_hash = p.file_hash)
             then 'photo' else 'date and gallons' end),
      jsonb_build_object('gallons', p.gallons))
    on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
  end if;

  if v.fuel_tank_capacity_gal is not null then
    select sum(gallons) into v_day_total from public.fuel_purchases
    where vehicle_id = p.vehicle_id and purchase_date = p.purchase_date
      and created_at <= p.created_at;
    if v_day_total > v.fuel_tank_capacity_gal * 1.05 then
      found_kinds := array_append(found_kinds, 'over_capacity');
      insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
      values (p.organization_id, p.id, p.vehicle_id, 'over_capacity', 'high',
        format('%s gal bought on %s, but the tank holds %s gal.',
          round(v_day_total, 1), p.purchase_date, round(v.fuel_tank_capacity_gal, 1)),
        jsonb_build_object('day_gallons', v_day_total, 'tank_gallons', v.fuel_tank_capacity_gal))
      on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
    end if;
  end if;

  v_checked_location := p.purchase_date < (now() at time zone 'utc')::date;
  if v_checked_location then
    select count(*) into v_points from public.session_gps_breadcrumbs b
    where b.vehicle_id = p.vehicle_id
      and b.recorded_at >= (p.purchase_date - 1)::timestamptz
      and b.recorded_at < (p.purchase_date + 2)::timestamptz;

    select count(*) into v_trips from public.sessions s
    where s.vehicle_id = p.vehicle_id
      and s.date_key between p.purchase_date - 1 and p.purchase_date + 1;

    if v_points = 0 and v_trips = 0 then
      found_kinds := array_append(found_kinds, 'no_trip');
      insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
      values (p.organization_id, p.id, p.vehicle_id, 'no_trip', 'medium',
        format('No trips were recorded for this vehicle between %s and %s.', p.purchase_date - 1, p.purchase_date + 1),
        '{}'::jsonb)
      on conflict (purchase_id, kind) do update set detail = excluded.detail;
    elsif v_points > 0 and p.state_code is not null then
      with pts as (
        select b.latitude, b.longitude,
               row_number() over (order by b.recorded_at) rn, count(*) over () n
        from public.session_gps_breadcrumbs b
        where b.vehicle_id = p.vehicle_id
          and b.recorded_at >= (p.purchase_date - 1)::timestamptz
          and b.recorded_at < (p.purchase_date + 2)::timestamptz
      ),
      sampled as (select * from pts where rn % greatest(1, n / 500) = 0),
      visited as (
        select distinct sb.state_code from sampled s
        join public.ifta_us_state_boundaries sb
          on ST_Contains(sb.geom, ST_SetSRID(ST_MakePoint(s.longitude, s.latitude), 4326))
      )
      select bool_or(state_code = p.state_code), string_agg(state_code, ', ' order by state_code)
      into v_in_state, v_states from visited;

      if v_states is not null and not coalesce(v_in_state, false) then
        found_kinds := array_append(found_kinds, 'location_mismatch');
        insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
        values (p.organization_id, p.id, p.vehicle_id, 'location_mismatch', 'high',
          format('Receipt says %s, but the vehicle''s GPS around %s was only in %s.', p.state_code, p.purchase_date, v_states),
          jsonb_build_object('receipt_state', p.state_code, 'gps_states', v_states))
        on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
      end if;
    end if;
  end if;

  select * into v_prev from public.fuel_purchases o
  where o.vehicle_id = p.vehicle_id and o.id <> p.id
    and (o.purchase_date < p.purchase_date
         or (o.purchase_date = p.purchase_date and o.created_at < p.created_at))
  order by o.purchase_date desc, o.created_at desc
  limit 1;

  if v_prev.id is not null and p.gallons >= 5 and v_checked_location then
    select coalesce(sum(s.total_miles), 0) into v_miles from public.sessions s
    where s.vehicle_id = p.vehicle_id
      and s.date_key > v_prev.purchase_date and s.date_key <= p.purchase_date;

    if v_miles < 1 and p.purchase_date > v_prev.purchase_date then
      found_kinds := array_append(found_kinds, 'no_miles');
      insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
      values (p.organization_id, p.id, p.vehicle_id, 'no_miles', 'high',
        format('%s gal bought, but no miles were driven since the last fill-up on %s.', round(p.gallons, 1), v_prev.purchase_date),
        jsonb_build_object('gallons', p.gallons, 'previous_purchase_date', v_prev.purchase_date))
      on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
    elsif v_miles >= 1 then
      v_mpg := v_miles / p.gallons;
      with fills as (
        select o.purchase_date, o.gallons,
               lag(o.purchase_date) over (order by o.purchase_date, o.created_at) prev_date
        from public.fuel_purchases o
        where o.vehicle_id = p.vehicle_id
          and o.purchase_date between p.purchase_date - 180 and p.purchase_date
          and o.id <> p.id
      ),
      intervals as (
        select (select sum(s.total_miles) from public.sessions s
                where s.vehicle_id = p.vehicle_id and s.date_key > f.prev_date and s.date_key <= f.purchase_date) / f.gallons as mpg
        from fills f
        where f.prev_date is not null and f.gallons >= 5
      )
      select percentile_cont(0.5) within group (order by mpg), count(*)
      into v_baseline, v_samples
      from intervals where mpg > 0;

      v_floor := case when coalesce(v.ifta_fuel_type, p.fuel_type) = 'gasoline' then 8 else 3.5 end;
      if (v_samples >= 3 and v_mpg < v_baseline * 0.6) or v_mpg < v_floor then
        found_kinds := array_append(found_kinds, 'low_mpg');
        insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
        values (p.organization_id, p.id, p.vehicle_id, 'low_mpg', 'medium',
          case when v_samples >= 3
            then format('%s MPG since the last fill-up (%s mi on %s gal) — this vehicle normally does %s MPG.',
                   round(v_mpg, 1), round(v_miles), round(p.gallons, 1), round(v_baseline, 1))
            else format('%s MPG since the last fill-up (%s mi on %s gal) — unusually low.',
                   round(v_mpg, 1), round(v_miles), round(p.gallons, 1))
          end,
          jsonb_build_object('mpg', round(v_mpg, 2), 'miles', round(v_miles, 1), 'gallons', p.gallons,
                             'baseline_mpg', round(v_baseline, 2), 'samples', v_samples))
        on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
      end if;
    end if;
  end if;

  if p.price_per_gallon_usd is not null and p.total_cost_usd is not null
     and abs(p.gallons * p.price_per_gallon_usd - p.total_cost_usd) > greatest(1, p.total_cost_usd * 0.02) then
    found_kinds := array_append(found_kinds, 'price_mismatch');
    insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
    values (p.organization_id, p.id, p.vehicle_id, 'price_mismatch', 'low',
      format('%s gal × $%s = $%s, but the receipt total is $%s.',
        round(p.gallons, 3), round(p.price_per_gallon_usd, 3),
        round(p.gallons * p.price_per_gallon_usd, 2), round(p.total_cost_usd, 2)),
      jsonb_build_object('expected_total', round(p.gallons * p.price_per_gallon_usd, 2), 'receipt_total', p.total_cost_usd))
    on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
  end if;

  if p.price_per_gallon_usd is not null then
    select percentile_cont(0.5) within group (order by o.price_per_gallon_usd), count(*)
    into v_median_ppg, v_samples
    from public.fuel_purchases o
    where o.organization_id = p.organization_id and o.id <> p.id
      and o.fuel_type = p.fuel_type and o.price_per_gallon_usd > 0
      and o.purchase_date between p.purchase_date - 60 and p.purchase_date + 60;
    if v_samples >= 5 and p.price_per_gallon_usd > v_median_ppg * 1.25 then
      found_kinds := array_append(found_kinds, 'price_high');
      insert into public.fuel_anomalies (organization_id, purchase_id, vehicle_id, kind, severity, detail, metrics)
      values (p.organization_id, p.id, p.vehicle_id, 'price_high', 'low',
        format('$%s/gal, %s%% above the fleet''s usual $%s/gal for %s.',
          round(p.price_per_gallon_usd, 3), round((p.price_per_gallon_usd / v_median_ppg - 1) * 100),
          round(v_median_ppg, 3), p.fuel_type),
        jsonb_build_object('price', p.price_per_gallon_usd, 'median_price', round(v_median_ppg, 3)))
      on conflict (purchase_id, kind) do update set detail = excluded.detail, metrics = excluded.metrics;
    end if;
  end if;

  delete from public.fuel_anomalies a
  where a.purchase_id = p.id and a.status = 'open' and not (a.kind = any (found_kinds));
end;
$_$;


ALTER FUNCTION "public"."fn_evaluate_fuel_purchase"("p_purchase_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_fold_empty_trip_sections"("p_session_id" "uuid") RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  r record;
  v_keep uuid;
  v_folded integer := 0;
begin
  for r in
    select id, start_time
      from public.session_sections
     where session_id = p_session_id
       and coalesce(total_miles, 0) < 0.05
       and section_status in ('closed', 'switched')
       and nullif(btrim(coalesce(notes, '')), '') is null
       and start_odometer_image_url is null
       and end_odometer_image_url is null
  loop
    select k.id into v_keep
      from public.session_sections k
     where k.session_id = p_session_id
       and coalesce(k.total_miles, 0) >= 0.05
     order by (k.start_time <= r.start_time) desc,
              abs(extract(epoch from (k.start_time - r.start_time)))
     limit 1;

    continue when v_keep is null;

    update public.audit_events set section_id = v_keep where section_id = r.id;
    update public.session_gps_breadcrumbs set section_id = v_keep where section_id = r.id;
    delete from public.session_sections where id = r.id;
    v_folded := v_folded + 1;
  end loop;
  return v_folded;
end;
$$;


ALTER FUNCTION "public"."fn_fold_empty_trip_sections"("p_session_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_freeze_closed_route"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if current_setting('cm.account_deletion', true) is not distinct from 'on' then
    return NEW;
  end if;
  if OLD.status = 'closed' then
    raise exception 'Cannot modify a closed route';
  end if;
  if NEW.status = 'closed' and OLD.status is distinct from 'closed' then
    NEW.closed_at := now();
  end if;
  return NEW;
end;
$$;


ALTER FUNCTION "public"."fn_freeze_closed_route"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_freeze_closed_session"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
begin
  if OLD.is_closed = true then
    if OLD.cgc_sealed_at is null
       and NEW.cgc_sealed_at is not null
       and (to_jsonb(NEW) - 'cgc_decision_id' - 'cgc_sealed_at' - 'updated_at')
         = (to_jsonb(OLD) - 'cgc_decision_id' - 'cgc_sealed_at' - 'updated_at') then
      return NEW;
    end if;
    if OLD.vehicle_id is null
       and NEW.vehicle_id is not null
       and OLD.cgc_sealed_at is null
       and OLD.organization_id is null
       and coalesce(current_setting('cm.assign_trip_vehicle', true), '') = 'on'
       and (to_jsonb(NEW) - 'vehicle_id' - 'updated_at')
         = (to_jsonb(OLD) - 'vehicle_id' - 'updated_at') then
      return NEW;
    end if;
    if OLD.cgc_sealed_at is null
       and coalesce(current_setting('cm.section_delete', true), '') = 'on'
       and (to_jsonb(NEW) - 'total_miles' - 'total_duration_seconds' - 'start_time' - 'end_time' - 'updated_at')
         = (to_jsonb(OLD) - 'total_miles' - 'total_duration_seconds' - 'start_time' - 'end_time' - 'updated_at') then
      return NEW;
    end if;
    raise exception 'Cannot modify a closed session';
  end if;
  return NEW;
end;
$$;


ALTER FUNCTION "public"."fn_freeze_closed_session"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_freeze_closed_session_section"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if OLD.section_status in ('closed', 'switched') then
    if NEW.total_miles is distinct from OLD.total_miles
      or NEW.total_duration_seconds is distinct from OLD.total_duration_seconds
      or NEW.start_time is distinct from OLD.start_time
      or NEW.end_time is distinct from OLD.end_time
      or NEW.gig_app is distinct from OLD.gig_app
      or NEW.start_latitude is distinct from OLD.start_latitude
      or NEW.start_longitude is distinct from OLD.start_longitude
      or NEW.end_latitude is distinct from OLD.end_latitude
      or NEW.end_longitude is distinct from OLD.end_longitude
      or NEW.session_id is distinct from OLD.session_id
      or NEW.user_id is distinct from OLD.user_id
      or NEW.organization_id is distinct from OLD.organization_id
      or (OLD.route_polyline is not null and NEW.route_polyline is distinct from OLD.route_polyline)
    then
      raise exception 'Cannot modify a closed trip section''s recorded data';
    end if;
    -- Gig history: the phone may fill an empty address once, and the driver may correct
    -- where the trip ended (its last segment, the only one left 'closed'). Nothing else.
    if OLD.organization_id is null and OLD.gig_app <> 'custom' and (
      NEW.irs_purpose is distinct from OLD.irs_purpose
      or NEW.notes is distinct from OLD.notes
      or (OLD.start_address is not null and NEW.start_address is distinct from OLD.start_address)
      or (OLD.section_status = 'switched' and (
        NEW.address_edited is distinct from OLD.address_edited
        or (OLD.end_address is not null and NEW.end_address is distinct from OLD.end_address)
      ))
    ) then
      raise exception 'Gig trip history cannot be edited';
    end if;
  end if;
  return NEW;
end;
$$;


ALTER FUNCTION "public"."fn_freeze_closed_session_section"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_freeze_profile_display_id"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if OLD.display_id is not null and NEW.display_id is distinct from OLD.display_id then
    raise exception 'display_id cannot be changed once assigned';
  end if;
  return NEW;
end;
$$;


ALTER FUNCTION "public"."fn_freeze_profile_display_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_freeze_started_shift_block"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if current_setting('cm.shift_block_rpc', true) is not distinct from 'on'
     or current_setting('cm.account_deletion', true) is not distinct from 'on' then
    return new;
  end if;
  if old.status = 'scheduled' then
    return new;
  end if;
  if old.status = 'cancelled' and new.status = 'scheduled'
     and (new.driver_id, new.vehicle_id, new.block_date, new.start_time, new.end_time, new.note)
         is not distinct from
         (old.driver_id, old.vehicle_id, old.block_date, old.start_time, old.end_time, old.note) then
    return new;
  end if;
  raise exception 'A class that already started cannot be edited';
end $$;


ALTER FUNCTION "public"."fn_freeze_started_shift_block"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_freeze_vehicle_display_id"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if OLD.display_id is not null and NEW.display_id is distinct from OLD.display_id then
    raise exception 'display_id cannot be changed once assigned';
  end if;
  return NEW;
end;
$$;


ALTER FUNCTION "public"."fn_freeze_vehicle_display_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_fuel_purchase_evaluate_trigger"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_next uuid;
begin
  -- A failing check must never block a driver from logging a receipt:
  -- errors are logged and the nightly re-check tries again.
  begin
    perform public.fn_evaluate_fuel_purchase(new.id);
    select o.id into v_next from public.fuel_purchases o
    where o.vehicle_id = new.vehicle_id and o.id <> new.id
      and (o.purchase_date > new.purchase_date
           or (o.purchase_date = new.purchase_date and o.created_at > new.created_at))
    order by o.purchase_date, o.created_at
    limit 1;
    if v_next is not null then
      perform public.fn_evaluate_fuel_purchase(v_next);
    end if;
  exception when others then
    raise warning 'fuel anomaly check failed for %: %', new.id, sqlerrm;
  end;
  return null;
end;
$$;


ALTER FUNCTION "public"."fn_fuel_purchase_evaluate_trigger"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_guard_maintenance_tenant"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v record;
begin
  select owner_user_id, organization_id into v from public.vehicles where id = new.vehicle_id;
  if not found
     or not (coalesce(v.owner_user_id = new.user_id, false)
             or exists (select 1 from public.organization_members m
                         where m.organization_id = v.organization_id and m.user_id = new.user_id and m.is_active)) then
    raise exception 'VEHICLE_NOT_YOURS' using errcode = 'P0001';
  end if;
  new.organization_id := v.organization_id;
  return new;
end $$;


ALTER FUNCTION "public"."fn_guard_maintenance_tenant"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_guard_org_billing_columns"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if current_user not in ('authenticated', 'anon') then
    return new;
  end if;

  if tg_op = 'INSERT' then
    new.created_by := auth.uid();
    new.created_at := now();
    new.tier_enforcement_exempt := false;
    new.stripe_customer_id := null;
    new.stripe_subscription_id := null;
    new.subscription_tier := null;
    new.subscription_status := null;
    new.subscription_vehicle_count := null;
    new.subscription_updated_at := null;
    new.fleet_type_confirmed_at := null;
    new.service_acquired_at := null;
    new.service_acquisition_cents := null;
    new.service_acquisition_tier := null;
    return new;
  end if;

  if new.id is distinct from old.id
     or new.created_by is distinct from old.created_by
     or new.created_at is distinct from old.created_at
     or new.tier_enforcement_exempt is distinct from old.tier_enforcement_exempt
     or new.stripe_customer_id is distinct from old.stripe_customer_id
     or new.stripe_subscription_id is distinct from old.stripe_subscription_id
     or new.subscription_tier is distinct from old.subscription_tier
     or new.subscription_status is distinct from old.subscription_status
     or new.subscription_vehicle_count is distinct from old.subscription_vehicle_count
     or new.subscription_updated_at is distinct from old.subscription_updated_at
     or new.industry_template is distinct from old.industry_template
     or new.fleet_type_confirmed_at is distinct from old.fleet_type_confirmed_at
     or new.service_acquired_at is distinct from old.service_acquired_at
     or new.service_acquisition_cents is distinct from old.service_acquisition_cents
     or new.service_acquisition_tier is distinct from old.service_acquisition_tier
  then
    raise exception 'PROTECTED_ORG_COLUMN: this field cannot be changed directly';
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_guard_org_billing_columns"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_guard_profile_protected_columns"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if current_user in ('authenticated', 'anon') then
    if new.id                     is distinct from old.id
       or new.display_id          is distinct from old.display_id
       or new.email               is distinct from old.email
       or new.account_type        is distinct from old.account_type
       or new.is_active           is distinct from old.is_active
       or new.default_org_id      is distinct from old.default_org_id
       or new.base_entitled       is distinct from old.base_entitled
       or new.premium_entitled    is distinct from old.premium_entitled
       or new.multi_org_entitled  is distinct from old.multi_org_entitled
       or new.tier_enforcement_exempt is distinct from old.tier_enforcement_exempt
       or new.created_at          is distinct from old.created_at
       or new.legal_accepted_at   is distinct from old.legal_accepted_at
       or new.legal_terms_version is distinct from old.legal_terms_version
    then
      raise exception 'PROTECTED_PROFILE_COLUMN: this field cannot be changed directly';
    end if;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_guard_profile_protected_columns"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_guard_session_tenant"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v record;
begin
  if tg_op = 'UPDATE' then
    if new.user_id is distinct from old.user_id or new.organization_id is distinct from old.organization_id then
      raise exception 'TRIP_OWNER_LOCKED' using errcode = 'P0001';
    end if;
    if new.vehicle_id is not distinct from old.vehicle_id then
      return new;
    end if;
  end if;

  if new.vehicle_id is not null then
    select owner_user_id, organization_id into v from public.vehicles where id = new.vehicle_id;
    -- coalesce: a company vehicle has no owner_user_id, and a null here
    -- would let the check pass.
    if not found
       or not coalesce((new.organization_id is null and v.owner_user_id = new.user_id)
                       or (new.organization_id is not null and v.organization_id = new.organization_id), false) then
      raise exception 'VEHICLE_NOT_YOURS' using errcode = 'P0001';
    end if;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_guard_session_tenant"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_inherit_session_tenant"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  s record;
begin
  select user_id, organization_id, is_closed into s from public.sessions where id = new.session_id;
  if not found or s.user_id is distinct from new.user_id then
    raise exception 'TRIP_NOT_YOURS' using errcode = 'P0001';
  end if;
  if tg_op = 'INSERT' and s.is_closed is true then
    raise exception 'TRIP_ALREADY_CLOSED' using errcode = 'P0001';
  end if;
  new.organization_id := s.organization_id;
  return new;
end $$;


ALTER FUNCTION "public"."fn_inherit_session_tenant"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_invite_unconfirmed_user"("p_email" "text") RETURNS TABLE("user_id" "uuid", "confirmed" boolean)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select u.id, (u.email_confirmed_at is not null)
    from auth.users u
   where lower(u.email) = lower(coalesce(p_email, ''))
   limit 1;
$$;


ALTER FUNCTION "public"."fn_invite_unconfirmed_user"("p_email" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_is_org_creator"("p_organization_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select exists (select 1 from public.organizations where id = p_organization_id and created_by = auth.uid());
$$;


ALTER FUNCTION "public"."fn_is_org_creator"("p_organization_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_latest_inspection_id"("p_vehicle_id" "uuid") RETURNS "uuid"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select id from public.vehicle_inspections
  where vehicle_id = p_vehicle_id
  order by created_at desc
  limit 1;
$$;


ALTER FUNCTION "public"."fn_latest_inspection_id"("p_vehicle_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_link_session_to_shift_block"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.shift_block_id is null then
    return new;
  end if;
  if not exists (
    select 1 from public.shift_blocks b
    where b.id = new.shift_block_id and b.driver_id = new.user_id and b.status = 'in_progress'
  ) then
    raise exception 'This class is not in progress';
  end if;
  perform set_config('cm.shift_block_rpc', 'on', true);
  update public.shift_blocks set session_id = new.id where id = new.shift_block_id;
  perform set_config('cm.shift_block_rpc', 'off', true);
  return new;
end $$;


ALTER FUNCTION "public"."fn_link_session_to_shift_block"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_meters_between"("lat1" double precision, "lon1" double precision, "lat2" double precision, "lon2" double precision) RETURNS double precision
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  select 6371000 * acos(least(1.0, greatest(-1.0,
    cos(radians(lat1)) * cos(radians(lat2)) * cos(radians(lon2) - radians(lon1)) +
    sin(radians(lat1)) * sin(radians(lat2)))));
$$;


ALTER FUNCTION "public"."fn_meters_between"("lat1" double precision, "lon1" double precision, "lat2" double precision, "lon2" double precision) OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."route_runs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "route_id" "uuid" NOT NULL,
    "run_date" "date" NOT NULL,
    "driver_id" "uuid",
    "vehicle_id" "uuid",
    "session_id" "uuid",
    "status" "text" DEFAULT 'in_progress'::"text" NOT NULL,
    "started_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "completed_at" timestamp with time zone,
    "child_check_at" timestamp with time zone,
    "child_check_latitude" double precision,
    "child_check_longitude" double precision,
    "monitor_name" "text",
    "monitor_id" "uuid",
    CONSTRAINT "route_runs_monitor_name_check" CHECK ((("monitor_name" IS NULL) OR ("length"("monitor_name") <= 80))),
    CONSTRAINT "route_runs_status_check" CHECK (("status" = ANY (ARRAY['in_progress'::"text", 'completed'::"text"])))
);


ALTER TABLE "public"."route_runs" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_my_crew_run"("p_run_id" "uuid") RETURNS "public"."route_runs"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare v_run public.route_runs%rowtype;
begin
  select * into v_run from public.route_runs where id = p_run_id;
  if not found or (
    v_run.driver_id is distinct from auth.uid()
    and not exists (select 1 from public.fn_route_crew(v_run.route_id, v_run.run_date) c where c.monitor_id = auth.uid())
  ) then
    raise exception 'ROUTE_NOT_ASSIGNED';
  end if;
  perform public.fn_require_org_feature(v_run.organization_id, 'school');
  if v_run.status <> 'in_progress' then
    raise exception 'ROUTE_ALREADY_COMPLETED';
  end if;
  return v_run;
end $$;


ALTER FUNCTION "public"."fn_my_crew_run"("p_run_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_my_open_run"("p_run_id" "uuid") RETURNS "public"."route_runs"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare v_run public.route_runs%rowtype;
begin
  select * into v_run from public.route_runs where id = p_run_id;
  if not found or v_run.driver_id is distinct from auth.uid() then
    raise exception 'ROUTE_NOT_ASSIGNED';
  end if;
  perform public.fn_require_org_feature(v_run.organization_id, 'school');
  if v_run.status <> 'in_progress' then
    raise exception 'ROUTE_ALREADY_COMPLETED';
  end if;
  return v_run;
end $$;


ALTER FUNCTION "public"."fn_my_open_run"("p_run_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_notify_trip_safety"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_hb int; v_ha int; v_sp int;
begin
  if new.organization_id is null or not new.is_closed or coalesce(old.is_closed, false) then
    return null;
  end if;
  if not public.fn_org_feature_internal(new.organization_id, 'safety_scores') then
    return null;
  end if;
  begin
    select count(*) filter (where event_type = 'harsh_braking'),
           count(*) filter (where event_type = 'hard_acceleration'),
           count(*) filter (where event_type = 'speeding')
    into v_hb, v_ha, v_sp
    from public.driver_safety_events
    where session_id = new.id;
    if v_hb + v_ha + v_sp > 0 then
      insert into public.driver_notifications (user_id, organization_id, kind, session_id, data)
      values (new.user_id, new.organization_id, 'trip_safety', new.id,
              jsonb_build_object('harsh_braking', v_hb, 'hard_acceleration', v_ha, 'speeding', v_sp,
                                 'miles', round(coalesce(new.total_miles, 0)::numeric, 1),
                                 'trip_date', coalesce(new.date_key, new.start_time::date)))
      on conflict do nothing;
    end if;
  exception when others then
    raise warning 'trip safety notification failed for %: %', new.id, sqlerrm;
  end;
  return null;
end;
$$;


ALTER FUNCTION "public"."fn_notify_trip_safety"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_odometer_cycle_start"("p_vehicle_id" "uuid", "p_date" "date") RETURNS "date"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_vehicle record;
  v_anchor date;
begin
  select * into v_vehicle from public.vehicles where id = p_vehicle_id;
  if v_vehicle is null then
    return null;
  end if;

  if v_vehicle.owner_user_id is distinct from auth.uid()
     and v_vehicle.assigned_driver_id is distinct from auth.uid()
     and not (v_vehicle.organization_id is not null and public.is_org_member(v_vehicle.organization_id))
  then
    return null;
  end if;

  v_anchor := coalesce(
    v_vehicle.odometer_cycle_anchor,
    (v_vehicle.created_at::date) - (extract(isodow from v_vehicle.created_at::date)::int - 1)
  );

  return public.fn_odometer_period_start(
    coalesce(v_vehicle.odometer_cycle, 'weekly'), p_date, v_anchor
  );
end;
$$;


ALTER FUNCTION "public"."fn_odometer_cycle_start"("p_vehicle_id" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_odometer_period_start"("p_cycle" "text", "p_date" "date", "p_anchor" "date") RETURNS "date"
    LANGUAGE "sql" STABLE
    SET "search_path" TO 'public'
    AS $$
  select case p_cycle
    when 'annual' then date_trunc('year', p_date)::date
    when 'daily' then p_date
    when 'monthly' then date_trunc('month', p_date)::date
    when 'semimonthly' then
      case when extract(day from p_date) >= 15
           then date_trunc('month', p_date)::date + 14
           else date_trunc('month', p_date)::date end
    when 'weekly' then p_date - (extract(isodow from p_date)::int - 1)
    else
      (p_anchor - (extract(isodow from p_anchor)::int - 1))
      + (floor(
          ((p_date - (extract(isodow from p_date)::int - 1))
           - (p_anchor - (extract(isodow from p_anchor)::int - 1))) / 14.0
        )::int * 14)
  end
$$;


ALTER FUNCTION "public"."fn_odometer_period_start"("p_cycle" "text", "p_date" "date", "p_anchor" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_billable_vehicles"("p_org_id" "uuid") RETURNS integer
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select greatest(count(*)::int, 1)
    from public.vehicles
   where organization_id = p_org_id and not coalesce(is_archived, false);
$$;


ALTER FUNCTION "public"."fn_org_billable_vehicles"("p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_branch_allowance"("p_org" "uuid") RETURNS TABLE("included" integer, "max_branches" integer, "extra_price_cents" integer, "active" integer)
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_member(p_org) then raise exception 'Not authorized'; end if;
  return query select * from public.fn_org_branch_allowance_internal(p_org);
end $$;


ALTER FUNCTION "public"."fn_org_branch_allowance"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_branch_allowance_internal"("p_org" "uuid") RETURNS TABLE("included" integer, "max_branches" integer, "extra_price_cents" integer, "active" integer)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  with o as (
    select o.id, o.tier_enforcement_exempt from public.organizations o where o.id = p_org
  ), t as (
    select case
             when (select tier_enforcement_exempt from o) or public.fn_org_enterprise_internal(p_org) then 'enterprise'
             else public.fn_org_tier_internal(p_org)
           end as tier
  )
  select case when t.tier = 'none' then 1 else p.included_branches end,
         case when t.tier = 'none' then 1 else p.max_branches end,
         case when t.tier = 'none' then null else p.extra_branch_cents end,
         (select count(*)::int from public.branches b where b.organization_id = p_org and not b.is_archived)
    from o
    cross join t
    left join public.fleet_plans p on p.tier = t.tier;
$$;


ALTER FUNCTION "public"."fn_org_branch_allowance_internal"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_driving_school_cycle"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.industry_template = 'driving_school'
     and new.industry_template is distinct from old.industry_template then
    update public.vehicles
    set odometer_cycle = 'monthly'
    where organization_id = new.id and odometer_cycle <> 'monthly';
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_org_driving_school_cycle"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_effective_tier"("p_org_id" "uuid") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_member(p_org_id) then
    return 'none';
  end if;
  return public.fn_org_tier_internal(p_org_id);
end;
$$;


ALTER FUNCTION "public"."fn_org_effective_tier"("p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_enterprise_internal"("p_org_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select coalesce((
    select o.tier_enforcement_exempt
        or (o.subscription_status in ('active', 'trialing', 'past_due') and o.subscription_tier = 'enterprise')
    from public.organizations o where o.id = p_org_id
  ), false);
$$;


ALTER FUNCTION "public"."fn_org_enterprise_internal"("p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_feature_internal"("p_org_id" "uuid", "p_feature" "text") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select p_feature = any(public.fn_org_feature_list_internal(p_org_id));
$$;


ALTER FUNCTION "public"."fn_org_feature_internal"("p_org_id" "uuid", "p_feature" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_feature_list_internal"("p_org_id" "uuid") RETURNS "text"[]
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
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
$$;


ALTER FUNCTION "public"."fn_org_feature_list_internal"("p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_features"("p_org_id" "uuid") RETURNS "text"[]
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select case when public.is_org_member(p_org_id)
              then public.fn_org_feature_list_internal(p_org_id)
              else '{}'::text[] end;
$$;


ALTER FUNCTION "public"."fn_org_features"("p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_fleet_template_to_vehicles"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  update public.vehicles set fleet_template = new.industry_template
   where organization_id = new.id and fleet_template is distinct from new.industry_template;
  return null;
end $$;


ALTER FUNCTION "public"."fn_org_fleet_template_to_vehicles"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_has_classes"("p_org" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select public.fn_org_feature_internal(p_org, 'classes');
$$;


ALTER FUNCTION "public"."fn_org_has_classes"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_has_feature"("p_org_id" "uuid", "p_feature" "text") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select public.is_org_member(p_org_id) and public.fn_org_feature_internal(p_org_id, p_feature);
$$;


ALTER FUNCTION "public"."fn_org_has_feature"("p_org_id" "uuid", "p_feature" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_local_today"("p_org" "uuid") RETURNS "date"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select (now() at time zone o.timezone)::date from public.organizations o where o.id = p_org;
$$;


ALTER FUNCTION "public"."fn_org_local_today"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_tier_internal"("p_org_id" "uuid") RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select coalesce((
    select case
      when o.tier_enforcement_exempt then 'growth'
      when o.subscription_status in ('active', 'trialing', 'past_due') and o.subscription_tier in ('growth', 'enterprise') then 'growth'
      when o.subscription_status in ('active', 'trialing', 'past_due') and o.subscription_tier = 'starter' then 'starter'
      when now() - o.created_at <= interval '15 days' then 'growth'
      else 'none'
    end
    from public.organizations o
    where o.id = p_org_id
  ), 'none');
$$;


ALTER FUNCTION "public"."fn_org_tier_internal"("p_org_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_org_today"("p_org" "uuid") RETURNS "date"
    LANGUAGE "sql" STABLE
    SET "search_path" TO 'public'
    AS $$
  select (now() at time zone coalesce((select timezone from public.organizations where id = p_org), 'America/New_York'))::date;
$$;


ALTER FUNCTION "public"."fn_org_today"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_plan_features"("p_template" "text", "p_plan_rank" integer) RETURNS "text"[]
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select coalesce(array_agg(distinct r.feature order by r.feature), '{}'::text[])
    from public.plan_feature_rules r
   where p_template is not null
     and p_plan_rank >= case r.min_plan when 'starter' then 1 when 'growth' then 2 else 3 end
     and (r.templates is null or p_template = any (r.templates));
$$;


ALTER FUNCTION "public"."fn_plan_features"("p_template" "text", "p_plan_rank" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_profile_requires_pretrip"("p" "text") RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  select p in ('general', 'trucking', 'construction', 'passenger', 'driving_school', 'school_transport');
$$;


ALTER FUNCTION "public"."fn_profile_requires_pretrip"("p" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_reevaluate_recent_fuel_purchases"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  r record;
  n integer := 0;
begin
  for r in
    select id from public.fuel_purchases
    where organization_id is not null
      and purchase_date >= (now() at time zone 'utc')::date - 14
  loop
    begin
      perform public.fn_evaluate_fuel_purchase(r.id);
      n := n + 1;
    exception when others then
      raise warning 'fuel anomaly check failed for %: %', r.id, sqlerrm;
    end;
  end loop;
  return n;
end;
$$;


ALTER FUNCTION "public"."fn_reevaluate_recent_fuel_purchases"() OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."regular_trips" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "start_any" boolean DEFAULT false NOT NULL,
    "start_latitude" double precision,
    "start_longitude" double precision,
    "start_address" "text",
    "end_latitude" double precision NOT NULL,
    "end_longitude" double precision NOT NULL,
    "end_address" "text",
    "purpose" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "regular_trips_check" CHECK (("start_any" OR (("start_latitude" IS NOT NULL) AND ("start_longitude" IS NOT NULL)))),
    CONSTRAINT "regular_trips_end_address_check" CHECK (("char_length"("end_address") <= 300)),
    CONSTRAINT "regular_trips_purpose_check" CHECK (("purpose" = ANY (ARRAY['business'::"text", 'delivery'::"text", 'errand'::"text", 'client'::"text", 'travel'::"text", 'work'::"text", 'medical'::"text", 'charitable'::"text", 'moving'::"text", 'education'::"text", 'personal'::"text"]))),
    CONSTRAINT "regular_trips_start_address_check" CHECK (("char_length"("start_address") <= 300))
);


ALTER TABLE "public"."regular_trips" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_regular_trip_covers"("r" "public"."regular_trips", "start_lat" double precision, "start_lng" double precision, "end_lat" double precision, "end_lng" double precision) RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  select end_lat is not null and end_lng is not null
    and public.fn_cm_distance_m(r.end_latitude, r.end_longitude, end_lat, end_lng) <= 150
    and (r.start_any or (
      start_lat is not null and start_lng is not null
      and public.fn_cm_distance_m(r.start_latitude, r.start_longitude, start_lat, start_lng) <= 150
    ));
$$;


ALTER FUNCTION "public"."fn_regular_trip_covers"("r" "public"."regular_trips", "start_lat" double precision, "start_lng" double precision, "end_lat" double precision, "end_lng" double precision) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_require_org_feature"("p_org_id" "uuid", "p_feature" "text") RETURNS "void"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if p_org_id is null or not public.fn_org_feature_internal(p_org_id, p_feature) then
    raise exception 'FEATURE_NOT_IN_PLAN';
  end if;
end;
$$;


ALTER FUNCTION "public"."fn_require_org_feature"("p_org_id" "uuid", "p_feature" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_retire_display_id"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if old.display_id is not null and btrim(old.display_id) <> '' then
    insert into public.retired_display_ids (display_id, kind) values (old.display_id, tg_argv[0])
    on conflict (display_id) do update set retired_at = now(), kind = excluded.kind;
  end if;
  return old;
end;
$$;


ALTER FUNCTION "public"."fn_retire_display_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ride_notice_applies"("p_student_id" "uuid", "p_date" "date", "p_route_type" "text") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select exists (
    select 1 from public.student_ride_notices n
     where n.student_id = p_student_id and n.notice_date = p_date
       and n.part in ('both', case when p_route_type = 'school_pm' then 'pm' else 'am' end)
  );
$$;


ALTER FUNCTION "public"."fn_ride_notice_applies"("p_student_id" "uuid", "p_date" "date", "p_route_type" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_ride_notice_role"("p_student_id" "uuid") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.students where id = p_student_id and is_active;
  if v_org is null then raise exception 'Student not found'; end if;
  if public.is_org_operator_or_above(v_org) then return 'staff'; end if;
  if exists (
    select 1
      from public.school_guardians g
      join public.student_guardians sg on sg.guardian_id = g.id and sg.is_active
     where g.user_id = auth.uid() and g.is_active and sg.student_id = p_student_id
  ) then return 'guardian'; end if;
  raise exception 'Not authorized';
end $$;


ALTER FUNCTION "public"."fn_ride_notice_role"("p_student_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_rider_status"("p_route_id" "uuid", "p_run_id" "uuid", "p_stop_id" "uuid", "p_student" "uuid", "p_action" "text") RETURNS "text"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_route public.routes%rowtype;
  v_date date;
  v_due boolean;
  v_done boolean;
  v_boarded boolean;
  v_released boolean;
begin
  select * into v_route from public.routes where id = p_route_id;
  v_date := coalesce((select run_date from public.route_runs where id = p_run_id),
                     public.fn_org_today(v_route.organization_id));
  v_due := public.fn_stop_due(p_run_id, p_stop_id);
  v_done := p_run_id is not null and exists (
    select 1 from public.ridership_events where run_id = p_run_id and student_id = p_student and action = p_action);
  v_boarded := p_run_id is not null and exists (
    select 1 from public.ridership_events where run_id = p_run_id and student_id = p_student and action = 'board');
  v_released := p_run_id is not null and exists (
    select 1 from public.ridership_events where run_id = p_run_id and student_id = p_student and action = 'released');

  if v_done then return 'blue'; end if;

  if p_action = 'board' then
    if v_released then return 'gray'; end if;
    if v_route.route_type = 'school_pm' then
      if not public.fn_rode_am_today(v_route.organization_id, p_student, v_date) then
        return 'yellow';
      end if;
      return case when v_due then 'red' else 'expected' end;
    end if;
    return case when v_due then 'yellow' else 'pending' end;
  end if;

  if v_released then return 'gray'; end if;
  if not v_boarded then
    if v_route.route_type = 'school_pm' then
      return case when not public.fn_rode_am_today(v_route.organization_id, p_student, v_date)
                  then 'yellow' else 'pending' end;
    end if;
    return case when exists (
                  select 1 from public.student_stop_assignments a
                   where a.route_id = p_route_id and a.student_id = p_student and a.action = 'board'
                     and public.fn_stop_due(p_run_id, a.stop_id))
                then 'yellow' else 'pending' end;
  end if;
  return case when v_due then 'red' else 'on_board' end;
end $$;


ALTER FUNCTION "public"."fn_rider_status"("p_route_id" "uuid", "p_run_id" "uuid", "p_stop_id" "uuid", "p_student" "uuid", "p_action" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_rode_am_today"("p_org" "uuid", "p_student" "uuid", "p_date" "date") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select exists (
    select 1 from public.ridership_events e
      join public.route_runs rr on rr.id = e.run_id
      join public.routes r on r.id = rr.route_id
     where rr.organization_id = p_org and rr.run_date = p_date and r.route_type = 'school_am'
       and e.student_id = p_student and e.action = 'board');
$$;


ALTER FUNCTION "public"."fn_rode_am_today"("p_org" "uuid", "p_student" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_route_crew"("p_route_id" "uuid", "p_date" "date") RETURNS TABLE("driver_id" "uuid", "vehicle_id" "uuid", "monitor_id" "uuid", "monitor_name" "text", "is_substitute" boolean)
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select coalesce(o.driver_id, r.assigned_driver_id),
         coalesce(o.vehicle_id, r.assigned_vehicle_id),
         case when o.monitor_id is not null or o.monitor_name is not null then o.monitor_id else r.monitor_id end,
         case when o.monitor_id is not null or o.monitor_name is not null then o.monitor_name else r.monitor_name end,
         o.id is not null
    from public.routes r
    left join public.route_crew_overrides o on o.route_id = r.id and o.service_date = p_date
   where r.id = p_route_id;
$$;


ALTER FUNCTION "public"."fn_route_crew"("p_route_id" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_route_feature_ok"("p_org_id" "uuid", "p_route_type" "text") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select public.is_org_member(p_org_id) and public.fn_org_feature_internal(p_org_id,
           case when p_route_type in ('school_am', 'school_pm') then 'school' else 'routes' end);
$$;


ALTER FUNCTION "public"."fn_route_feature_ok"("p_org_id" "uuid", "p_route_type" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_route_run_mark_current_stops"("p_run_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_run public.route_runs%rowtype;
  v_lat double precision;
  v_lng double precision;
begin
  select * into v_run from public.route_runs where id = p_run_id;
  select last_latitude, last_longitude into v_lat, v_lng from public.vehicles
   where id = v_run.vehicle_id and last_location_at > now() - interval '10 minutes';
  if v_lat is null or v_lng is null then return; end if;
  insert into public.route_stop_events (organization_id, run_id, stop_id, method)
  select v_run.organization_id, p_run_id, s.id, 'auto'
    from public.route_stops s
   where s.route_id = v_run.route_id
     and public.fn_meters_between(s.latitude, s.longitude, v_lat, v_lng) <= s.radius_meters
  on conflict (run_id, stop_id) do nothing;
end $$;


ALTER FUNCTION "public"."fn_route_run_mark_current_stops"("p_run_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_route_run_set_monitor"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  select c.monitor_id, c.monitor_name into new.monitor_id, new.monitor_name
    from public.fn_route_crew(new.route_id, new.run_date) c;
  return new;
end $$;


ALTER FUNCTION "public"."fn_route_run_set_monitor"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_route_run_track_stops"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_run record;
  v_stop record;
begin
  if new.last_latitude is null or new.last_longitude is null then
    return new;
  end if;
  begin
    for v_run in
      select id, organization_id, route_id from public.route_runs
       where vehicle_id = new.id and status = 'in_progress'
    loop
      update public.route_stop_events e
         set departed_at = now()
        from public.route_stops s
       where e.run_id = v_run.id and e.stop_id = s.id and e.departed_at is null
         and public.fn_meters_between(s.latitude, s.longitude, new.last_latitude, new.last_longitude) > s.radius_meters * 1.5;
      for v_stop in
        select s.id from public.route_stops s
         where s.route_id = v_run.route_id
           and public.fn_meters_between(s.latitude, s.longitude, new.last_latitude, new.last_longitude) <= s.radius_meters
           and not exists (select 1 from public.route_stop_events e where e.run_id = v_run.id and e.stop_id = s.id)
      loop
        insert into public.route_stop_events (organization_id, run_id, stop_id, method)
        values (v_run.organization_id, v_run.id, v_stop.id, 'auto')
        on conflict (run_id, stop_id) do nothing;
      end loop;
    end loop;
  exception when others then
    raise warning 'fn_route_run_track_stops failed for vehicle %: %', new.id, sqlerrm;
  end;
  return new;
end $$;


ALTER FUNCTION "public"."fn_route_run_track_stops"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_safety_score"("p_points" numeric, "p_miles" numeric) RETURNS numeric
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  select case when p_miles is null or p_miles < 20 then null
              else greatest(0, round(100 - p_points * 100 / p_miles)) end;
$$;


ALTER FUNCTION "public"."fn_safety_score"("p_points" numeric, "p_miles" numeric) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_school_same_org"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if TG_TABLE_NAME = 'route_stops' then
    if not exists (select 1 from public.routes r where r.id = new.route_id and r.organization_id = new.organization_id) then
      raise exception 'Route belongs to another fleet';
    end if;
  elsif TG_TABLE_NAME = 'student_stop_assignments' then
    if not exists (
      select 1 from public.route_stops s join public.students st on st.id = new.student_id
       where s.id = new.stop_id and s.route_id = new.route_id
         and s.organization_id = new.organization_id and st.organization_id = new.organization_id
    ) then
      raise exception 'Student, stop and route must belong to the same fleet';
    end if;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_school_same_org"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_send_safety_summaries"() RETURNS integer
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_end date := (now() at time zone 'utc')::date - 1;
  v_start date := v_end - 14;
  v_prev_start date := v_start - 15;
  n int := 0;
begin
  with drivers as (
    select m.user_id, m.organization_id
    from public.organization_members m
    where m.member_role = 'driver' and m.is_active
      and public.fn_org_feature_internal(m.organization_id, 'safety_scores')
  ),
  cur as (
    select s.user_id, s.organization_id, sum(coalesce(s.total_miles, 0))::numeric mi
    from public.sessions s
    join drivers d on d.user_id = s.user_id and d.organization_id = s.organization_id
    where s.date_key between v_start and v_end
    group by 1, 2
  ),
  prev as (
    select s.user_id, s.organization_id, sum(coalesce(s.total_miles, 0))::numeric mi
    from public.sessions s
    join drivers d on d.user_id = s.user_id and d.organization_id = s.organization_id
    where s.date_key between v_prev_start and v_start - 1
    group by 1, 2
  ),
  ev as (
    select e.user_id, e.organization_id,
      count(*) filter (where e.event_type = 'harsh_braking' and e.recorded_at >= v_start::timestamptz) hb,
      count(*) filter (where e.event_type = 'hard_acceleration' and e.recorded_at >= v_start::timestamptz) ha,
      count(*) filter (where e.event_type = 'speeding' and e.recorded_at >= v_start::timestamptz) sp,
      sum(case e.event_type when 'harsh_braking' then 3 when 'hard_acceleration' then 2 when 'speeding' then 5 else 0 end)
        filter (where e.recorded_at < v_start::timestamptz) prev_pts
    from public.driver_safety_events e
    join drivers d on d.user_id = e.user_id and d.organization_id = e.organization_id
    where e.recorded_at >= v_prev_start::timestamptz and e.recorded_at < (v_end + 1)::timestamptz
    group by 1, 2
  ),
  rws as (
    select c.user_id, c.organization_id, c.mi,
      coalesce(ev.hb, 0) hb, coalesce(ev.ha, 0) ha, coalesce(ev.sp, 0) sp,
      public.fn_safety_score(3 * coalesce(ev.hb, 0) + 2 * coalesce(ev.ha, 0) + 5 * coalesce(ev.sp, 0), c.mi) score,
      public.fn_safety_score(coalesce(ev.prev_pts, 0), p.mi) prev_score
    from cur c
    left join prev p on p.user_id = c.user_id and p.organization_id = c.organization_id
    left join ev on ev.user_id = c.user_id and ev.organization_id = c.organization_id
    where c.mi > 0
  ),
  ins as (
    insert into public.driver_notifications (user_id, organization_id, kind, data)
    select r.user_id, r.organization_id, 'safety_summary',
      jsonb_build_object(
        'period_start', v_start, 'period_end', v_end,
        'miles', round(r.mi, 1),
        'harsh_braking', r.hb, 'hard_acceleration', r.ha, 'speeding', r.sp,
        'score', r.score, 'previous_score', r.prev_score,
        'trend', case
          when r.score is null or r.prev_score is null then
            case when r.score is null then 'unrated' when r.score >= 90 then 'good' else 'attention' end
          when r.score > r.prev_score then 'better'
          when r.score < r.prev_score then 'worse'
          else 'steady' end)
    from rws r
    returning 1
  )
  select count(*) into n from ins;
  return n;
end;
$$;


ALTER FUNCTION "public"."fn_send_safety_summaries"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_session_miles_from_sections"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
declare
  v_sum double precision;
begin
  if coalesce(new.is_closed, false) and not coalesce(old.is_closed, false) then
    select sum(total_miles) into v_sum from public.session_sections where session_id = new.id;
    if v_sum is not null and v_sum > 0 then
      new.total_miles := v_sum;
    end if;
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_session_miles_from_sections"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_set_vehicle_service"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.organization_id is not null then
    select o.service into new.service from organizations o where o.id = new.organization_id;
  else
    new.service := 'gig';
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_set_vehicle_service"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_stop_due"("p_run_id" "uuid", "p_stop_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select p_run_id is not null and (
    exists (select 1 from public.route_runs where id = p_run_id and status = 'completed')
    or exists (select 1 from public.route_stop_events
                where run_id = p_run_id and stop_id = p_stop_id
                  and (departed_at is not null or arrived_at <= now() - interval '5 minutes')));
$$;


ALTER FUNCTION "public"."fn_stop_due"("p_run_id" "uuid", "p_stop_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_sun_times"("p_lat" double precision, "p_lng" double precision, "p_at" timestamp with time zone, OUT "sunrise" timestamp with time zone, OUT "sunset" timestamp with time zone) RETURNS "record"
    LANGUAGE "plpgsql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
declare
  rad constant double precision := pi() / 180;
  j2000 constant double precision := 2451545;
  j0 constant double precision := 0.0009;
  lw double precision := rad * -p_lng;
  phi double precision := rad * p_lat;
  d double precision;
  n double precision;
  ds double precision;
  m double precision;
  c double precision;
  l double precision;
  dec double precision;
  jnoon double precision;
  cosw double precision;
  w double precision;
  jset double precision;
  jrise double precision;
begin
  d := extract(epoch from p_at) / 86400 - 0.5 + 2440588 - j2000;
  n := round(d - j0 - lw / (2 * pi()));
  ds := j0 + lw / (2 * pi()) + n;
  m := rad * (357.5291 + 0.98560028 * ds);
  c := rad * (1.9148 * sin(m) + 0.02 * sin(2 * m) + 0.0003 * sin(3 * m));
  l := m + c + rad * 102.9372 + pi();
  dec := asin(sin(l) * sin(rad * 23.4397));
  jnoon := j2000 + ds + 0.0053 * sin(m) - 0.0069 * sin(2 * l);
  cosw := (sin(rad * -0.833) - sin(phi) * sin(dec)) / (cos(phi) * cos(dec));
  cosw := greatest(-1, least(1, cosw));
  w := acos(cosw);
  jset := j2000 + (j0 + (w + lw) / (2 * pi()) + n) + 0.0053 * sin(m) - 0.0069 * sin(2 * l);
  jrise := jnoon - (jset - jnoon);
  sunrise := to_timestamp((jrise + 0.5 - 2440588) * 86400);
  sunset := to_timestamp((jset + 0.5 - 2440588) * 86400);
end $$;


ALTER FUNCTION "public"."fn_sun_times"("p_lat" double precision, "p_lng" double precision, "p_at" timestamp with time zone, OUT "sunrise" timestamp with time zone, OUT "sunset" timestamp with time zone) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_sync_driving_school_client"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.service = 'driving_school' then
    insert into driving_school_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from driving_school_clients where organization_id = new.id;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_sync_driving_school_client"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_sync_general_business_client"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.service = 'general_business' then
    insert into general_business_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from general_business_clients where organization_id = new.id;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_sync_general_business_client"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_sync_gig_client"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  insert into gig_clients(profile_id) values (new.id) on conflict do nothing;
  return new;
end $$;


ALTER FUNCTION "public"."fn_sync_gig_client"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_sync_org_service"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    AS $$
begin
  new.service := public.service_for_industry(new.industry_template);
  return new;
end $$;


ALTER FUNCTION "public"."fn_sync_org_service"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_sync_sales_client"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.service = 'sales' then
    insert into sales_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from sales_clients where organization_id = new.id;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_sync_sales_client"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_sync_school_bus_client"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.service = 'school_bus' then
    insert into school_bus_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from school_bus_clients where organization_id = new.id;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_sync_school_bus_client"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_sync_trucking_client"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.service = 'trucking' then
    insert into trucking_clients(organization_id) values (new.id) on conflict do nothing;
  else
    delete from trucking_clients where organization_id = new.id;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_sync_trucking_client"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_touch_updated_at"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."fn_touch_updated_at"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_valid_fleet_profile"("p" "text") RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $$
  select p in ('general', 'delivery', 'field_service', 'trucking', 'construction', 'passenger', 'sales',
               'driving_school', 'school_transport');
$$;


ALTER FUNCTION "public"."fn_valid_fleet_profile"("p" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_valid_origins"("p" "text"[]) RETURNS boolean
    LANGUAGE "sql" IMMUTABLE
    SET "search_path" TO 'public'
    AS $_$
  select coalesce(bool_and(o ~ '^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{2,5})?$'), true)
    from unnest(p) o;
$_$;


ALTER FUNCTION "public"."fn_valid_origins"("p" "text"[]) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_validate_org_timezone"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if not exists (select 1 from pg_timezone_names where name = new.timezone) then
    raise exception 'Unknown timezone: %', new.timezone;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_validate_org_timezone"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_vehicle_active_trip"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if tg_op = 'INSERT' then
    if new.vehicle_id is not null and not coalesce(new.is_closed, false) then
      update public.vehicles set active_session_id = new.id where id = new.vehicle_id;
    end if;
  elsif tg_op = 'UPDATE' then
    if coalesce(new.is_closed, false) and not coalesce(old.is_closed, false) then
      update public.vehicles set active_session_id = null
      where id = new.vehicle_id and active_session_id = new.id;
    end if;
  elsif tg_op = 'DELETE' then
    update public.vehicles set active_session_id = null
    where id = old.vehicle_id and active_session_id = old.id;
  end if;
  return null;
exception when others then
  raise warning 'vehicle active trip update failed: %', sqlerrm;
  return null;
end;
$$;


ALTER FUNCTION "public"."fn_vehicle_active_trip"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_vehicles_driving_school_cycle"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.organization_id is not null and exists (
    select 1 from public.organizations o
    where o.id = new.organization_id and o.industry_template = 'driving_school'
  ) then
    new.odometer_cycle := 'monthly';
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_vehicles_driving_school_cycle"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_vehicles_fleet_template"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if new.organization_id is null then
    new.fleet_template := null;
  else
    select industry_template into new.fleet_template
      from public.organizations where id = new.organization_id;
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_vehicles_fleet_template"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_vehicles_plan_limit"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_active int;
  v_max int;
begin
  if new.organization_id is null or coalesce(new.is_archived, false) then return new; end if;
  if tg_op = 'UPDATE' and not coalesce(old.is_archived, false) and old.organization_id is not distinct from new.organization_id then
    return new;
  end if;
  if exists (select 1 from public.organizations o where o.id = new.organization_id and o.tier_enforcement_exempt) then
    return new;
  end if;
  if public.fn_org_enterprise_internal(new.organization_id) or public.fn_org_tier_internal(new.organization_id) <> 'starter' then
    return new;
  end if;
  select p.max_cars into v_max from public.fleet_plans p where p.tier = 'starter';
  if v_max is null then return new; end if;
  select count(*) into v_active from public.vehicles
   where organization_id = new.organization_id and not coalesce(is_archived, false) and id <> new.id;
  if v_active >= v_max then
    raise exception 'Starter allows up to % cars. Upgrade to Growth to add more.', v_max using errcode = 'P0001';
  end if;
  return new;
end $$;


ALTER FUNCTION "public"."fn_vehicles_plan_limit"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."fn_vehicles_set_cycle_anchor"() RETURNS "trigger"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  if new.odometer_cycle_anchor is null then
    new.odometer_cycle_anchor := (new.created_at::date) - (extract(isodow from new.created_at::date)::int - 1);
  end if;
  return new;
end;
$$;


ALTER FUNCTION "public"."fn_vehicles_set_cycle_anchor"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."generate_report_access_code"("p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid" DEFAULT NULL::"uuid", "p_weekly_checkpoints" "jsonb" DEFAULT '[]'::"jsonb", "p_target_user_id" "uuid" DEFAULT NULL::"uuid") RETURNS TABLE("code" "text", "expires_at" timestamp with time zone)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_caller uuid := auth.uid();
  v_user_id uuid;
  v_organization_id uuid;
  v_recent_count int;
  v_plain_code text;
  v_alphabet text := 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
  v_expires timestamptz := now() + interval '15 minutes';
  v_metadata jsonb;
  v_deduction numeric;
  i int;
begin
  if v_caller is null then
    raise exception 'Authentication required';
  end if;

  if p_target_user_id is null or p_target_user_id = v_caller then
    v_user_id := v_caller;
  else
    select caller_m.organization_id into v_organization_id
    from public.organization_members caller_m
    join public.organization_members target_m
      on target_m.organization_id = caller_m.organization_id
    where caller_m.user_id = v_caller
      and caller_m.member_role in ('owner', 'admin')
      and caller_m.is_active = true
      and target_m.user_id = p_target_user_id
      and target_m.is_active = true
    limit 1;

    if v_organization_id is null then
      raise exception 'Not authorized to generate a report for that driver';
    end if;

    if public.fn_org_effective_tier(v_organization_id) = 'none' then
      raise exception 'FLEET_SUBSCRIPTION_REQUIRED';
    end if;

    v_user_id := p_target_user_id;
  end if;

  if p_end_date < p_start_date then
    raise exception 'Invalid date range';
  end if;

  select count(*) into v_recent_count
  from public.reports
  where generated_by = v_caller
    and generated_at > now() - interval '1 hour';

  if v_recent_count >= 5 then
    raise exception 'Too many report codes generated recently. Try again later.';
  end if;

  select coalesce(sum(
    case when s.date_key < date '2026-07-01'
      then s.total_miles * 72.5 / 100.0
      else s.total_miles * 76.0 / 100.0
    end
  ), 0) into v_deduction
  from public.sessions s
  where s.user_id = v_user_id
    and s.organization_id is not distinct from v_organization_id
    and s.date_key between p_start_date and p_end_date
    and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
      and (coalesce(s.total_miles, 0) >= 0.05
           or exists (select 1 from public.session_sections x
                      where x.session_id = s.id and x.total_miles >= 0.05));

  with vehicles_in_range as (
    select distinct v.id, v.nickname, v.make, v.model, v.year, v.plate
    from public.sessions s
    join public.vehicles v on v.id = s.vehicle_id
    where s.user_id = v_user_id
    and s.organization_id is not distinct from v_organization_id
      and s.date_key between p_start_date and p_end_date
      and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
      and (coalesce(s.total_miles, 0) >= 0.05
           or exists (select 1 from public.session_sections x
                      where x.session_id = s.id and x.total_miles >= 0.05))
  ),
  purpose_breakdown as (
    select
      ss.gig_app,
      ss.irs_purpose,
      sum(ss.total_miles) as miles
    from public.session_sections ss
    join public.sessions s on s.id = ss.session_id
    where s.user_id = v_user_id
    and s.organization_id is not distinct from v_organization_id
      and s.date_key between p_start_date and p_end_date
      and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
      and (coalesce(s.total_miles, 0) >= 0.05
           or exists (select 1 from public.session_sections x
                      where x.session_id = s.id and x.total_miles >= 0.05))
    group by ss.gig_app, ss.irs_purpose
  ),
  totals as (
    select
      coalesce(sum(s.total_miles), 0) as total_miles,
      count(distinct s.id) as total_sessions
    from public.sessions s
    where s.user_id = v_user_id
    and s.organization_id is not distinct from v_organization_id
      and s.date_key between p_start_date and p_end_date
      and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
      and (coalesce(s.total_miles, 0) >= 0.05
           or exists (select 1 from public.session_sections x
                      where x.session_id = s.id and x.total_miles >= 0.05))
  ),
  sessions_in_range as (
    select s.id, s.date_key, s.total_miles, s.start_time, s.end_time, s.map_token,
           case when s.total_duration_seconds > 0 then s.total_duration_seconds
                when s.start_time is not null and s.end_time is not null
                  then extract(epoch from (s.end_time - s.start_time))::int
           end as effective_duration_seconds, s.start_odometer_value, s.end_odometer_value
    from public.sessions s
    where s.user_id = v_user_id
    and s.organization_id is not distinct from v_organization_id
      and s.date_key between p_start_date and p_end_date
      and (p_vehicle_id is null or s.vehicle_id = p_vehicle_id)
      and (coalesce(s.total_miles, 0) >= 0.05
           or exists (select 1 from public.session_sections x
                      where x.session_id = s.id and x.total_miles >= 0.05))
  ),
  trip_apps as (
    select
      ss.session_id,
      string_agg(
        upper(ss.gig_app) ||
          case when ss.irs_purpose is not null and ss.irs_purpose <> ''
               then ' (' || ss.irs_purpose || ')'
               else '' end,
        ' / ' order by ss.start_time
      ) as apps_label
    from public.session_sections ss
    join sessions_in_range sir on sir.id = ss.session_id
    group by ss.session_id
  ),
  trip_places as (
    select
      ss.session_id,
      (array_agg(ss.start_address order by ss.start_time))[1] as from_address,
      (array_agg(ss.end_address order by ss.start_time desc))[1] as to_address
    from public.session_sections ss
    join sessions_in_range sir on sir.id = ss.session_id
    group by ss.session_id
  ),
  route_points as (
    select sir.id as session_id, sir.date_key, sir.start_time, sir.total_miles, sir.map_token
    from sessions_in_range sir
    where exists (
            select 1 from public.session_sections ss
             where ss.session_id = sir.id
               and (ss.route_polyline is not null
                    or (ss.start_latitude is not null and ss.end_latitude is not null))
          )
       or (select count(*) from public.session_gps_breadcrumbs b where b.session_id = sir.id) >= 2
  )
  select jsonb_build_object(
    'driver_display_name', p.full_name,
    'driver_display_id', p.display_id,
    'start_date', p_start_date,
    'end_date', p_end_date,
    'generated_at', now(),
    'total_miles', t.total_miles,
    'total_sessions', t.total_sessions,
    'total_deduction_estimate', v_deduction,
    'vehicles', coalesce((select jsonb_agg(jsonb_build_object(
        'nickname', vr.nickname, 'make', vr.make, 'model', vr.model,
        'year', vr.year, 'plate', vr.plate
      )) from vehicles_in_range vr), '[]'::jsonb),
    'gig_app_breakdown', coalesce((select jsonb_agg(jsonb_build_object(
        'gig_app', pb.gig_app, 'irs_purpose', pb.irs_purpose, 'miles', pb.miles
      )) from purpose_breakdown pb), '[]'::jsonb),
    'trips', coalesce((select jsonb_agg(jsonb_build_object(
        'date_key', sir.date_key,
        'apps_label', coalesce(ta.apps_label, ''),
        'total_miles', sir.total_miles,
        'duration_seconds', coalesce(sir.effective_duration_seconds, 0),
        'start_odometer_value', sir.start_odometer_value,
        'end_odometer_value', sir.end_odometer_value,
        'from_address', tp.from_address,
        'to_address', tp.to_address
      ) order by sir.start_time)
      from sessions_in_range sir
      left join trip_apps ta on ta.session_id = sir.id
      left join trip_places tp on tp.session_id = sir.id), '[]'::jsonb),
    'weekly_checkpoints', coalesce(p_weekly_checkpoints, '[]'::jsonb),
    'route_points', coalesce((select jsonb_agg(jsonb_build_object(
        'session_id', rp.session_id, 'date_key', rp.date_key,
        'total_miles', rp.total_miles, 'map_token', rp.map_token,
        'section_ids', (select case when count(*) > 1 then jsonb_agg(ss.id order by ss.start_time) end
                          from public.session_sections ss where ss.session_id = rp.session_id and ss.total_miles >= 0.05)
      ) order by rp.start_time)
      from route_points rp), '[]'::jsonb)
  )
  into v_metadata
  from public.profiles p, totals t
  where p.id = v_user_id;

  v_plain_code := '';
  for i in 1..8 loop
    v_plain_code := v_plain_code || substr(v_alphabet, 1 + floor(random() * length(v_alphabet))::int, 1);
  end loop;

  insert into public.reports (
    report_type, user_id, organization_id, vehicle_id, start_date, end_date,
    total_miles, total_sessions, generated_by, metadata,
    qr_token, qr_expires_at, qr_uses, qr_max_uses
  ) values (
    'custom', v_user_id, v_organization_id, p_vehicle_id, p_start_date, p_end_date,
    coalesce((v_metadata->>'total_miles')::float8, 0),
    coalesce((v_metadata->>'total_sessions')::int, 0),
    v_caller, v_metadata,
    encode(digest(v_plain_code, 'sha256'), 'hex'), v_expires, 0, 2
  );

  return query select v_plain_code, v_expires;
end;
$$;


ALTER FUNCTION "public"."generate_report_access_code"("p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid", "p_weekly_checkpoints" "jsonb", "p_target_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_fleet_export_data"("p_org_id" "uuid", "p_start_date" "date", "p_end_date" "date") RETURNS TABLE("user_id" "uuid", "driver_name" "text", "driver_display_id" "text", "total_miles" double precision, "total_sessions" bigint, "vehicles" "jsonb")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if not is_org_admin_or_owner(p_org_id) then
    raise exception 'Only an org admin or owner can export fleet-wide data';
  end if;

  if public.fn_org_effective_tier(p_org_id) <> 'growth' then
    raise exception 'FLEET_GROWTH_REQUIRED';
  end if;

  return query
  select
    s.user_id,
    p.full_name as driver_name,
    p.display_id as driver_display_id,
    coalesce(sum(s.total_miles), 0) as total_miles,
    count(distinct s.id) as total_sessions,
    coalesce(
      (select jsonb_agg(distinct jsonb_build_object(
        'display_id', v.display_id, 'make', v.make, 'model', v.model, 'nickname', v.nickname
      ))
      from public.vehicles v
      where v.id in (
        select s2.vehicle_id from public.sessions s2
        where s2.user_id = s.user_id
          and s2.organization_id = p_org_id
          and s2.date_key between p_start_date and p_end_date
          and s2.vehicle_id is not null
      )),
      '[]'::jsonb
    ) as vehicles
  from public.sessions s
  join public.profiles p on p.id = s.user_id
  where s.organization_id = p_org_id
    and s.date_key between p_start_date and p_end_date
  group by s.user_id, p.full_name, p.display_id
  order by total_miles desc;
end;
$$;


ALTER FUNCTION "public"."get_fleet_export_data"("p_org_id" "uuid", "p_start_date" "date", "p_end_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_my_shift_day"("p_org" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_uid uuid := auth.uid();
  v_tz text;
  v_window int;
  v_today date;
  v_blocks jsonb;
  v_day public.driver_workdays;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  if not public.fn_org_has_classes(p_org) then
    return jsonb_build_object('date', null, 'window_minutes', null,
      'workday_open', false, 'workday_closed', false, 'blocks', '[]'::jsonb);
  end if;

  select timezone, shift_start_window_minutes into v_tz, v_window
  from public.organizations where id = p_org;
  v_today := (now() at time zone v_tz)::date;

  perform public.materialize_shift_blocks(p_org, v_today);

  select * into v_day from public.driver_workdays
  where organization_id = p_org and driver_id = v_uid and work_date = v_today;

  select coalesce(jsonb_agg(jsonb_build_object(
      'id', b.id,
      'start_time', b.start_time,
      'end_time', b.end_time,
      'note', b.note,
      'vehicle_id', b.vehicle_id,
      'vehicle_label', nullif(concat_ws(' ', v.make, v.model), ''),
      'vehicle_display_id', v.display_id,
      'status', b.status,
      'late_minutes', b.late_minutes,
      'student_id', b.student_id,
      'student_name', nullif(concat_ws(' ', st.first_name, st.last_name), ''),
      'evaluated', exists (select 1 from public.ds_evaluations e where e.shift_block_id = b.id),
      'opens_at', ((b.block_date + b.start_time) at time zone v_tz) - make_interval(mins => v_window),
      'closes_at', ((b.block_date + b.start_time) at time zone v_tz) + make_interval(mins => v_window)
    ) order by b.start_time), '[]'::jsonb)
  into v_blocks
  from public.shift_blocks b
  left join public.vehicles v on v.id = b.vehicle_id
  left join public.ds_students st on st.id = b.student_id
  where b.organization_id = p_org and b.driver_id = v_uid and b.block_date = v_today
    and b.status <> 'cancelled';

  return jsonb_build_object(
    'date', v_today,
    'window_minutes', v_window,
    'workday_open', v_day.id is not null and v_day.closed_at is null,
    'workday_closed', v_day.closed_at is not null,
    'blocks', v_blocks
  );
end $$;


ALTER FUNCTION "public"."get_my_shift_day"("p_org" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_my_upcoming_classes"("p_org" "uuid", "p_days" integer DEFAULT 7) RETURNS "jsonb"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_uid uuid := auth.uid();
  v_tz text;
  v_today date;
  v_n int := least(greatest(coalesce(p_days, 7), 1), 14);
  d date;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  if not public.fn_org_has_classes(p_org) then return '[]'::jsonb; end if;
  if not exists (select 1 from public.organization_members m
                  where m.organization_id = p_org and m.user_id = v_uid and m.is_active) then
    return '[]'::jsonb;
  end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_org;
  v_today := (now() at time zone v_tz)::date;
  for d in select (v_today + g)::date from generate_series(1, v_n) g loop
    perform public.materialize_shift_blocks(p_org, d);
  end loop;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
        'id', b.id,
        'date', b.block_date,
        'start_time', b.start_time,
        'end_time', b.end_time,
        'note', b.note,
        'vehicle_label', nullif(concat_ws(' ', v.make, v.model), ''),
        'vehicle_display_id', v.display_id,
        'student_name', nullif(concat_ws(' ', st.first_name, st.last_name), '')
      ) order by b.block_date, b.start_time)
      from public.shift_blocks b
      left join public.vehicles v on v.id = b.vehicle_id
      left join public.ds_students st on st.id = b.student_id
     where b.organization_id = p_org and b.driver_id = v_uid
       and b.block_date > v_today and b.block_date <= v_today + v_n
       and b.status = 'scheduled'
  ), '[]'::jsonb);
end $$;


ALTER FUNCTION "public"."get_my_upcoming_classes"("p_org" "uuid", "p_days" integer) OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."shift_blocks" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "driver_id" "uuid" NOT NULL,
    "vehicle_id" "uuid",
    "block_date" "date" NOT NULL,
    "start_time" time without time zone NOT NULL,
    "end_time" time without time zone NOT NULL,
    "note" "text",
    "source" "text" DEFAULT 'one_off'::"text" NOT NULL,
    "template_shift_id" "uuid",
    "status" "text" DEFAULT 'scheduled'::"text" NOT NULL,
    "started_at" timestamp with time zone,
    "ended_at" timestamp with time zone,
    "late_minutes" integer,
    "session_id" "uuid",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "student_id" "uuid",
    "booked_via" "text",
    "cancelled_at" timestamp with time zone,
    "late_cancel" boolean DEFAULT false NOT NULL,
    CONSTRAINT "shift_blocks_booked_via_check" CHECK ((("booked_via" IS NULL) OR ("booked_via" = ANY (ARRAY['office'::"text", 'portal'::"text"])))),
    CONSTRAINT "shift_blocks_source_check" CHECK (("source" = ANY (ARRAY['template'::"text", 'one_off'::"text"]))),
    CONSTRAINT "shift_blocks_status_check" CHECK (("status" = ANY (ARRAY['scheduled'::"text", 'in_progress'::"text", 'done'::"text", 'cancelled'::"text"]))),
    CONSTRAINT "shift_blocks_time_order" CHECK (("end_time" > "start_time"))
);


ALTER TABLE "public"."shift_blocks" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_org_shift_day"("p_org" "uuid", "p_date" "date") RETURNS SETOF "public"."shift_blocks"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_operator_or_above(p_org) then
    raise exception 'Only an owner, admin or operator can see the schedule';
  end if;
  perform public.materialize_shift_blocks(p_org, p_date);
  return query
    select * from public.shift_blocks
    where organization_id = p_org and block_date = p_date
    order by start_time;
end $$;


ALTER FUNCTION "public"."get_org_shift_day"("p_org" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_org_shift_range"("p_org" "uuid", "p_from" "date", "p_days" integer) RETURNS SETOF "public"."shift_blocks"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  d date;
begin
  if not public.is_org_operator_or_above(p_org) then
    raise exception 'Only an owner, admin or operator can see the schedule';
  end if;
  for d in select (p_from + g)::date from generate_series(0, least(greatest(p_days, 1), 31) - 1) g loop
    perform public.materialize_shift_blocks(p_org, d);
  end loop;
  return query
    select * from public.shift_blocks
     where organization_id = p_org and block_date >= p_from and block_date < p_from + least(greatest(p_days, 1), 31)
     order by block_date, start_time;
end $$;


ALTER FUNCTION "public"."get_org_shift_range"("p_org" "uuid", "p_from" "date", "p_days" integer) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."get_trip_map"("p_session_id" "uuid", "p_token" "uuid") RETURNS "jsonb"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select jsonb_build_object(
    'closed', coalesce(s.is_closed, false)
      and (not exists (select 1 from public.session_sections x
                        where x.session_id = s.id and x.route_polyline is null)
           or coalesce(s.end_time, s.updated_at) < now() - interval '1 hour'),
    'sections', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', ss.id,
        'gig_app', ss.gig_app,
        'polyline', ss.route_polyline,
        'points', case when ss.route_polyline is null then (
            select jsonb_agg(jsonb_build_array(round(b.latitude::numeric, 5), round(b.longitude::numeric, 5))
                             order by b.recorded_at)
              from public.session_gps_breadcrumbs b
             where b.section_id = ss.id
          ) end,
        'start', case when ss.start_latitude is not null
          then jsonb_build_array(ss.start_latitude, ss.start_longitude) end,
        'end', case when ss.end_latitude is not null
          then jsonb_build_array(ss.end_latitude, ss.end_longitude) end
      ) order by ss.start_time)
      from public.session_sections ss
      where ss.session_id = s.id
    ), '[]'::jsonb)
  )
  from public.sessions s
  where s.id = p_session_id and s.map_token = p_token;
$$;


ALTER FUNCTION "public"."get_trip_map"("p_session_id" "uuid", "p_token" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."guardian_login_user"("p_display_id" "text") RETURNS "uuid"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select user_id from public.school_guardians
   where display_id = upper(btrim(p_display_id)) and is_active and user_id is not null;
$$;


ALTER FUNCTION "public"."guardian_login_user"("p_display_id" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."handle_new_user"() RETURNS "trigger"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_first_name TEXT;
  v_last_name TEXT;
  v_org_name TEXT;
  v_org_id uuid;
BEGIN
  v_first_name := COALESCE(
    NEW.raw_user_meta_data->>'first_name',
    SPLIT_PART(COALESCE(NEW.email, ''), '@', 1)
  );
  v_last_name := NULLIF(COALESCE(NEW.raw_user_meta_data->>'last_name', ''), '');
  v_org_name := NULLIF(TRIM(COALESCE(NEW.raw_user_meta_data->>'pending_org_name', '')), '');

  INSERT INTO public.profiles (id, email, first_name, last_name, account_type)
  VALUES (NEW.id, NEW.email, v_first_name, v_last_name, 'gig')
  ON CONFLICT (id) DO NOTHING;

  INSERT INTO public.user_onboarding (user_id)
  VALUES (NEW.id)
  ON CONFLICT (user_id) DO NOTHING;

  IF v_org_name IS NOT NULL THEN
    INSERT INTO public.organizations (name, created_by, industry_template)
    VALUES (v_org_name, NEW.id, 'general')
    RETURNING id INTO v_org_id;

    INSERT INTO public.organization_members (organization_id, user_id, member_role, is_active, joined_at)
    VALUES (v_org_id, NEW.id, 'owner', true, now());

    UPDATE public.profiles
    SET account_type = 'fleet_admin', default_org_id = v_org_id
    WHERE id = NEW.id;

    UPDATE public.user_onboarding
    SET account_type_chosen = true
    WHERE user_id = NEW.id;
  END IF;

  RETURN NEW;

EXCEPTION WHEN OTHERS THEN
  RAISE LOG '[ControlMiles] handle_new_user FAILED for uid=% email=% | error: %', NEW.id, NEW.email, SQLERRM;
  BEGIN
    INSERT INTO public.auth_signup_errors (user_id, email, error_message)
    VALUES (NEW.id, NEW.email, SQLERRM);
  EXCEPTION WHEN OTHERS THEN
    NULL;
  END;
  RETURN NEW;
END;
$$;


ALTER FUNCTION "public"."handle_new_user"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."ifta_state_at_point"("p_lat" double precision, "p_lng" double precision) RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
  select state_code from public.ifta_us_state_boundaries
  where ST_Contains(geom, ST_SetSRID(ST_MakePoint(p_lng, p_lat), 4326))
  limit 1;
$$;


ALTER FUNCTION "public"."ifta_state_at_point"("p_lat" double precision, "p_lng" double precision) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."invite_member_by_email"("p_org_id" "uuid", "p_email" "text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_target_id uuid;
  v_target_account_type text;
  v_existing_membership uuid;
  v_membership_id uuid;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  IF NOT public.is_org_operator_or_above(p_org_id) THEN
    RAISE EXCEPTION 'Only an org admin, owner, or operator can invite members';
  END IF;

  IF public.fn_org_effective_tier(p_org_id) = 'none' THEN
    RAISE EXCEPTION 'FLEET_SUBSCRIPTION_REQUIRED';
  END IF;

  SELECT id, account_type INTO v_target_id, v_target_account_type
  FROM public.profiles
  WHERE lower(email) = lower(trim(p_email))
  LIMIT 1;

  IF v_target_id IS NULL THEN
    RAISE EXCEPTION 'No ControlMiles account found for that email';
  END IF;

  IF v_target_account_type = 'fleet_admin' THEN
    RAISE EXCEPTION 'This person already owns their own fleet and cannot be invited as a driver';
  END IF;

  SELECT id INTO v_existing_membership
  FROM public.organization_members
  WHERE organization_id = p_org_id AND user_id = v_target_id;

  IF v_existing_membership IS NOT NULL THEN
    RAISE EXCEPTION 'This person is already a member or has a pending invite for this organization';
  END IF;

  INSERT INTO public.organization_members
    (organization_id, user_id, member_role, is_active, invited_at)
  VALUES
    (p_org_id, v_target_id, 'driver', false, now())
  RETURNING id INTO v_membership_id;

  RETURN v_membership_id;
END;
$$;


ALTER FUNCTION "public"."invite_member_by_email"("p_org_id" "uuid", "p_email" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_org_admin_or_owner"("p_organization_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = p_organization_id
      AND user_id = auth.uid()
      AND is_active = true
      AND member_role IN ('owner', 'admin')
  );
$$;


ALTER FUNCTION "public"."is_org_admin_or_owner"("p_organization_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_org_member"("p_organization_id" "uuid", "p_required_role" "text" DEFAULT NULL::"text") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = p_organization_id
      AND user_id = auth.uid()
      AND is_active = true
      AND (p_required_role IS NULL OR member_role = p_required_role)
  );
$$;


ALTER FUNCTION "public"."is_org_member"("p_organization_id" "uuid", "p_required_role" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_org_operator_or_above"("p_organization_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = p_organization_id
      AND user_id = auth.uid()
      AND is_active = true
      AND member_role IN ('owner', 'admin', 'operator')
  );
$$;


ALTER FUNCTION "public"."is_org_operator_or_above"("p_organization_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."is_org_owner"("p_organization_id" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = p_organization_id
      AND user_id = auth.uid()
      AND is_active = true
      AND member_role = 'owner'
  );
$$;


ALTER FUNCTION "public"."is_org_owner"("p_organization_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."mark_driver_notifications_read"("p_ids" "uuid"[] DEFAULT NULL::"uuid"[]) RETURNS "void"
    LANGUAGE "sql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  update public.driver_notifications
  set read_at = now()
  where user_id = auth.uid() and read_at is null
    and (p_ids is null or id = any (p_ids));
$$;


ALTER FUNCTION "public"."mark_driver_notifications_read"("p_ids" "uuid"[]) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."mark_stop_arrived"("p_run_id" "uuid", "p_stop_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare v_run public.route_runs%rowtype := public.fn_my_open_run(p_run_id);
begin
  if not exists (select 1 from public.route_stops where id = p_stop_id and route_id = v_run.route_id) then
    raise exception 'Stop is not on this route';
  end if;
  insert into public.route_stop_events (organization_id, run_id, stop_id, method)
  values (v_run.organization_id, p_run_id, p_stop_id, 'manual')
  on conflict (run_id, stop_id) do nothing;
end $$;


ALTER FUNCTION "public"."mark_stop_arrived"("p_run_id" "uuid", "p_stop_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."materialize_shift_blocks"("p_org" "uuid", "p_date" "date") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_member(p_org, null) then
    raise exception 'Not a member of this organization';
  end if;
  if not public.fn_org_has_classes(p_org) then
    return;
  end if;

  perform set_config('cm.shift_block_rpc', 'on', true);

  insert into public.shift_blocks
    (organization_id, driver_id, vehicle_id, block_date, start_time, end_time, note, source, template_shift_id)
  select s.organization_id, s.driver_id, s.vehicle_id, p_date, s.start_time, s.end_time, s.notes, 'template', s.id
  from public.shifts s
  where s.organization_id = p_org
    and s.is_active
    and s.day_of_week = extract(dow from p_date)::int
  on conflict (template_shift_id, block_date) do update
    set driver_id = excluded.driver_id,
        vehicle_id = excluded.vehicle_id,
        start_time = excluded.start_time,
        end_time = excluded.end_time,
        note = excluded.note
    where public.shift_blocks.status = 'scheduled';

  delete from public.shift_blocks b
  where b.organization_id = p_org
    and b.block_date = p_date
    and b.source = 'template'
    and b.status = 'scheduled'
    and not exists (
      select 1 from public.shifts s
      where s.id = b.template_shift_id and s.is_active
        and s.day_of_week = extract(dow from p_date)::int
    );

  perform set_config('cm.shift_block_rpc', 'off', true);
end $$;


ALTER FUNCTION "public"."materialize_shift_blocks"("p_org" "uuid", "p_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."move_to_branch"("p_organization_id" "uuid", "p_subject_type" "text", "p_subject_id" "uuid", "p_to_branch" "uuid", "p_any" boolean, "p_note" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_from uuid;
  v_from_any boolean := false;
  v_name text;
  v_any boolean := coalesce(p_any, false) and p_subject_type = 'member';
begin
  if not public.is_org_admin_or_owner(p_organization_id) then raise exception 'Not authorized'; end if;
  if length(btrim(coalesce(p_note, ''))) < 3 then
    raise exception 'Write why you are making this move' using errcode = 'P0001';
  end if;
  if p_to_branch is not null and not exists (
    select 1 from public.branches where id = p_to_branch and organization_id = p_organization_id and not is_archived
  ) then
    raise exception 'That branch belongs to another fleet' using errcode = 'P0001';
  end if;

  if p_subject_type = 'member' then
    select m.branch_id, m.any_branch, nullif(concat_ws(' ', p.first_name, p.last_name), '')
      into v_from, v_from_any, v_name
      from public.organization_members m left join public.profiles p on p.id = m.user_id
     where m.organization_id = p_organization_id and m.user_id = p_subject_id;
    if not found then raise exception 'That person is not on this team' using errcode = 'P0001'; end if;
    update public.organization_members
       set branch_id = case when v_any then null else p_to_branch end, any_branch = v_any
     where organization_id = p_organization_id and user_id = p_subject_id;
  elsif p_subject_type = 'student' then
    select branch_id, concat_ws(' ', first_name, last_name) into v_from, v_name
      from public.ds_students where id = p_subject_id and organization_id = p_organization_id;
    if not found then raise exception 'That student is not in this school' using errcode = 'P0001'; end if;
    update public.ds_students set branch_id = p_to_branch where id = p_subject_id;
  else
    raise exception 'Bad subject';
  end if;

  insert into public.branch_moves (organization_id, subject_type, subject_id, subject_name, from_branch_id, to_branch_id,
                                   from_any, to_any, note, moved_by)
  values (p_organization_id, p_subject_type, p_subject_id, v_name, v_from,
          case when v_any then null else p_to_branch end, coalesce(v_from_any, false), v_any, btrim(p_note), auth.uid());
end $$;


ALTER FUNCTION "public"."move_to_branch"("p_organization_id" "uuid", "p_subject_type" "text", "p_subject_id" "uuid", "p_to_branch" "uuid", "p_any" boolean, "p_note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."my_fleet_driver_id"() RETURNS "text"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select s.display_id
    from public.fleet_driver_slots s
   where s.claimed_by = auth.uid()
   order by s.claimed_at desc nulls last
   limit 1;
$$;


ALTER FUNCTION "public"."my_fleet_driver_id"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."my_guardian_children"() RETURNS TABLE("student_id" "uuid", "organization_id" "uuid", "org_name" "text", "first_name" "text", "last_initial" "text")
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select st.id, st.organization_id, o.name, st.first_name, st.last_initial
    from public.school_guardians g
    join public.student_guardians sg on sg.guardian_id = g.id and sg.is_active
    join public.students st on st.id = sg.student_id and st.is_active
    join public.organizations o on o.id = st.organization_id
   where g.user_id = auth.uid() and g.is_active
   order by st.first_name;
$$;


ALTER FUNCTION "public"."my_guardian_children"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."my_pending_invite"() RETURNS TABLE("organization_name" "text", "intended_role" "text", "display_id" "text")
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select o.name, coalesce(i.intended_role, 'driver'), s.display_id
    from public.driver_invites i
    join public.profiles p on lower(p.email) = lower(i.email)
    join public.organizations o on o.id = i.organization_id
    join auth.users u on u.id = p.id
    left join public.fleet_driver_slots s on s.id = i.slot_id
   where p.id = auth.uid()
     and u.email_confirmed_at is not null
     and i.status = 'pending'
     and i.expires_at > now()
   order by i.created_at desc
   limit 1;
$$;


ALTER FUNCTION "public"."my_pending_invite"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."my_school_routes_today"("p_organization_id" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_today date := public.fn_org_today(p_organization_id);
  v_dow smallint := extract(isodow from v_today)::smallint;
begin
  if auth.uid() is null then raise exception 'Not authenticated'; end if;
  if not public.fn_org_feature_internal(p_organization_id, 'school') then return '[]'::jsonb; end if;
  return coalesce((
    select jsonb_agg(route_json order by start_time nulls last, route_name)
    from (
      select r.scheduled_start_time as start_time, r.name as route_name,
        (select jsonb_build_object(
          'id', r.id, 'name', r.name, 'route_type', r.route_type,
          'scheduled_start_time', r.scheduled_start_time,
          'vehicle_id', crew.vehicle_id,
          'my_role', case when crew.driver_id = auth.uid() then 'driver' else 'monitor' end,
          'school', (select ss.name from public.school_sites ss where ss.id = r.school_site_id),
          'run', (select jsonb_build_object('id', rr.id, 'status', rr.status, 'started_at', rr.started_at,
                                            'completed_at', rr.completed_at)
                    from public.route_runs rr where rr.id = run.id),
          'stops', coalesce((
            select jsonb_agg(stop_json order by seq)
            from (
              select s.seq,
                jsonb_build_object(
                  'id', s.id, 'seq', s.seq, 'name', s.name, 'address', s.address,
                  'latitude', s.latitude, 'longitude', s.longitude, 'radius_meters', s.radius_meters,
                  'scheduled_time', s.scheduled_time, 'stop_kind', s.stop_kind,
                  'arrived_at', (select e.arrived_at from public.route_stop_events e
                                  where e.stop_id = s.id and e.run_id = run.id),
                  'departed_at', (select e.departed_at from public.route_stop_events e
                                   where e.stop_id = s.id and e.run_id = run.id),
                  'students', coalesce((
                    select jsonb_agg(jsonb_build_object(
                      'id', st.id, 'name', st.first_name || coalesce(' ' || st.last_initial || '.', ''),
                      'grade', st.grade, 'action', a.action,
                      'done', exists (select 1 from public.ridership_events re
                                       where re.run_id = run.id and re.student_id = st.id and re.action = a.action),
                      'status', public.fn_rider_status(r.id, run.id, s.id, st.id, a.action),
                      'release_reason', (select re.reason from public.ridership_events re
                                          where re.run_id = run.id and re.student_id = st.id and re.action = 'released'),
                      'release_note', (select re.note from public.ridership_events re
                                        where re.run_id = run.id and re.student_id = st.id and re.action = 'released'),
                      'notice', (select jsonb_build_object('reason', n.reason,
                                                           'will_attend_school', n.will_attend_school,
                                                           'note', n.note)
                                   from public.student_ride_notices n
                                  where n.student_id = st.id and n.notice_date = v_today
                                    and n.part in ('both', case when r.route_type = 'school_pm' then 'pm' else 'am' end)))
                      order by st.first_name)
                      from (
                        select sa.student_id, sa.action
                          from public.student_stop_assignments sa
                         where sa.stop_id = s.id
                        union all
                        select b.student_id, 'alight'::text
                          from public.student_stop_assignments b
                         where b.route_id = r.id and b.action = 'board'
                           and s.seq = (select max(s2.seq) from public.route_stops s2 where s2.route_id = r.id)
                           and not exists (select 1 from public.student_stop_assignments x
                                            where x.route_id = r.id and x.student_id = b.student_id and x.action = 'alight')
                      ) a
                      join public.students st on st.id = a.student_id and st.is_active), '[]'::jsonb)) as stop_json
              from public.route_stops s where s.route_id = r.id
            ) stops_q), '[]'::jsonb))) as route_json
      from public.routes r
      cross join lateral public.fn_route_crew(r.id, v_today) crew
      left join lateral (select rr.id from public.route_runs rr
                          where rr.route_id = r.id and rr.run_date = v_today) run on true
     where r.organization_id = p_organization_id
       and (crew.driver_id = auth.uid() or crew.monitor_id = auth.uid())
       and r.route_type in ('school_am', 'school_pm')
       and r.status = 'active'
       and v_dow = any (r.service_days)
    ) q
  ), '[]'::jsonb);
end $$;


ALTER FUNCTION "public"."my_school_routes_today"("p_organization_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."my_shift_today"("p_organization_id" "uuid") RETURNS TABLE("shift_id" "uuid", "vehicle_id" "uuid", "start_time" time without time zone, "end_time" time without time zone, "status" "text")
    LANGUAGE "plpgsql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_tz text;
  v_now timestamp;
begin
  if not public.is_org_member(p_organization_id) then
    raise exception 'Not authorized for this organization';
  end if;
  if not public.fn_org_feature_internal(p_organization_id, 'shift_schedules') then
    return;
  end if;
  select coalesce(timezone, 'America/New_York') into v_tz from public.organizations where id = p_organization_id;
  v_now := now() at time zone v_tz;

  return query
  select s.id, s.vehicle_id, s.start_time, s.end_time,
    case
      when v_now::time >= s.start_time - interval '60 minutes'
       and (v_now::time <= s.end_time or s.end_time <= s.start_time) then 'open'
      when v_now::time < s.start_time - interval '60 minutes' then 'upcoming'
      else 'ended'
    end
  from public.shifts s
  where s.organization_id = p_organization_id
    and s.driver_id = auth.uid()
    and s.is_active
    and s.day_of_week = extract(dow from v_now)::int
  order by
    case
      when v_now::time >= s.start_time - interval '60 minutes'
       and (v_now::time <= s.end_time or s.end_time <= s.start_time) then 0
      when v_now::time < s.start_time then 1
      else 2
    end,
    s.start_time;
end;
$$;


ALTER FUNCTION "public"."my_shift_today"("p_organization_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."public_pricing_catalog"() RETURNS "jsonb"
    LANGUAGE "sql" STABLE SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
  select jsonb_build_object(
    'plans', (select jsonb_agg(to_jsonb(p) - 'sort' order by p.sort) from public.fleet_plans p),
    'acquisition', (select jsonb_agg(jsonb_build_object('service', f.service, 'tier', f.tier, 'cents', f.cents)
                                      order by f.service, f.tier)
                      from public.service_license_fees f),
    'services', (select jsonb_agg(jsonb_build_object(
                          'service', s.service,
                          'features', jsonb_build_object(
                            'starter', public.fn_plan_features(s.service, 1),
                            'growth', public.fn_plan_features(s.service, 2),
                            'enterprise', public.fn_plan_features(s.service, 3)))
                        order by s.service)
                   from (select distinct service from public.service_license_fees) s));
$$;


ALTER FUNCTION "public"."public_pricing_catalog"() OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."recompute_personal_entitlements"("p_user" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_base boolean;
  v_premium boolean;
begin
  with sources as (
    select tier from public.play_subscriptions
     where user_id = p_user
       and expiry_time > now()
       and state in ('SUBSCRIPTION_STATE_ACTIVE',
                     'SUBSCRIPTION_STATE_IN_GRACE_PERIOD',
                     'SUBSCRIPTION_STATE_CANCELED')
    union all
    select coalesce(tier, 'premium') from public.subscriptions
     where user_id = p_user
       and status in ('active', 'trialing')
       and (current_period_end is null or current_period_end > now())
  )
  select count(*) > 0, bool_or(tier = 'premium')
    into v_base, v_premium
    from sources;

  update public.profiles
     set base_entitled = coalesce(v_base, false),
         premium_entitled = coalesce(v_premium, false)
   where id = p_user;

  -- Weekly and monthly photos are a Premium choice: without Premium, back to annual.
  if not coalesce(v_premium, false) then
    update public.vehicles v
       set odometer_cycle = 'annual'
     where v.owner_user_id = p_user
       and v.organization_id is null
       and v.odometer_cycle <> 'annual'
       and not exists (select 1 from public.profiles p where p.id = p_user and p.tier_enforcement_exempt);
  end if;
end;
$$;


ALTER FUNCTION "public"."recompute_personal_entitlements"("p_user" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."record_ridership"("p_run_id" "uuid", "p_stop_id" "uuid", "p_student_id" "uuid", "p_action" "text", "p_done" boolean, "p_reason" "text" DEFAULT NULL::"text", "p_note" "text" DEFAULT NULL::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_run public.route_runs%rowtype := public.fn_my_crew_run(p_run_id);
  v_assign_action text := case when p_action = 'released' then 'board' else p_action end;
begin
  if p_action not in ('board', 'alight', 'released') then raise exception 'Invalid action'; end if;
  if not exists (
    select 1 from public.student_stop_assignments
     where student_id = p_student_id and route_id = v_run.route_id and stop_id = p_stop_id and action = v_assign_action
  ) and not (
    -- Planned pick-up with no planned drop-off: dropped off at the last stop.
    p_action = 'alight'
    and p_stop_id = (select s2.id from public.route_stops s2 where s2.route_id = v_run.route_id order by s2.seq desc limit 1)
    and exists (select 1 from public.student_stop_assignments b
                 where b.student_id = p_student_id and b.route_id = v_run.route_id and b.action = 'board')
    and not exists (select 1 from public.student_stop_assignments x
                     where x.student_id = p_student_id and x.route_id = v_run.route_id and x.action = 'alight')
  ) then
    raise exception 'Student is not assigned to this stop';
  end if;
  if p_done then
    if p_action = 'released' and p_reason is null then
      raise exception 'RELEASE_REASON_REQUIRED';
    end if;
    insert into public.ridership_events (organization_id, run_id, stop_id, student_id, action, reason, note, recorded_by)
    values (v_run.organization_id, p_run_id, p_stop_id, p_student_id, p_action,
            case when p_action = 'released' then p_reason end,
            case when p_action = 'released' then nullif(trim(p_note), '') end,
            auth.uid())
    on conflict (run_id, student_id, action)
      do update set reason = excluded.reason, note = excluded.note, at = now(), recorded_by = excluded.recorded_by;
    if p_action = 'board' then
      delete from public.ridership_events where run_id = p_run_id and student_id = p_student_id and action = 'released';
    elsif p_action = 'released' then
      delete from public.ridership_events where run_id = p_run_id and student_id = p_student_id and action = 'board';
    end if;
  else
    delete from public.ridership_events
     where run_id = p_run_id and student_id = p_student_id and action = p_action;
  end if;
end $$;


ALTER FUNCTION "public"."record_ridership"("p_run_id" "uuid", "p_stop_id" "uuid", "p_student_id" "uuid", "p_action" "text", "p_done" boolean, "p_reason" "text", "p_note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."redeem_report_access_code"("p_code" "text", "p_ip_hash" "text") RETURNS TABLE("success" boolean, "message" "text", "report" "jsonb")
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_recent_failures int;
  v_hash text;
  v_report record;
begin
  select count(*) into v_recent_failures
  from public.report_access_attempts raa
  where raa.ip_hash = p_ip_hash
    and raa.success = false
    and raa.attempted_at > now() - interval '15 minutes';

  if v_recent_failures >= 5 then
    return query select false, 'Too many attempts. Try again later.', null::jsonb;
    return;
  end if;

  v_hash := encode(digest(coalesce(p_code, ''), 'sha256'), 'hex');

  select * into v_report
  from public.reports r
  where r.qr_token = v_hash
    and r.qr_expires_at > now()
    and r.qr_uses < r.qr_max_uses
  limit 1;

  if not found then
    insert into public.report_access_attempts (ip_hash, success, report_id)
    values (p_ip_hash, false, null);
    return query select false, 'Invalid or expired code.', null::jsonb;
    return;
  end if;

  update public.reports set qr_uses = qr_uses + 1 where id = v_report.id;

  insert into public.report_access_attempts (ip_hash, success, report_id)
  values (p_ip_hash, true, v_report.id);

  return query select true, 'ok', v_report.metadata;
end;
$$;


ALTER FUNCTION "public"."redeem_report_access_code"("p_code" "text", "p_ip_hash" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."register_my_own_vehicle"("p_organization_id" "uuid", "p_make" "text", "p_model" "text", "p_year" integer DEFAULT NULL::integer, "p_plate" "text" DEFAULT NULL::"text", "p_vin" "text" DEFAULT NULL::"text") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_id uuid;
  v_allowed boolean;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;
  if not exists (
    select 1 from public.organization_members
    where organization_id = p_organization_id and user_id = auth.uid() and is_active
  ) then
    raise exception 'Not authorized for this organization';
  end if;
  perform public.fn_require_org_feature(p_organization_id, 'owner_operators');
  select allow_driver_owned_vehicles into v_allowed from public.organizations where id = p_organization_id;
  if not coalesce(v_allowed, false) then
    raise exception 'Your fleet doesn''t allow drivers to use their own vehicle. Ask your fleet admin.';
  end if;
  if nullif(btrim(p_make), '') is null or nullif(btrim(p_model), '') is null then
    raise exception 'Enter the make and model of your vehicle.';
  end if;
  if p_year is not null and (p_year < 1980 or p_year > extract(year from now())::int + 1) then
    raise exception 'Enter a valid year.';
  end if;
  if exists (
    select 1 from public.vehicles
    where organization_id = p_organization_id and owner_user_id = auth.uid()
      and ownership = 'driver_owned' and not is_archived
  ) then
    raise exception 'You already registered your own vehicle with this fleet.';
  end if;
  insert into public.vehicles (organization_id, owner_user_id, assigned_driver_id, ownership, make, model, year, plate, vin)
  values (p_organization_id, auth.uid(), auth.uid(), 'driver_owned',
          btrim(p_make), btrim(p_model), p_year, nullif(btrim(p_plate), ''), nullif(upper(btrim(p_vin)), ''))
  returning id into v_id;
  return v_id;
end;
$$;


ALTER FUNCTION "public"."register_my_own_vehicle"("p_organization_id" "uuid", "p_make" "text", "p_model" "text", "p_year" integer, "p_plate" "text", "p_vin" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."remove_driver_from_org"("p_org_id" "uuid", "p_user_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if not public.is_org_operator_or_above(p_org_id) then
    raise exception 'Only an org admin, owner, or operator can remove a driver';
  end if;

  update public.organization_members
  set is_active = false
  where organization_id = p_org_id and user_id = p_user_id and member_role = 'driver';

  if not found then
    raise exception 'No active driver membership found for that user in this organization';
  end if;
end;
$$;


ALTER FUNCTION "public"."remove_driver_from_org"("p_org_id" "uuid", "p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."report_permission_status"("p_app_version" "text", "p_os_version" "text", "p_device_model" "text", "p_location_state" "text", "p_location_always" boolean, "p_notifications" boolean, "p_motion" boolean, "p_camera" boolean, "p_battery_unrestricted" boolean, "p_usage_access" boolean, "p_exact_alarm" boolean) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'pg_temp'
    AS $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;
  if p_location_state is not null and p_location_state not in ('precise', 'approximate', 'denied') then
    raise exception 'invalid location_state' using errcode = '22023';
  end if;

  insert into public.device_permission_status as d (
    user_id, app_version, os_version, device_model, location_state, location_always,
    notifications, motion, camera, battery_unrestricted, usage_access, exact_alarm, reported_at
  ) values (
    v_uid, left(p_app_version, 40), left(p_os_version, 40), left(p_device_model, 80), p_location_state,
    p_location_always, p_notifications, p_motion, p_camera, p_battery_unrestricted, p_usage_access,
    p_exact_alarm, now()
  )
  on conflict (user_id) do update set
    app_version = excluded.app_version,
    os_version = excluded.os_version,
    device_model = excluded.device_model,
    location_state = excluded.location_state,
    location_always = excluded.location_always,
    notifications = excluded.notifications,
    motion = excluded.motion,
    camera = excluded.camera,
    battery_unrestricted = excluded.battery_unrestricted,
    usage_access = excluded.usage_access,
    exact_alarm = excluded.exact_alarm,
    reported_at = now();
end;
$$;


ALTER FUNCTION "public"."report_permission_status"("p_app_version" "text", "p_os_version" "text", "p_device_model" "text", "p_location_state" "text", "p_location_always" boolean, "p_notifications" boolean, "p_motion" boolean, "p_camera" boolean, "p_battery_unrestricted" boolean, "p_usage_access" boolean, "p_exact_alarm" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."report_student_no_ride"("p_student_id" "uuid", "p_date" "date", "p_part" "text", "p_reason" "text", "p_will_attend" boolean, "p_note" "text" DEFAULT NULL::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_role text := public.fn_ride_notice_role(p_student_id);
  v_org uuid := (select organization_id from public.students where id = p_student_id);
  v_today date := public.fn_org_today(v_org);
begin
  if p_date is null or p_date < v_today or p_date > v_today + 30 then
    raise exception 'NOTICE_DATE_OUT_OF_RANGE';
  end if;
  if p_part not in ('am', 'pm', 'both') then raise exception 'Invalid part'; end if;
  if p_reason not in ('medical', 'overslept', 'sick', 'other') then raise exception 'Invalid reason'; end if;
  insert into public.student_ride_notices
    (organization_id, student_id, notice_date, part, reason, will_attend_school, note, reported_by, reported_by_role)
  values
    (v_org, p_student_id, p_date, p_part, p_reason, coalesce(p_will_attend, true),
     nullif(left(trim(coalesce(p_note, '')), 300), ''), auth.uid(), v_role)
  on conflict (student_id, notice_date) do update
    set part = excluded.part, reason = excluded.reason, will_attend_school = excluded.will_attend_school,
        note = excluded.note, reported_by = excluded.reported_by, reported_by_role = excluded.reported_by_role,
        created_at = now();
end $$;


ALTER FUNCTION "public"."report_student_no_ride"("p_student_id" "uuid", "p_date" "date", "p_part" "text", "p_reason" "text", "p_will_attend" boolean, "p_note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."resolve_driver_invite"("p_token" "text") RETURNS TABLE("valid" boolean, "organization_name" "text", "email" "text", "account_exists" boolean)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_hash text := encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_invite record;
  v_allowed boolean;
begin
  select public.check_rate_limit('resolve_driver_invite', v_hash, 20, 60) into v_allowed;
  if not v_allowed then
    return query select false, null::text, null::text, null::boolean;
    return;
  end if;

  select i.email, i.organization_id, o.name as org_name
  into v_invite
  from public.driver_invites i
  join public.organizations o on o.id = i.organization_id
  where i.token_hash = v_hash
    and i.status = 'pending'
    and i.expires_at > now()
  limit 1;

  if not found then
    return query select false, null::text, null::text, null::boolean;
    return;
  end if;

  return query select
    true,
    v_invite.org_name,
    v_invite.email,
    exists(select 1 from public.profiles where lower(profiles.email) = lower(v_invite.email));
end;
$$;


ALTER FUNCTION "public"."resolve_driver_invite"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."resolve_guardian_invite"("p_token" "text") RETURNS TABLE("valid" boolean, "org_name" "text", "email" "text", "display_id" "text", "has_account" boolean)
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public', 'extensions'
    AS $$
declare
  v_hash text := encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
  v_allowed boolean;
  r record;
begin
  select public.check_rate_limit('resolve_guardian_invite', v_hash, 20, 60) into v_allowed;
  if not v_allowed then
    return query select false, null::text, null::text, null::text, null::boolean; return;
  end if;
  select o.name, i.email, g.display_id into r
    from public.guardian_invites i
    join public.school_guardians g on g.id = i.guardian_id and g.is_active
    join public.organizations o on o.id = i.organization_id
   where i.token_hash = v_hash and i.status = 'pending' and i.expires_at > now();
  if not found then
    return query select false, null::text, null::text, null::text, null::boolean; return;
  end if;
  return query select true, r.name::text, r.email::text, r.display_id::text,
    exists (select 1 from public.profiles p where lower(p.email) = lower(r.email));
end $$;


ALTER FUNCTION "public"."resolve_guardian_invite"("p_token" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."respond_to_invite"("p_membership_id" "uuid", "p_accept" boolean) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
DECLARE
  v_org_id uuid;
  v_user_id uuid;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Not authenticated';
  END IF;

  SELECT organization_id, user_id INTO v_org_id, v_user_id
  FROM public.organization_members
  WHERE id = p_membership_id AND is_active = false;

  IF v_org_id IS NULL THEN
    RAISE EXCEPTION 'No pending invite found';
  END IF;

  IF v_user_id != auth.uid() THEN
    RAISE EXCEPTION 'This invite does not belong to you';
  END IF;

  IF p_accept THEN
    UPDATE public.organization_members
    SET is_active = true, joined_at = now()
    WHERE id = p_membership_id;

    UPDATE public.profiles
    SET account_type = 'fleet_driver', default_org_id = v_org_id
    WHERE id = auth.uid();
  ELSE
    DELETE FROM public.organization_members WHERE id = p_membership_id;
  END IF;
END;
$$;


ALTER FUNCTION "public"."respond_to_invite"("p_membership_id" "uuid", "p_accept" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."review_fuel_anomaly"("p_anomaly_id" "uuid", "p_status" "text", "p_note" "text" DEFAULT NULL::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.fuel_anomalies where id = p_anomaly_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  perform public.fn_require_org_feature(v_org, 'fuel_alerts');
  if p_status not in ('open', 'dismissed', 'confirmed') then
    raise exception 'Unknown status: %', p_status;
  end if;
  update public.fuel_anomalies
  set status = p_status,
      review_note = nullif(btrim(p_note), ''),
      reviewed_by = case when p_status = 'open' then null else auth.uid() end,
      reviewed_at = case when p_status = 'open' then null else now() end
  where id = p_anomaly_id;
end;
$$;


ALTER FUNCTION "public"."review_fuel_anomaly"("p_anomaly_id" "uuid", "p_status" "text", "p_note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."revoke_guardian"("p_guardian_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare v_org uuid;
begin
  select organization_id into v_org from public.school_guardians where id = p_guardian_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then raise exception 'Not authorized'; end if;
  update public.school_guardians set is_active = false, revoked_at = now() where id = p_guardian_id;
  update public.guardian_invites set status = 'revoked' where guardian_id = p_guardian_id and status = 'pending';
end $$;


ALTER FUNCTION "public"."revoke_guardian"("p_guardian_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."service_for_industry"("p_industry" "text") RETURNS "text"
    LANGUAGE "sql" IMMUTABLE
    AS $$
  select case p_industry
    when 'driving_school'   then 'driving_school'
    when 'school_transport' then 'school_bus'
    when 'sales'            then 'sales'
    when 'trucking'         then 'trucking'
    else 'general_business'
  end
$$;


ALTER FUNCTION "public"."service_for_industry"("p_industry" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_active_vehicle"("p_vehicle_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
begin
  update public.vehicles
  set is_active = false, is_primary = false
  where owner_user_id = auth.uid()
    and is_archived = false
    and is_active = true;

  update public.vehicles
  set is_active = true, is_primary = true
  where id = p_vehicle_id
    and owner_user_id = auth.uid();
end;
$$;


ALTER FUNCTION "public"."set_active_vehicle"("p_vehicle_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_branch_manager"("p_branch_id" "uuid", "p_user_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.branches where id = p_branch_id;
  if v_org is null or not public.is_org_owner(v_org) then raise exception 'Only the owner assigns branch admins'; end if;
  if p_user_id is not null and not exists (
    select 1 from public.organization_members
     where organization_id = v_org and user_id = p_user_id and is_active and member_role in ('admin', 'owner')
  ) then
    raise exception 'Pick an admin of this fleet' using errcode = 'P0001';
  end if;
  update public.branches set manager_id = p_user_id where id = p_branch_id;
end $$;


ALTER FUNCTION "public"."set_branch_manager"("p_branch_id" "uuid", "p_user_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_owner(p_organization_id) then
    raise exception 'FLEET_TYPE_OWNER_ONLY';
  end if;
  if not coalesce(public.fn_valid_fleet_profile(p_industry_template), false) then
    raise exception 'Unknown fleet type: %', p_industry_template;
  end if;
  if exists (
    select 1 from public.organizations
     where id = p_organization_id and fleet_type_confirmed_at is not null
  ) then
    raise exception 'FLEET_TYPE_LOCKED';
  end if;

  update public.organizations
     set industry_template = p_industry_template,
         require_pretrip_inspection = public.fn_profile_requires_pretrip(p_industry_template),
         fleet_type_confirmed_at = now()
   where id = p_organization_id;

  insert into public.fleet_type_changes (organization_id, from_type, to_type, changed_by, source)
  values (p_organization_id, null, p_industry_template, auth.uid(), 'onboarding');
end;
$$;


ALTER FUNCTION "public"."set_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_member_admin"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_admin" boolean) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if not public.is_org_owner(p_org_id) then
    raise exception 'Only the organization owner can assign admins';
  end if;

  if public.fn_org_effective_tier(p_org_id) = 'none' then
    raise exception 'FLEET_SUBSCRIPTION_REQUIRED';
  end if;

  update public.organization_members
  set member_role = case when p_make_admin then 'admin' else 'driver' end
  where organization_id = p_org_id
    and user_id = p_user_id
    and member_role in ('driver', 'operator', 'admin');

  if not found then
    raise exception 'No active driver, operator, or admin membership found for that user in this organization';
  end if;
end;
$$;


ALTER FUNCTION "public"."set_member_admin"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_admin" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_member_branch"("p_organization_id" "uuid", "p_user_id" "uuid", "p_branch_id" "uuid", "p_any_branch" boolean) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_admin_or_owner(p_organization_id) then
    raise exception 'Not authorized';
  end if;
  if p_branch_id is not null and not exists (
    select 1 from public.branches where id = p_branch_id and organization_id = p_organization_id
  ) then
    raise exception 'That branch belongs to another fleet';
  end if;
  update public.organization_members
  set branch_id = case when coalesce(p_any_branch, false) then null else p_branch_id end,
      any_branch = coalesce(p_any_branch, false)
  where organization_id = p_organization_id and user_id = p_user_id;
end;
$$;


ALTER FUNCTION "public"."set_member_branch"("p_organization_id" "uuid", "p_user_id" "uuid", "p_branch_id" "uuid", "p_any_branch" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_member_languages"("p_organization_id" "uuid", "p_user_id" "uuid", "p_languages" "text"[]) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v text[] := array(select distinct x from unnest(p_languages) x where x in ('en', 'es') order by 1);
begin
  if not public.is_org_admin_or_owner(p_organization_id) then raise exception 'Not authorized'; end if;
  if cardinality(v) = 0 then raise exception 'Pick at least one language' using errcode = 'P0001'; end if;
  update public.organization_members set languages = v
   where organization_id = p_organization_id and user_id = p_user_id;
end $$;


ALTER FUNCTION "public"."set_member_languages"("p_organization_id" "uuid", "p_user_id" "uuid", "p_languages" "text"[]) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_member_operator"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_operator" boolean) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if not public.is_org_admin_or_owner(p_org_id) then
    raise exception 'Only an org admin or owner can assign operators';
  end if;

  if public.fn_org_effective_tier(p_org_id) = 'none' then
    raise exception 'FLEET_SUBSCRIPTION_REQUIRED';
  end if;

  update public.organization_members
  set member_role = case when p_make_operator then 'operator' else 'driver' end
  where organization_id = p_org_id
    and user_id = p_user_id
    and member_role in ('driver', 'operator');

  if not found then
    raise exception 'No active driver or operator membership found for that user in this organization';
  end if;
end;
$$;


ALTER FUNCTION "public"."set_member_operator"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_operator" boolean) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_report_branding"("p_organization_id" "uuid", "p_display_name" "text", "p_logo_path" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
begin
  if not public.is_org_admin_or_owner(p_organization_id) then
    raise exception 'Not authorized';
  end if;
  if p_logo_path is not null and split_part(p_logo_path, '/', 1) <> p_organization_id::text then
    raise exception 'Logo must be stored under the fleet''s folder';
  end if;
  update public.organizations
     set report_display_name = nullif(trim(p_display_name), ''),
         report_logo_path = p_logo_path
   where id = p_organization_id;
end $$;


ALTER FUNCTION "public"."set_report_branding"("p_organization_id" "uuid", "p_display_name" "text", "p_logo_path" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_trip_approval"("p_session_id" "uuid", "p_status" "text", "p_note" "text" DEFAULT NULL::"text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
  v_closed boolean;
begin
  select organization_id, coalesce(is_closed, false) into v_org, v_closed
  from public.sessions where id = p_session_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  perform public.fn_require_org_feature(v_org, 'trip_approval');
  if not v_closed then
    raise exception 'TRIP_NOT_FINISHED';
  end if;
  if p_status is null then
    delete from public.trip_approvals where session_id = p_session_id;
    return;
  end if;
  if p_status not in ('approved', 'rejected') then
    raise exception 'Unknown status: %', p_status;
  end if;
  insert into public.trip_approvals (session_id, organization_id, status, note, decided_by)
  values (p_session_id, v_org, p_status, nullif(btrim(p_note), ''), auth.uid())
  on conflict (session_id) do update
    set status = excluded.status, note = excluded.note,
        decided_by = excluded.decided_by, decided_at = now();
end;
$$;


ALTER FUNCTION "public"."set_trip_approval"("p_session_id" "uuid", "p_status" "text", "p_note" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_vehicle_branch"("p_vehicle_id" "uuid", "p_branch_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.vehicles where id = p_vehicle_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  if p_branch_id is not null and not exists (
    select 1 from public.branches where id = p_branch_id and organization_id = v_org
  ) then
    raise exception 'That branch belongs to another fleet';
  end if;
  update public.vehicles set branch_id = p_branch_id where id = p_vehicle_id;
end;
$$;


ALTER FUNCTION "public"."set_vehicle_branch"("p_vehicle_id" "uuid", "p_branch_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_vehicle_ifta"("p_vehicle_id" "uuid", "p_qualified" boolean, "p_fuel_type" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.vehicles where id = p_vehicle_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  perform public.fn_require_org_feature(v_org, 'ifta');
  if p_fuel_type not in ('diesel', 'gasoline') then
    raise exception 'Unknown fuel type: %', p_fuel_type;
  end if;
  update public.vehicles
  set ifta_qualified = coalesce(p_qualified, false), ifta_fuel_type = p_fuel_type
  where id = p_vehicle_id;
end;
$$;


ALTER FUNCTION "public"."set_vehicle_ifta"("p_vehicle_id" "uuid", "p_qualified" boolean, "p_fuel_type" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."set_vehicle_tank_capacity"("p_vehicle_id" "uuid", "p_gallons" numeric) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
begin
  select organization_id into v_org from public.vehicles where id = p_vehicle_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then
    raise exception 'Not authorized';
  end if;
  if p_gallons is not null and (p_gallons <= 0 or p_gallons > 1000) then
    raise exception 'Tank capacity must be between 1 and 1000 gallons';
  end if;
  update public.vehicles set fuel_tank_capacity_gal = p_gallons where id = p_vehicle_id;
  perform public.fn_evaluate_fuel_purchase(fp.id)
  from public.fuel_purchases fp
  where fp.vehicle_id = p_vehicle_id and fp.purchase_date >= current_date - 90;
end;
$$;


ALTER FUNCTION "public"."set_vehicle_tank_capacity"("p_vehicle_id" "uuid", "p_gallons" numeric) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."start_route_run"("p_route_id" "uuid", "p_session_id" "uuid") RETURNS "uuid"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_route public.routes%rowtype;
  v_session public.sessions%rowtype;
  v_today date;
  v_run_id uuid;
  v_status text;
  v_crew record;
begin
  select * into v_route from public.routes where id = p_route_id;
  if not found then
    raise exception 'ROUTE_NOT_ASSIGNED';
  end if;
  perform public.fn_require_org_feature(v_route.organization_id, 'school');
  v_today := public.fn_org_today(v_route.organization_id);
  select * into v_crew from public.fn_route_crew(p_route_id, v_today);
  if v_crew.driver_id is distinct from auth.uid() then
    raise exception 'ROUTE_NOT_ASSIGNED';
  end if;
  if v_route.status <> 'active' or v_route.route_type not in ('school_am', 'school_pm') then
    raise exception 'ROUTE_NOT_ACTIVE';
  end if;
  select * into v_session from public.sessions
   where id = p_session_id and user_id = auth.uid() and not coalesce(is_closed, false);
  if not found then
    raise exception 'TRIP_NOT_ACTIVE';
  end if;

  select id, status into v_run_id, v_status from public.route_runs
   where route_id = p_route_id and run_date = v_today;
  if v_status = 'completed' then
    raise exception 'ROUTE_ALREADY_COMPLETED';
  end if;
  if v_run_id is not null then
    update public.route_runs
       set session_id = p_session_id, vehicle_id = coalesce(v_session.vehicle_id, vehicle_id), driver_id = auth.uid(),
           monitor_id = v_crew.monitor_id, monitor_name = v_crew.monitor_name
     where id = v_run_id;
    perform public.fn_route_run_mark_current_stops(v_run_id);
    return v_run_id;
  end if;

  if exists (
    select 1 from public.route_runs
     where driver_id = auth.uid() and status = 'in_progress' and run_date = v_today
  ) then
    raise exception 'ANOTHER_ROUTE_IN_PROGRESS';
  end if;

  insert into public.route_runs (organization_id, route_id, run_date, driver_id, vehicle_id, session_id, monitor_name)
  values (v_route.organization_id, p_route_id, v_today, auth.uid(),
          coalesce(v_session.vehicle_id, v_crew.vehicle_id), p_session_id, v_crew.monitor_name)
  returning id into v_run_id;
  perform public.fn_route_run_mark_current_stops(v_run_id);
  return v_run_id;
end $$;


ALTER FUNCTION "public"."start_route_run"("p_route_id" "uuid", "p_session_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."start_shift_block"("p_block_id" "uuid") RETURNS "public"."shift_blocks"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_uid uuid := auth.uid();
  b public.shift_blocks;
  v_tz text;
  v_window int;
  v_start timestamptz;
  v_day public.driver_workdays;
begin
  select * into b from public.shift_blocks where id = p_block_id for update;
  if b.id is null or b.driver_id is distinct from v_uid then
    raise exception 'Class not found';
  end if;
  if b.status <> 'scheduled' then
    raise exception 'This class is not available to start';
  end if;

  select timezone, shift_start_window_minutes into v_tz, v_window
  from public.organizations where id = b.organization_id;
  v_start := (b.block_date + b.start_time) at time zone v_tz;

  if now() < v_start - make_interval(mins => v_window) then
    raise exception 'SHIFT_BLOCK_TOO_EARLY:%', to_char((v_start - make_interval(mins => v_window)) at time zone v_tz, 'HH12:MI AM');
  end if;
  if now() > v_start + make_interval(mins => v_window) then
    raise exception 'SHIFT_BLOCK_WINDOW_CLOSED';
  end if;
  if exists (select 1 from public.shift_blocks x
             where x.driver_id = v_uid and x.status = 'in_progress' and x.id <> b.id) then
    raise exception 'SHIFT_BLOCK_ANOTHER_IN_PROGRESS';
  end if;

  select * into v_day from public.driver_workdays
  where organization_id = b.organization_id and driver_id = v_uid and work_date = b.block_date;
  if v_day.closed_at is not null then
    raise exception 'WORKDAY_ALREADY_CLOSED';
  end if;
  if v_day.id is null then
    insert into public.driver_workdays (organization_id, driver_id, work_date)
    values (b.organization_id, v_uid, b.block_date);
  end if;

  perform set_config('cm.shift_block_rpc', 'on', true);
  update public.shift_blocks
     set status = 'in_progress',
         started_at = now(),
         late_minutes = greatest(0, floor(extract(epoch from (now() - v_start)) / 60))::int
   where id = b.id
   returning * into b;
  perform set_config('cm.shift_block_rpc', 'off', true);
  return b;
end $$;


ALTER FUNCTION "public"."start_shift_block"("p_block_id" "uuid") OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."fuel_purchases" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "user_id" "uuid",
    "organization_id" "uuid",
    "purchase_date" "date" NOT NULL,
    "state_code" "text",
    "gallons" numeric NOT NULL,
    "price_per_gallon_usd" numeric,
    "total_cost_usd" numeric,
    "fuel_type" "text" DEFAULT 'diesel'::"text" NOT NULL,
    "receipt_image_url" "text" NOT NULL,
    "file_hash" "text" NOT NULL,
    "ocr_source" boolean DEFAULT false NOT NULL,
    "ocr_confidence" numeric,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "vendor_name" "text",
    "tax_paid" boolean DEFAULT true NOT NULL,
    "receipt_path" "text" GENERATED ALWAYS AS (NULLIF("split_part"("receipt_image_url", '/object/public/fuel_receipts/'::"text", 2), ''::"text")) STORED,
    CONSTRAINT "fuel_purchases_fuel_type_check" CHECK (("fuel_type" = ANY (ARRAY['diesel'::"text", 'gasoline'::"text"]))),
    CONSTRAINT "fuel_purchases_gallons_check" CHECK (("gallons" > (0)::numeric)),
    CONSTRAINT "fuel_purchases_price_per_gallon_usd_check" CHECK ((("price_per_gallon_usd" IS NULL) OR ("price_per_gallon_usd" >= (0)::numeric))),
    CONSTRAINT "fuel_purchases_total_cost_usd_check" CHECK ((("total_cost_usd" IS NULL) OR ("total_cost_usd" >= (0)::numeric)))
);


ALTER TABLE "public"."fuel_purchases" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."submit_fuel_purchase"("p_vehicle_id" "uuid", "p_purchase_date" "date", "p_gallons" numeric, "p_state_code" "text" DEFAULT NULL::"text", "p_price_per_gallon_usd" numeric DEFAULT NULL::numeric, "p_total_cost_usd" numeric DEFAULT NULL::numeric, "p_fuel_type" "text" DEFAULT 'diesel'::"text", "p_receipt_image_url" "text" DEFAULT NULL::"text", "p_file_hash" "text" DEFAULT NULL::"text", "p_ocr_source" boolean DEFAULT false, "p_ocr_confidence" numeric DEFAULT NULL::numeric, "p_vendor_name" "text" DEFAULT NULL::"text") RETURNS "public"."fuel_purchases"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_owner uuid;
  v_org uuid;
  v_row public.fuel_purchases;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;
  if p_gallons is null or p_gallons <= 0 then
    raise exception 'Gallons must be greater than 0';
  end if;
  if p_receipt_image_url is null or p_file_hash is null then
    raise exception 'Receipt photo is required';
  end if;
  if coalesce(p_fuel_type, 'diesel') not in ('diesel', 'gasoline') then
    raise exception 'Unknown fuel type: %', p_fuel_type;
  end if;
  select owner_user_id, organization_id into v_owner, v_org
  from public.vehicles where id = p_vehicle_id;
  if not found then
    raise exception 'Vehicle not found';
  end if;
  if v_owner is distinct from auth.uid()
     and not (v_org is not null and public.is_org_member(v_org)) then
    raise exception 'Not authorized to log fuel for this vehicle';
  end if;
  if p_state_code is not null and not exists (
    select 1 from public.ifta_us_state_boundaries where state_code = p_state_code
  ) then
    raise exception 'Unknown state_code: %', p_state_code;
  end if;
  insert into public.fuel_purchases (
    vehicle_id, user_id, organization_id, purchase_date, state_code,
    gallons, price_per_gallon_usd, total_cost_usd, fuel_type,
    receipt_image_url, file_hash, ocr_source, ocr_confidence, vendor_name
  )
  values (
    p_vehicle_id, auth.uid(), v_org, p_purchase_date, p_state_code,
    p_gallons, p_price_per_gallon_usd, p_total_cost_usd, coalesce(p_fuel_type, 'diesel'),
    p_receipt_image_url, p_file_hash, p_ocr_source, p_ocr_confidence,
    nullif(btrim(p_vendor_name), '')
  )
  returning * into v_row;
  return v_row;
end;
$$;


ALTER FUNCTION "public"."submit_fuel_purchase"("p_vehicle_id" "uuid", "p_purchase_date" "date", "p_gallons" numeric, "p_state_code" "text", "p_price_per_gallon_usd" numeric, "p_total_cost_usd" numeric, "p_fuel_type" "text", "p_receipt_image_url" "text", "p_file_hash" "text", "p_ocr_source" boolean, "p_ocr_confidence" numeric, "p_vendor_name" "text") OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicle_inspections" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "user_id" "uuid",
    "organization_id" "uuid",
    "inspection_type" "text" NOT NULL,
    "overall_status" "text" NOT NULL,
    "items" "jsonb" DEFAULT '[]'::"jsonb" NOT NULL,
    "odometer" numeric,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "vehicle_inspections_inspection_type_check" CHECK (("inspection_type" = ANY (ARRAY['pre_trip'::"text", 'post_trip'::"text"]))),
    CONSTRAINT "vehicle_inspections_overall_status_check" CHECK (("overall_status" = ANY (ARRAY['pass'::"text", 'fail'::"text"])))
);


ALTER TABLE "public"."vehicle_inspections" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."submit_vehicle_inspection"("p_vehicle_id" "uuid", "p_inspection_type" "text", "p_items" "jsonb", "p_odometer" numeric DEFAULT NULL::numeric) RETURNS "public"."vehicle_inspections"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_owner uuid;
  v_org uuid;
  v_defect_count int;
  v_overall text;
  v_inspection public.vehicle_inspections;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if p_inspection_type not in ('pre_trip', 'post_trip') then
    raise exception 'Invalid inspection_type: %', p_inspection_type;
  end if;

  select owner_user_id, organization_id into v_owner, v_org
  from public.vehicles
  where id = p_vehicle_id;

  if not found then
    raise exception 'Vehicle not found';
  end if;

  if v_owner is distinct from auth.uid()
     and not (v_org is not null and public.is_org_member(v_org)) then
    raise exception 'Not authorized to inspect this vehicle';
  end if;
  if v_org is not null then
    perform public.fn_require_org_feature(v_org, 'dvir');
  end if;


  select count(*) into v_defect_count
  from jsonb_array_elements(p_items) elem
  where elem->>'status' = 'defect';

  v_overall := case when v_defect_count > 0 then 'fail' else 'pass' end;

  insert into public.vehicle_inspections (
    vehicle_id, user_id, organization_id, inspection_type, overall_status, items, odometer
  )
  values (
    p_vehicle_id, auth.uid(), v_org, p_inspection_type, v_overall, p_items, p_odometer
  )
  returning * into v_inspection;

  if v_overall = 'fail' then
    insert into public.vehicle_maintenance_records (
      vehicle_id, user_id, organization_id, type, performed_at, odometer_at_service, notes
    )
    values (
      p_vehicle_id, auth.uid(), v_org, 'other', current_date, p_odometer,
      'Auto-created from failed ' || p_inspection_type || ' inspection: ' ||
      coalesce(
        (select string_agg(elem->>'category', ', ')
         from jsonb_array_elements(p_items) elem
         where elem->>'status' = 'defect'),
        ''
      )
    );
  end if;

  return v_inspection;
end;
$$;


ALTER FUNCTION "public"."submit_vehicle_inspection"("p_vehicle_id" "uuid", "p_inspection_type" "text", "p_items" "jsonb", "p_odometer" numeric) OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicle_odometer_checkpoints" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "organization_id" "uuid",
    "week_start_date" "date" NOT NULL,
    "start_odometer_value" numeric,
    "start_odometer_image_url" "text",
    "start_file_hash" "text",
    "start_captured_by" "uuid",
    "start_captured_at" timestamp with time zone,
    "start_ocr_source" boolean,
    "start_ocr_confidence" numeric,
    "end_odometer_value" numeric,
    "end_odometer_image_url" "text",
    "end_file_hash" "text",
    "end_captured_by" "uuid",
    "end_captured_at" timestamp with time zone,
    "end_ocr_source" boolean,
    "end_ocr_confidence" numeric,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "vehicle_odometer_checkpoints_check" CHECK ((("start_odometer_value" IS NULL) OR ("end_odometer_value" IS NULL) OR ("end_odometer_value" >= "start_odometer_value")))
);


ALTER TABLE "public"."vehicle_odometer_checkpoints" OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."submit_vehicle_odometer_checkpoint"("p_vehicle_id" "uuid", "p_odometer_value" numeric, "p_odometer_image_url" "text", "p_file_hash" "text" DEFAULT NULL::"text", "p_ocr_source" boolean DEFAULT false, "p_ocr_confidence" numeric DEFAULT NULL::numeric, "p_capture_date" "date" DEFAULT ("timezone"('utc'::"text", "now"()))::"date") RETURNS "public"."vehicle_odometer_checkpoints"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_vehicle record;
  v_caller uuid := auth.uid();
  v_week_start date;
  v_year_row_start date;
  v_prev_open record;
  v_prev_open_found boolean;
  v_current record;
  v_result public.vehicle_odometer_checkpoints;
begin
  if v_caller is null then
    raise exception 'AUTH_REQUIRED';
  end if;

  if p_odometer_value is null or p_odometer_value < 0 then
    raise exception 'INVALID_ODOMETER_VALUE';
  end if;

  if p_capture_date is null
     or abs(p_capture_date - (timezone('utc', now()))::date) > 1 then
    raise exception 'INVALID_CAPTURE_DATE';
  end if;

  select * into v_vehicle from public.vehicles where id = p_vehicle_id;
  if v_vehicle is null then
    raise exception 'VEHICLE_NOT_FOUND';
  end if;

  if not (
    v_vehicle.owner_user_id = v_caller
    or v_vehicle.assigned_driver_id = v_caller
    or (v_vehicle.organization_id is not null and public.is_org_member(v_vehicle.organization_id))
  ) then
    raise exception 'NOT_AUTHORIZED';
  end if;

  if v_vehicle.odometer is not null and p_odometer_value < v_vehicle.odometer then
    raise exception 'ODOMETER_BELOW_REGISTERED:%', v_vehicle.odometer;
  end if;

  v_week_start := public.fn_odometer_cycle_start(p_vehicle_id, p_capture_date);

  if v_vehicle.odometer_cycle = 'annual' then
    select week_start_date into v_year_row_start
    from public.vehicle_odometer_checkpoints
    where vehicle_id = p_vehicle_id
      and week_start_date >= date_trunc('year', p_capture_date)::date
      and week_start_date < (date_trunc('year', p_capture_date) + interval '1 year')::date
    order by week_start_date desc
    limit 1;
    if found then
      v_week_start := v_year_row_start;
    end if;
  end if;

  select * into v_prev_open
  from public.vehicle_odometer_checkpoints
  where vehicle_id = p_vehicle_id
    and week_start_date < v_week_start
    and start_odometer_value is not null
    and end_odometer_value is null
  order by week_start_date desc
  limit 1;
  v_prev_open_found := found;

  if v_prev_open_found then
    update public.vehicle_odometer_checkpoints
    set end_odometer_value = p_odometer_value,
        end_odometer_image_url = p_odometer_image_url,
        end_file_hash = p_file_hash,
        end_captured_by = v_caller,
        end_captured_at = now(),
        end_ocr_source = p_ocr_source,
        end_ocr_confidence = p_ocr_confidence,
        updated_at = now()
    where id = v_prev_open.id;
  end if;

  select * into v_current
  from public.vehicle_odometer_checkpoints
  where vehicle_id = p_vehicle_id and week_start_date = v_week_start;

  if v_current is null then
    insert into public.vehicle_odometer_checkpoints (
      vehicle_id, organization_id, week_start_date,
      start_odometer_value, start_odometer_image_url, start_file_hash,
      start_captured_by, start_captured_at, start_ocr_source, start_ocr_confidence
    ) values (
      p_vehicle_id, v_vehicle.organization_id, v_week_start,
      p_odometer_value, p_odometer_image_url, p_file_hash,
      v_caller, now(), p_ocr_source, p_ocr_confidence
    )
    returning * into v_result;
  elsif v_current.start_odometer_value is null then
    update public.vehicle_odometer_checkpoints
    set start_odometer_value = p_odometer_value,
        start_odometer_image_url = p_odometer_image_url,
        start_file_hash = p_file_hash,
        start_captured_by = v_caller,
        start_captured_at = now(),
        start_ocr_source = p_ocr_source,
        start_ocr_confidence = p_ocr_confidence,
        updated_at = now()
    where id = v_current.id
    returning * into v_result;
  elsif v_current.end_odometer_value is null then
    update public.vehicle_odometer_checkpoints
    set end_odometer_value = p_odometer_value,
        end_odometer_image_url = p_odometer_image_url,
        end_file_hash = p_file_hash,
        end_captured_by = v_caller,
        end_captured_at = now(),
        end_ocr_source = p_ocr_source,
        end_ocr_confidence = p_ocr_confidence,
        updated_at = now()
    where id = v_current.id
    returning * into v_result;
  else
    raise exception 'WEEK_ALREADY_CLOSED';
  end if;

  update public.vehicles
  set odometer = greatest(coalesce(odometer, 0), p_odometer_value),
      updated_at = now()
  where id = p_vehicle_id;

  return v_result;
end;
$$;


ALTER FUNCTION "public"."submit_vehicle_odometer_checkpoint"("p_vehicle_id" "uuid", "p_odometer_value" numeric, "p_odometer_image_url" "text", "p_file_hash" "text", "p_ocr_source" boolean, "p_ocr_confidence" numeric, "p_capture_date" "date") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."suggest_regular_trip"("p_section_id" "uuid") RETURNS "jsonb"
    LANGUAGE "plpgsql" STABLE
    SET "search_path" TO 'public'
    AS $$
declare
  v public.session_sections%rowtype;
  v_count integer;
begin
  select * into v from public.session_sections s
  where s.id = p_section_id and s.user_id = auth.uid() and s.gig_app = 'custom'
    and s.organization_id is null and s.section_status = 'closed' and s.irs_purpose is not null
    and s.start_latitude is not null and s.end_latitude is not null;
  if not found then return null; end if;

  if not exists (select 1 from public.profiles p where p.id = auth.uid() and p.premium_entitled) then
    return null;
  end if;
  if exists (select 1 from public.trip_classification_settings c
             where c.user_id = auth.uid() and not (c.regular_enabled and c.suggestions_enabled)) then
    return null;
  end if;
  if exists (select 1 from public.regular_trips r
             where r.user_id = auth.uid()
               and public.fn_regular_trip_covers(r, v.start_latitude, v.start_longitude, v.end_latitude, v.end_longitude)) then
    return null;
  end if;

  select count(*) into v_count from public.session_sections s
  where s.user_id = auth.uid() and s.gig_app = 'custom' and s.organization_id is null
    and s.section_status = 'closed' and s.irs_purpose = v.irs_purpose
    and s.start_latitude is not null and s.end_latitude is not null
    and public.fn_cm_distance_m(s.start_latitude, s.start_longitude, v.start_latitude, v.start_longitude) <= 150
    and public.fn_cm_distance_m(s.end_latitude, s.end_longitude, v.end_latitude, v.end_longitude) <= 150;
  if v_count < 3 then return null; end if;

  return jsonb_build_object(
    'start_latitude', v.start_latitude, 'start_longitude', v.start_longitude, 'start_address', v.start_address,
    'end_latitude', v.end_latitude, 'end_longitude', v.end_longitude, 'end_address', v.end_address,
    'purpose', v.irs_purpose, 'count', v_count
  );
end;
$$;


ALTER FUNCTION "public"."suggest_regular_trip"("p_section_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."support_change_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text", "p_reason" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_old text;
begin
  if not coalesce(public.fn_valid_fleet_profile(p_industry_template), false) then
    raise exception 'Unknown fleet type: %', p_industry_template;
  end if;
  if coalesce(btrim(p_reason), '') = '' then
    raise exception 'A reason is required';
  end if;

  select industry_template into v_old from public.organizations where id = p_organization_id for update;
  if not found then
    raise exception 'Organization not found';
  end if;

  update public.organizations
     set industry_template = p_industry_template,
         require_pretrip_inspection = public.fn_profile_requires_pretrip(p_industry_template),
         fleet_type_confirmed_at = now()
   where id = p_organization_id;

  insert into public.fleet_type_changes (organization_id, from_type, to_type, source, reason)
  values (p_organization_id, v_old, p_industry_template, 'support', p_reason);
end;
$$;


ALTER FUNCTION "public"."support_change_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text", "p_reason" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."switch_account_mode"("p_mode" "text") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_caller uuid := auth.uid();
  v_current_org_id uuid;
  v_org_id uuid;
begin
  if v_caller is null then
    raise exception 'Not authenticated';
  end if;

  if p_mode not in ('gig', 'fleet_admin', 'fleet_driver') then
    raise exception 'Invalid mode';
  end if;

  if p_mode = 'gig' then
    update public.profiles set account_type = 'gig' where id = v_caller;
    return;
  end if;

  select default_org_id into v_current_org_id from public.profiles where id = v_caller;

  if p_mode = 'fleet_admin' then
    select organization_id into v_org_id
    from public.organization_members
    where user_id = v_caller and organization_id = v_current_org_id
      and member_role = 'owner' and is_active = true;

    if v_org_id is null then
      select organization_id into v_org_id
      from public.organization_members
      where user_id = v_caller and member_role = 'owner' and is_active = true
      order by joined_at asc
      limit 1;
    end if;

    if v_org_id is null then
      raise exception 'You do not own a fleet organization yet.';
    end if;

    update public.profiles
    set account_type = 'fleet_admin', default_org_id = v_org_id
    where id = v_caller;
    return;
  end if;

  if p_mode = 'fleet_driver' then
    select organization_id into v_org_id
    from public.organization_members
    where user_id = v_caller and organization_id = v_current_org_id
      and member_role = 'driver' and is_active = true;

    if v_org_id is null then
      select organization_id into v_org_id
      from public.organization_members
      where user_id = v_caller and member_role = 'driver' and is_active = true
      order by joined_at desc
      limit 1;
    end if;

    if v_org_id is null then
      raise exception 'You are not an active driver in any fleet.';
    end if;

    update public.profiles
    set account_type = 'fleet_driver', default_org_id = v_org_id
    where id = v_caller;
    return;
  end if;
end;
$$;


ALTER FUNCTION "public"."switch_account_mode"("p_mode" "text") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."switch_default_organization"("p_org_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_caller uuid := auth.uid();
  v_ok boolean;
begin
  if v_caller is null then
    raise exception 'Not authenticated';
  end if;

  select exists(
    select 1 from public.organization_members
    where organization_id = p_org_id and user_id = v_caller
      and member_role in ('owner', 'admin') and is_active = true
  ) into v_ok;

  if not v_ok then
    raise exception 'You are not an admin of that organization';
  end if;

  update public.profiles set default_org_id = p_org_id where id = v_caller;
end;
$$;


ALTER FUNCTION "public"."switch_default_organization"("p_org_id" "uuid") OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."session_sections" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "session_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "organization_id" "uuid",
    "gig_app" "text" DEFAULT 'custom'::"text" NOT NULL,
    "section_status" "text" DEFAULT 'active'::"text" NOT NULL,
    "start_time" timestamp with time zone DEFAULT "now"() NOT NULL,
    "end_time" timestamp with time zone,
    "total_miles" double precision DEFAULT 0 NOT NULL,
    "total_duration_seconds" integer DEFAULT 0 NOT NULL,
    "start_latitude" double precision,
    "start_longitude" double precision,
    "end_latitude" double precision,
    "end_longitude" double precision,
    "start_odometer_image_url" "text",
    "end_odometer_image_url" "text",
    "irs_purpose" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "notes" "text",
    "route_polyline" "text",
    "start_address" "text",
    "end_address" "text",
    "address_edited" boolean DEFAULT false NOT NULL,
    "auto_purpose_source" "text",
    CONSTRAINT "chk_irs_purpose_valid" CHECK ((("irs_purpose" IS NULL) OR ("irs_purpose" = ANY (ARRAY['business'::"text", 'work'::"text", 'medical'::"text", 'moving'::"text", 'charitable'::"text", 'education'::"text", 'personal'::"text", 'delivery'::"text", 'errand'::"text", 'client'::"text", 'travel'::"text"])))),
    CONSTRAINT "session_sections_address_len" CHECK (((COALESCE("length"("start_address"), 0) <= 300) AND (COALESCE("length"("end_address"), 0) <= 300))),
    CONSTRAINT "session_sections_auto_purpose_source_check" CHECK (("auto_purpose_source" = ANY (ARRAY['regular_trip'::"text", 'work_hours'::"text"]))),
    CONSTRAINT "session_sections_route_polyline_len" CHECK ((("route_polyline" IS NULL) OR ("length"("route_polyline") <= 20000))),
    CONSTRAINT "session_sections_section_status_check" CHECK (("section_status" = ANY (ARRAY['active'::"text", 'paused'::"text", 'closed'::"text", 'switched'::"text"])))
);


ALTER TABLE "public"."session_sections" OWNER TO "postgres";


COMMENT ON COLUMN "public"."session_sections"."notes" IS 'Nota libre del usuario sobre la sección (ej. "faltaron 5 millas"). Nunca se usa para editar total_miles/total_duration_seconds directamente -- las millas trackeadas son inmutables por diseño. Solo contexto.';



CREATE OR REPLACE FUNCTION "public"."switch_gig_app_section"("p_session_id" "uuid", "p_old_section_id" "uuid", "p_new_section_id" "uuid", "p_new_gig_app" "text", "p_new_irs_purpose" "text", "p_old_total_miles" double precision, "p_old_total_duration_seconds" integer, "p_old_end_latitude" double precision, "p_old_end_longitude" double precision) RETURNS SETOF "public"."session_sections"
    LANGUAGE "plpgsql"
    SET "search_path" TO 'public'
    AS $$
declare
  v_org_id uuid;
begin
  select organization_id into v_org_id from public.sessions where id = p_session_id;

  if p_old_section_id is not null then
    update session_sections
    set section_status = 'switched',
        end_time = now(),
        total_miles = coalesce(p_old_total_miles, total_miles),
        total_duration_seconds = coalesce(p_old_total_duration_seconds, total_duration_seconds),
        end_latitude = p_old_end_latitude,
        end_longitude = p_old_end_longitude
    where id = p_old_section_id
      and user_id = auth.uid()
      and section_status in ('active', 'paused');
  end if;

  insert into session_sections (
    id, session_id, user_id, organization_id, gig_app, irs_purpose,
    section_status, total_miles, total_duration_seconds, start_time
  )
  values (
    p_new_section_id, p_session_id, auth.uid(), v_org_id, p_new_gig_app,
    case when p_new_gig_app = 'custom' then p_new_irs_purpose else 'business' end,
    'active', 0, 0, now()
  );

  if p_old_section_id is not null then
    perform public.fn_drop_empty_switched_section(p_old_section_id, p_new_section_id);
  end if;

  return query select * from session_sections where id = p_new_section_id;
end;
$$;


ALTER FUNCTION "public"."switch_gig_app_section"("p_session_id" "uuid", "p_old_section_id" "uuid", "p_new_section_id" "uuid", "p_new_gig_app" "text", "p_new_irs_purpose" "text", "p_old_total_miles" double precision, "p_old_total_duration_seconds" integer, "p_old_end_latitude" double precision, "p_old_end_longitude" double precision) OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."unlink_guardian_student"("p_guardian_id" "uuid", "p_student_id" "uuid") RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare v_org uuid;
begin
  select organization_id into v_org from public.school_guardians where id = p_guardian_id;
  if v_org is null or not public.is_org_admin_or_owner(v_org) then raise exception 'Not authorized'; end if;
  update public.student_guardians set is_active = false, removed_at = now()
   where guardian_id = p_guardian_id and student_id = p_student_id and is_active;
end $$;


ALTER FUNCTION "public"."unlink_guardian_student"("p_guardian_id" "uuid", "p_student_id" "uuid") OWNER TO "postgres";


CREATE OR REPLACE FUNCTION "public"."update_vehicle_location"("p_vehicle_id" "uuid", "p_latitude" double precision, "p_longitude" double precision, "p_speed" double precision DEFAULT NULL::double precision) RETURNS "void"
    LANGUAGE "plpgsql" SECURITY DEFINER
    SET "search_path" TO 'public'
    AS $$
declare
  v_org uuid;
  v_assigned_driver uuid;
  v_authorized boolean;
  v_geofence record;
  v_distance double precision;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;
  select organization_id, assigned_driver_id into v_org, v_assigned_driver
  from public.vehicles where id = p_vehicle_id;
  if not found or v_org is null then
    return;
  end if;
  v_authorized := (v_assigned_driver = auth.uid())
    or exists (
      select 1 from public.sessions s
      where s.vehicle_id = p_vehicle_id and s.user_id = auth.uid() and not coalesce(s.is_closed, false)
    )
    or public.is_org_admin_or_owner(v_org);
  if not v_authorized then
    raise exception 'Not authorized to update this vehicle location';
  end if;
  if public.fn_org_feature_internal(v_org, 'live_map') then
    update public.vehicles
    set last_latitude = p_latitude, last_longitude = p_longitude, last_speed = p_speed, last_location_at = now()
    where id = p_vehicle_id;
  end if;
  for v_geofence in
    select id, center_latitude, center_longitude, radius_meters
    from public.vehicle_geofences
    where vehicle_id = p_vehicle_id and is_active = true
  loop
    v_distance := 6371000 * acos(
      least(1.0, greatest(-1.0,
        cos(radians(v_geofence.center_latitude)) * cos(radians(p_latitude)) *
          cos(radians(p_longitude) - radians(v_geofence.center_longitude)) +
        sin(radians(v_geofence.center_latitude)) * sin(radians(p_latitude))
      ))
    );
    if v_distance > v_geofence.radius_meters then
      if not exists (
        select 1 from public.vehicle_geofence_alerts
        where vehicle_id = p_vehicle_id and geofence_id = v_geofence.id
          and created_at > now() - interval '15 minutes'
      ) then
        insert into public.vehicle_geofence_alerts (vehicle_id, geofence_id, organization_id, latitude, longitude, distance_meters)
        values (p_vehicle_id, v_geofence.id, v_org, p_latitude, p_longitude, v_distance);
      end if;
    end if;
  end loop;
end;
$$;


ALTER FUNCTION "public"."update_vehicle_location"("p_vehicle_id" "uuid", "p_latitude" double precision, "p_longitude" double precision, "p_speed" double precision) OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "ops"."domain_allowed_functions" (
    "fn" "text" NOT NULL,
    "reason" "text" NOT NULL
);


ALTER TABLE "ops"."domain_allowed_functions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "ops"."domain_check_log" (
    "id" bigint NOT NULL,
    "checked_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "source" "text" NOT NULL,
    "violation_count" integer,
    "detail" "text",
    CONSTRAINT "domain_check_log_source_check" CHECK (("source" = ANY (ARRAY['daily'::"text", 'bypass'::"text"])))
);


ALTER TABLE "ops"."domain_check_log" OWNER TO "postgres";


ALTER TABLE "ops"."domain_check_log" ALTER COLUMN "id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "ops"."domain_check_log_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "ops"."domain_tables" (
    "tbl" "text" NOT NULL,
    "domain" "text" NOT NULL,
    CONSTRAINT "domain_tables_domain_check" CHECK (("domain" = ANY (ARRAY['core'::"text", 'gig'::"text", 'fleet'::"text", 'school_bus'::"text", 'driving_school'::"text"])))
);


ALTER TABLE "ops"."domain_tables" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "ops"."domain_triggers" (
    "tbl" "text" NOT NULL,
    "tg" "text" NOT NULL,
    "domain" "text" NOT NULL,
    "guard" "text",
    CONSTRAINT "domain_triggers_check" CHECK ((("domain" = 'core'::"text") OR ("guard" IS NOT NULL))),
    CONSTRAINT "domain_triggers_domain_check" CHECK (("domain" = ANY (ARRAY['core'::"text", 'gig'::"text", 'fleet'::"text", 'school_bus'::"text", 'driving_school'::"text"])))
);


ALTER TABLE "ops"."domain_triggers" OWNER TO "postgres";


CREATE OR REPLACE VIEW "ops"."v_domain_coupling" AS
 WITH "f" AS (
         SELECT ("p"."proname")::"text" AS "fn",
            "p"."prosrc"
           FROM "pg_proc" "p"
          WHERE (("p"."pronamespace" = ('"public"'::"regnamespace")::"oid") AND ("p"."prokind" = 'f'::"char") AND (NOT (EXISTS ( SELECT 1
                   FROM "pg_depend" "e"
                  WHERE (("e"."classid" = ('"pg_proc"'::"regclass")::"oid") AND ("e"."objid" = "p"."oid") AND ("e"."deptype" = 'e'::"char"))))))
        ), "hits" AS (
         SELECT "f"."fn",
            "d"."tbl",
            "d"."domain"
           FROM ("f"
             JOIN "ops"."domain_tables" "d" ON (("f"."prosrc" ~* (('(^|[^a-z0-9_])(public\.)?'::"text" || "d"."tbl") || '([^a-z0-9_]|$)'::"text"))))
        )
 SELECT "fn" AS "function_name",
    "string_agg"(DISTINCT "domain", ' + '::"text" ORDER BY "domain") AS "domains",
    "string_agg"(DISTINCT "tbl", ', '::"text" ORDER BY "tbl") FILTER (WHERE ("domain" = 'core'::"text")) AS "core_tables",
    "string_agg"(DISTINCT "tbl", ', '::"text" ORDER BY "tbl") FILTER (WHERE ("domain" <> 'core'::"text")) AS "service_tables"
   FROM "hits"
  GROUP BY "fn";


ALTER VIEW "ops"."v_domain_coupling" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."app_versions" (
    "app" "text" NOT NULL,
    "min_build" integer DEFAULT 0 NOT NULL,
    "latest_build" integer DEFAULT 0 NOT NULL,
    "store_url" "text" NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "app_versions_app_check" CHECK (("app" = ANY (ARRAY['gig'::"text", 'fleet'::"text"])))
);


ALTER TABLE "public"."app_versions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."audit_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "session_id" "uuid" NOT NULL,
    "section_id" "uuid",
    "user_id" "uuid" NOT NULL,
    "organization_id" "uuid",
    "event_type" "text" NOT NULL,
    "payload" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "hash" "text" NOT NULL,
    "prev_hash" "text",
    "event_index" integer,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."audit_events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."auth_signup_errors" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid",
    "email" "text",
    "error_message" "text" NOT NULL,
    "occurred_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."auth_signup_errors" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."branch_moves" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "subject_type" "text" NOT NULL,
    "subject_id" "uuid" NOT NULL,
    "subject_name" "text",
    "from_branch_id" "uuid",
    "to_branch_id" "uuid",
    "from_any" boolean DEFAULT false NOT NULL,
    "to_any" boolean DEFAULT false NOT NULL,
    "note" "text" NOT NULL,
    "moved_by" "uuid",
    "moved_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "branch_moves_note_check" CHECK ((("length"("btrim"("note")) >= 3) AND ("length"("btrim"("note")) <= 500))),
    CONSTRAINT "branch_moves_subject_type_check" CHECK (("subject_type" = ANY (ARRAY['member'::"text", 'student'::"text"])))
);


ALTER TABLE "public"."branch_moves" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."branches" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "address" "text",
    "phone" "text",
    "is_archived" boolean DEFAULT false NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "manager_id" "uuid",
    CONSTRAINT "branches_name_check" CHECK ((("length"("btrim"("name")) >= 1) AND ("length"("btrim"("name")) <= 80)))
);


ALTER TABLE "public"."branches" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."device_permission_status" (
    "user_id" "uuid" NOT NULL,
    "app_version" "text",
    "os_version" "text",
    "device_model" "text",
    "location_state" "text",
    "location_always" boolean,
    "notifications" boolean,
    "motion" boolean,
    "camera" boolean,
    "battery_unrestricted" boolean,
    "usage_access" boolean,
    "exact_alarm" boolean,
    "reported_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "device_permission_status_location_state_check" CHECK (("location_state" = ANY (ARRAY['precise'::"text", 'approximate'::"text", 'denied'::"text"])))
);


ALTER TABLE "public"."device_permission_status" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."diagnostic_logs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" DEFAULT "auth"."uid"() NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "app_version" "text",
    "device" "text",
    "content" "text" NOT NULL,
    CONSTRAINT "diagnostic_logs_content_check" CHECK (("length"("content") <= 600000))
);


ALTER TABLE "public"."diagnostic_logs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."driver_invites" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "email" "text" NOT NULL,
    "token_hash" "text" NOT NULL,
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "created_by" "uuid",
    "accepted_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "expires_at" timestamp with time zone DEFAULT ("now"() + '7 days'::interval) NOT NULL,
    "first_name" "text" DEFAULT ''::"text" NOT NULL,
    "last_name" "text" DEFAULT ''::"text" NOT NULL,
    "slot_id" "uuid",
    "intended_role" "text" DEFAULT 'driver'::"text" NOT NULL,
    CONSTRAINT "driver_invites_intended_role_check" CHECK (("intended_role" = ANY (ARRAY['driver'::"text", 'operator'::"text", 'admin'::"text", 'monitor'::"text"]))),
    CONSTRAINT "driver_invites_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'accepted'::"text", 'expired'::"text"])))
);


ALTER TABLE "public"."driver_invites" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."driver_notifications" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "kind" "text" NOT NULL,
    "session_id" "uuid",
    "data" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "read_at" timestamp with time zone,
    CONSTRAINT "driver_notifications_kind_check" CHECK (("kind" = ANY (ARRAY['trip_safety'::"text", 'safety_summary'::"text"])))
);


ALTER TABLE "public"."driver_notifications" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."driver_safety_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "session_id" "uuid",
    "section_id" "uuid",
    "event_type" "text" NOT NULL,
    "speed_mps" double precision,
    "latitude" double precision,
    "longitude" double precision,
    "recorded_at" timestamp with time zone NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "speed_limit_mps" double precision,
    "speed_limit_source" "text",
    CONSTRAINT "driver_safety_events_event_type_check" CHECK (("event_type" = ANY (ARRAY['harsh_braking'::"text", 'hard_acceleration'::"text", 'speeding'::"text"]))),
    CONSTRAINT "driver_safety_events_speed_limit_source_check" CHECK ((("speed_limit_source" IS NULL) OR ("speed_limit_source" = ANY (ARRAY['osm'::"text", 'fixed_fallback'::"text"]))))
);


ALTER TABLE "public"."driver_safety_events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."driver_slot_claim_attempts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "success" boolean NOT NULL,
    "slot_id" "uuid",
    "attempted_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."driver_slot_claim_attempts" OWNER TO "postgres";


COMMENT ON TABLE "public"."driver_slot_claim_attempts" IS 'Internal: written by claim_driver_slot (SECURITY DEFINER). No client policies by design.';



CREATE TABLE IF NOT EXISTS "public"."driver_workdays" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "driver_id" "uuid" NOT NULL,
    "work_date" "date" NOT NULL,
    "opened_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "closed_at" timestamp with time zone
);


ALTER TABLE "public"."driver_workdays" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."driving_school_clients" (
    "organization_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."driving_school_clients" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_availability" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "instructor_id" "uuid" NOT NULL,
    "weekday" smallint NOT NULL,
    "start_time" time without time zone NOT NULL,
    "end_time" time without time zone NOT NULL,
    "vehicle_id" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "ds_availability_check" CHECK (("end_time" > "start_time")),
    CONSTRAINT "ds_availability_weekday_check" CHECK ((("weekday" >= 0) AND ("weekday" <= 6)))
);


ALTER TABLE "public"."ds_availability" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_blocked_hours" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "instructor_id" "uuid",
    "weekday" smallint,
    "on_date" "date",
    "start_time" time without time zone NOT NULL,
    "end_time" time without time zone NOT NULL,
    "label" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "ds_blocked_hours_check" CHECK (("end_time" > "start_time")),
    CONSTRAINT "ds_blocked_hours_check1" CHECK ((("weekday" IS NULL) OR ("on_date" IS NULL))),
    CONSTRAINT "ds_blocked_hours_label_check" CHECK ((("label" IS NULL) OR ("char_length"("label") <= 60))),
    CONSTRAINT "ds_blocked_hours_weekday_check" CHECK ((("weekday" >= 0) AND ("weekday" <= 6)))
);


ALTER TABLE "public"."ds_blocked_hours" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_certificates" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "number" "text" NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "student_id" "uuid" NOT NULL,
    "data" "jsonb" NOT NULL,
    "sha256" "text" NOT NULL,
    "issued_by" "uuid",
    "issued_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."ds_certificates" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_client_students" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "client_id" "uuid" NOT NULL,
    "student_id" "uuid" NOT NULL,
    "relation" "text" NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "ended_at" timestamp with time zone,
    "ended_reason" "text",
    CONSTRAINT "ds_client_students_ended_reason_check" CHECK ((("ended_reason" IS NULL) OR ("ended_reason" = ANY (ARRAY['majority'::"text", 'emancipated'::"text", 'revoked'::"text"])))),
    CONSTRAINT "ds_client_students_relation_check" CHECK (("relation" = ANY (ARRAY['self'::"text", 'guardian'::"text"])))
);


ALTER TABLE "public"."ds_client_students" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_client_tokens" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "client_id" "uuid" NOT NULL,
    "kind" "text" NOT NULL,
    "token_hash" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "expires_at" timestamp with time zone NOT NULL,
    "used_at" timestamp with time zone,
    "revoked_at" timestamp with time zone,
    CONSTRAINT "ds_client_tokens_kind_check" CHECK (("kind" = ANY (ARRAY['link'::"text", 'session'::"text"])))
);


ALTER TABLE "public"."ds_client_tokens" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_enrollment_requests" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "first_name" "text" NOT NULL,
    "last_name" "text" NOT NULL,
    "birth_date" "date" NOT NULL,
    "email" "text",
    "phone" "text",
    "guardian_name" "text",
    "guardian_email" "text",
    "guardian_phone" "text",
    "program_id" "uuid",
    "branch_id" "uuid",
    "message" "text",
    "is_minor" boolean NOT NULL,
    "consent_by" "text" NOT NULL,
    "consent_name" "text" NOT NULL,
    "consent_version" "text" DEFAULT '2026-10-20'::"text" NOT NULL,
    "consent_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "sms_opt_in" boolean DEFAULT false NOT NULL,
    "sms_phone" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "decided_at" timestamp with time zone,
    "decided_by" "uuid",
    "student_id" "uuid",
    "preferred_language" "text",
    "client_id" "uuid",
    CONSTRAINT "ds_enrollment_requests_consent_by_check" CHECK (("consent_by" = ANY (ARRAY['student'::"text", 'guardian'::"text"]))),
    CONSTRAINT "ds_enrollment_requests_consent_name_check" CHECK ((("length"("btrim"("consent_name")) >= 2) AND ("length"("btrim"("consent_name")) <= 120))),
    CONSTRAINT "ds_enrollment_requests_email_check" CHECK ((("email" IS NULL) OR ("length"("email") <= 120))),
    CONSTRAINT "ds_enrollment_requests_first_name_check" CHECK ((("length"("btrim"("first_name")) >= 1) AND ("length"("btrim"("first_name")) <= 60))),
    CONSTRAINT "ds_enrollment_requests_guardian_email_check" CHECK ((("guardian_email" IS NULL) OR ("length"("guardian_email") <= 120))),
    CONSTRAINT "ds_enrollment_requests_guardian_name_check" CHECK ((("guardian_name" IS NULL) OR ("length"("guardian_name") <= 120))),
    CONSTRAINT "ds_enrollment_requests_guardian_phone_check" CHECK ((("guardian_phone" IS NULL) OR ("length"("guardian_phone") <= 30))),
    CONSTRAINT "ds_enrollment_requests_last_name_check" CHECK ((("length"("btrim"("last_name")) >= 1) AND ("length"("btrim"("last_name")) <= 60))),
    CONSTRAINT "ds_enrollment_requests_message_check" CHECK ((("message" IS NULL) OR ("length"("message") <= 500))),
    CONSTRAINT "ds_enrollment_requests_phone_check" CHECK ((("phone" IS NULL) OR ("length"("phone") <= 30))),
    CONSTRAINT "ds_enrollment_requests_preferred_language_check" CHECK (("preferred_language" = ANY (ARRAY['en'::"text", 'es'::"text"]))),
    CONSTRAINT "ds_enrollment_requests_sms_phone_check" CHECK ((("sms_phone" IS NULL) OR ("length"("sms_phone") <= 30))),
    CONSTRAINT "ds_enrollment_requests_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'approved'::"text", 'declined'::"text"])))
);


ALTER TABLE "public"."ds_enrollment_requests" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_evaluation_scores" (
    "evaluation_id" "uuid" NOT NULL,
    "skill_id" "uuid" NOT NULL,
    "score" smallint NOT NULL,
    CONSTRAINT "ds_evaluation_scores_score_check" CHECK ((("score" >= 1) AND ("score" <= 4)))
);


ALTER TABLE "public"."ds_evaluation_scores" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_evaluations" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "shift_block_id" "uuid" NOT NULL,
    "student_id" "uuid" NOT NULL,
    "instructor_id" "uuid",
    "note" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "ds_evaluations_note_check" CHECK ((("note" IS NULL) OR ("length"("note") <= 1000)))
);


ALTER TABLE "public"."ds_evaluations" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_packages" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "minutes" integer NOT NULL,
    "price_cents" integer DEFAULT 0 NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "ds_packages_minutes_check" CHECK ((("minutes" >= 1) AND ("minutes" <= 100000))),
    CONSTRAINT "ds_packages_name_check" CHECK ((("length"("btrim"("name")) >= 1) AND ("length"("btrim"("name")) <= 80))),
    CONSTRAINT "ds_packages_price_cents_check" CHECK (("price_cents" >= 0))
);


ALTER TABLE "public"."ds_packages" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_programs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "required_minutes" integer DEFAULT 0 NOT NULL,
    "required_night_minutes" integer DEFAULT 0 NOT NULL,
    "class_minutes" integer DEFAULT 60 NOT NULL,
    "notify_guardian" boolean DEFAULT false NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "sort" integer DEFAULT 0 NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "ds_programs_check" CHECK (("required_night_minutes" <= "required_minutes")),
    CONSTRAINT "ds_programs_class_minutes_check" CHECK ((("class_minutes" >= 15) AND ("class_minutes" <= 480))),
    CONSTRAINT "ds_programs_name_check" CHECK ((("length"("btrim"("name")) >= 1) AND ("length"("btrim"("name")) <= 60))),
    CONSTRAINT "ds_programs_required_minutes_check" CHECK ((("required_minutes" >= 0) AND ("required_minutes" <= 100000))),
    CONSTRAINT "ds_programs_required_night_minutes_check" CHECK ((("required_night_minutes" >= 0) AND ("required_night_minutes" <= 100000)))
);


ALTER TABLE "public"."ds_programs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_public_pages" (
    "organization_id" "uuid" NOT NULL,
    "slug" "text" NOT NULL,
    "enabled" boolean DEFAULT false NOT NULL,
    "intro" "text",
    "min_age" smallint DEFAULT 15 NOT NULL,
    "terms_url" "text",
    "allowed_origins" "text"[] DEFAULT '{}'::"text"[] NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "custom_domain" "text",
    "domain_token" "text",
    "domain_status" "text" DEFAULT 'none'::"text" NOT NULL,
    "domain_message" "text",
    "domain_checked_at" timestamp with time zone,
    "domain_verified_at" timestamp with time zone,
    CONSTRAINT "ds_public_pages_allowed_origins_check" CHECK ((("cardinality"("allowed_origins") <= 5) AND "public"."fn_valid_origins"("allowed_origins"))),
    CONSTRAINT "ds_public_pages_custom_domain_check" CHECK ((("custom_domain" IS NULL) OR (("custom_domain" ~ '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.){2,}[a-z0-9]([a-z0-9-]*[a-z0-9])?$'::"text") AND ("length"("custom_domain") <= 253)))),
    CONSTRAINT "ds_public_pages_domain_message_check" CHECK ((("domain_message" IS NULL) OR ("length"("domain_message") <= 300))),
    CONSTRAINT "ds_public_pages_domain_status_check" CHECK (("domain_status" = ANY (ARRAY['none'::"text", 'pending'::"text", 'verified'::"text", 'error'::"text"]))),
    CONSTRAINT "ds_public_pages_intro_check" CHECK ((("intro" IS NULL) OR ("length"("intro") <= 600))),
    CONSTRAINT "ds_public_pages_min_age_check" CHECK ((("min_age" >= 13) AND ("min_age" <= 25))),
    CONSTRAINT "ds_public_pages_slug_check" CHECK (("slug" ~ '^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$'::"text")),
    CONSTRAINT "ds_public_pages_terms_url_check" CHECK ((("terms_url" IS NULL) OR (("terms_url" ~ '^https://'::"text") AND ("length"("terms_url") <= 300))))
);


ALTER TABLE "public"."ds_public_pages" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_reminders_sent" (
    "shift_block_id" "uuid" NOT NULL,
    "recipient" "text" NOT NULL,
    "sent_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."ds_reminders_sent" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_settings" (
    "organization_id" "uuid" NOT NULL,
    "reminder_hours" integer DEFAULT 24 NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "booking_enabled" boolean DEFAULT false NOT NULL,
    "booking_lead_hours" integer DEFAULT 24 NOT NULL,
    "booking_horizon_days" integer DEFAULT 21 NOT NULL,
    "booking_max_upcoming" integer DEFAULT 2 NOT NULL,
    "cancel_free_hours" integer DEFAULT 24 NOT NULL,
    "cancellation_policy" "text",
    "age_of_majority" smallint DEFAULT 18 NOT NULL,
    "booking_open_time" time without time zone,
    "booking_close_time" time without time zone,
    CONSTRAINT "ds_settings_age_of_majority_check" CHECK ((("age_of_majority" >= 18) AND ("age_of_majority" <= 21))),
    CONSTRAINT "ds_settings_booking_horizon_days_check" CHECK ((("booking_horizon_days" >= 1) AND ("booking_horizon_days" <= 365))),
    CONSTRAINT "ds_settings_booking_hours_check" CHECK (((("booking_open_time" IS NULL) AND ("booking_close_time" IS NULL)) OR (("booking_open_time" IS NOT NULL) AND ("booking_close_time" IS NOT NULL) AND ("booking_close_time" > "booking_open_time")))),
    CONSTRAINT "ds_settings_booking_lead_hours_check" CHECK ((("booking_lead_hours" >= 0) AND ("booking_lead_hours" <= 336))),
    CONSTRAINT "ds_settings_booking_max_upcoming_check" CHECK ((("booking_max_upcoming" >= 1) AND ("booking_max_upcoming" <= 20))),
    CONSTRAINT "ds_settings_cancel_free_hours_check" CHECK ((("cancel_free_hours" >= 0) AND ("cancel_free_hours" <= 336))),
    CONSTRAINT "ds_settings_cancellation_policy_check" CHECK ((("cancellation_policy" IS NULL) OR ("length"("cancellation_policy") <= 1000))),
    CONSTRAINT "ds_settings_reminder_hours_check" CHECK ((("reminder_hours" >= 1) AND ("reminder_hours" <= 168)))
);


ALTER TABLE "public"."ds_settings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_skills" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "category" "text" NOT NULL,
    "name" "text" NOT NULL,
    "sort" integer DEFAULT 0 NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    CONSTRAINT "ds_skills_category_check" CHECK ((("length"("btrim"("category")) >= 1) AND ("length"("btrim"("category")) <= 60))),
    CONSTRAINT "ds_skills_name_check" CHECK ((("length"("btrim"("name")) >= 1) AND ("length"("btrim"("name")) <= 80)))
);


ALTER TABLE "public"."ds_skills" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_slot_notices" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "program_id" "uuid",
    "instructor_id" "uuid",
    "vehicle_id" "uuid",
    "block_date" "date" NOT NULL,
    "start_time" time without time zone NOT NULL,
    "end_time" time without time zone NOT NULL,
    "freed_by_student" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "sent_at" timestamp with time zone
);


ALTER TABLE "public"."ds_slot_notices" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_student_packages" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "student_id" "uuid" NOT NULL,
    "package_id" "uuid",
    "name" "text" NOT NULL,
    "minutes" integer NOT NULL,
    "price_cents" integer DEFAULT 0 NOT NULL,
    "amount_paid_cents" integer DEFAULT 0 NOT NULL,
    "payment_status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "note" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "ds_student_packages_amount_paid_cents_check" CHECK (("amount_paid_cents" >= 0)),
    CONSTRAINT "ds_student_packages_minutes_check" CHECK (("minutes" > 0)),
    CONSTRAINT "ds_student_packages_note_check" CHECK ((("note" IS NULL) OR ("length"("note") <= 500))),
    CONSTRAINT "ds_student_packages_payment_status_check" CHECK (("payment_status" = ANY (ARRAY['paid'::"text", 'partial'::"text", 'pending'::"text"]))),
    CONSTRAINT "ds_student_packages_price_cents_check" CHECK (("price_cents" >= 0))
);


ALTER TABLE "public"."ds_student_packages" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_student_private" (
    "student_id" "uuid" NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "date_of_birth" "date",
    "permit_number" "text",
    CONSTRAINT "ds_student_private_permit_number_check" CHECK ((("permit_number" IS NULL) OR ("length"("permit_number") <= 40)))
);


ALTER TABLE "public"."ds_student_private" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_students" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "branch_id" "uuid",
    "first_name" "text" NOT NULL,
    "last_name" "text" NOT NULL,
    "phone" "text",
    "email" "text",
    "guardian_name" "text",
    "guardian_phone" "text",
    "guardian_email" "text",
    "status" "text" DEFAULT 'active'::"text" NOT NULL,
    "notes" "text",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "program_id" "uuid",
    "state_cert_type" "text",
    "state_cert_number" "text",
    "sms_consent_at" timestamp with time zone,
    "sms_consent_phone" "text",
    "sms_consent_source" "text",
    "birth_date" "date",
    "preferred_language" "text",
    "emancipated_at" timestamp with time zone,
    "emancipated_by" "uuid",
    "emancipation_note" "text",
    CONSTRAINT "ds_students_email_check" CHECK ((("email" IS NULL) OR ("length"("email") <= 120))),
    CONSTRAINT "ds_students_emancipation_note_check" CHECK ((("emancipation_note" IS NULL) OR ("length"("emancipation_note") <= 300))),
    CONSTRAINT "ds_students_first_name_check" CHECK ((("length"("btrim"("first_name")) >= 1) AND ("length"("btrim"("first_name")) <= 60))),
    CONSTRAINT "ds_students_guardian_email_check" CHECK ((("guardian_email" IS NULL) OR ("length"("guardian_email") <= 120))),
    CONSTRAINT "ds_students_guardian_name_check" CHECK ((("guardian_name" IS NULL) OR ("length"("guardian_name") <= 120))),
    CONSTRAINT "ds_students_guardian_phone_check" CHECK ((("guardian_phone" IS NULL) OR ("length"("guardian_phone") <= 30))),
    CONSTRAINT "ds_students_last_name_check" CHECK ((("length"("btrim"("last_name")) >= 1) AND ("length"("btrim"("last_name")) <= 60))),
    CONSTRAINT "ds_students_notes_check" CHECK ((("notes" IS NULL) OR ("length"("notes") <= 1000))),
    CONSTRAINT "ds_students_phone_check" CHECK ((("phone" IS NULL) OR ("length"("phone") <= 30))),
    CONSTRAINT "ds_students_preferred_language_check" CHECK (("preferred_language" = ANY (ARRAY['en'::"text", 'es'::"text"]))),
    CONSTRAINT "ds_students_sms_consent_phone_check" CHECK ((("sms_consent_phone" IS NULL) OR ("length"("sms_consent_phone") <= 30))),
    CONSTRAINT "ds_students_sms_consent_source_check" CHECK ((("sms_consent_source" IS NULL) OR ("sms_consent_source" = ANY (ARRAY['office'::"text", 'portal'::"text", 'online_request'::"text"])))),
    CONSTRAINT "ds_students_state_cert_number_check" CHECK ((("state_cert_number" IS NULL) OR ("length"("state_cert_number") <= 40))),
    CONSTRAINT "ds_students_state_cert_type_check" CHECK ((("state_cert_type" IS NULL) OR ("length"("state_cert_type") <= 40))),
    CONSTRAINT "ds_students_status_check" CHECK (("status" = ANY (ARRAY['registered'::"text", 'active'::"text", 'finished'::"text", 'dropped'::"text"])))
);


ALTER TABLE "public"."ds_students" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ds_time_off" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "instructor_id" "uuid" NOT NULL,
    "date_from" "date" NOT NULL,
    "date_to" "date" NOT NULL,
    "note" "text",
    CONSTRAINT "ds_time_off_check" CHECK (("date_to" >= "date_from")),
    CONSTRAINT "ds_time_off_note_check" CHECK ((("note" IS NULL) OR ("length"("note") <= 200)))
);


ALTER TABLE "public"."ds_time_off" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."edge_function_rate_limits" (
    "id" bigint NOT NULL,
    "fn_name" "text" NOT NULL,
    "client_key" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."edge_function_rate_limits" OWNER TO "postgres";


COMMENT ON TABLE "public"."edge_function_rate_limits" IS 'Internal: edge function rate limiter. No client policies by design.';



CREATE SEQUENCE IF NOT EXISTS "public"."edge_function_rate_limits_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE "public"."edge_function_rate_limits_id_seq" OWNER TO "postgres";


ALTER SEQUENCE "public"."edge_function_rate_limits_id_seq" OWNED BY "public"."edge_function_rate_limits"."id";



CREATE TABLE IF NOT EXISTS "public"."fleet_driver_slots" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "first_name" "text" NOT NULL,
    "last_name" "text" NOT NULL,
    "display_id" "text",
    "claim_code_hash" "text" NOT NULL,
    "claimed_by" "uuid",
    "claimed_at" timestamp with time zone,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."fleet_driver_slots" OWNER TO "postgres";


COMMENT ON TABLE "public"."fleet_driver_slots" IS 'Admin-created driver roster entries, claimable by a real account later via a one-time hashed code. Not the same thing as organization_members -- that gets a real row only once claimed.';



COMMENT ON COLUMN "public"."fleet_driver_slots"."claim_code_hash" IS 'SHA-256 hex hash of the one-time claim code. The plaintext is returned once, at creation, and never stored.';



CREATE TABLE IF NOT EXISTS "public"."fleet_plans" (
    "tier" "text" NOT NULL,
    "sort" smallint NOT NULL,
    "base_cents" integer NOT NULL,
    "included_cars" integer NOT NULL,
    "extra_car_cents" integer NOT NULL,
    "volume_car_cents" integer,
    "volume_from" integer DEFAULT 16 NOT NULL,
    "max_cars" integer,
    "included_branches" integer,
    "max_branches" integer,
    "extra_branch_cents" integer,
    CONSTRAINT "fleet_plans_base_cents_check" CHECK (("base_cents" >= 0)),
    CONSTRAINT "fleet_plans_extra_branch_cents_check" CHECK ((("extra_branch_cents" IS NULL) OR ("extra_branch_cents" >= 0))),
    CONSTRAINT "fleet_plans_extra_car_cents_check" CHECK (("extra_car_cents" >= 0)),
    CONSTRAINT "fleet_plans_included_branches_check" CHECK ((("included_branches" IS NULL) OR ("included_branches" >= 0))),
    CONSTRAINT "fleet_plans_included_cars_check" CHECK (("included_cars" >= 0)),
    CONSTRAINT "fleet_plans_max_branches_check" CHECK ((("max_branches" IS NULL) OR ("max_branches" >= 1))),
    CONSTRAINT "fleet_plans_max_cars_check" CHECK ((("max_cars" IS NULL) OR ("max_cars" > 0))),
    CONSTRAINT "fleet_plans_tier_check" CHECK (("tier" = ANY (ARRAY['starter'::"text", 'growth'::"text", 'enterprise'::"text"]))),
    CONSTRAINT "fleet_plans_volume_car_cents_check" CHECK ((("volume_car_cents" IS NULL) OR ("volume_car_cents" >= 0))),
    CONSTRAINT "fleet_plans_volume_from_check" CHECK (("volume_from" > 1))
);


ALTER TABLE "public"."fleet_plans" OWNER TO "postgres";


COMMENT ON TABLE "public"."fleet_plans" IS 'Internal: the global fleet price list. Read through public_pricing_catalog() and the limit functions.';



CREATE TABLE IF NOT EXISTS "public"."fleet_type_changes" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "from_type" "text",
    "to_type" "text" NOT NULL,
    "changed_by" "uuid",
    "source" "text" NOT NULL,
    "reason" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "fleet_type_changes_source_check" CHECK (("source" = ANY (ARRAY['onboarding'::"text", 'support'::"text"])))
);


ALTER TABLE "public"."fleet_type_changes" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."fuel_anomalies" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "purchase_id" "uuid" NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "kind" "text" NOT NULL,
    "severity" "text" NOT NULL,
    "detail" "text" NOT NULL,
    "metrics" "jsonb" DEFAULT '{}'::"jsonb" NOT NULL,
    "status" "text" DEFAULT 'open'::"text" NOT NULL,
    "review_note" "text",
    "reviewed_by" "uuid",
    "reviewed_at" timestamp with time zone,
    "notified_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "fuel_anomalies_kind_check" CHECK (("kind" = ANY (ARRAY['duplicate'::"text", 'over_capacity'::"text", 'location_mismatch'::"text", 'no_trip'::"text", 'no_miles'::"text", 'low_mpg'::"text", 'price_mismatch'::"text", 'price_high'::"text"]))),
    CONSTRAINT "fuel_anomalies_severity_check" CHECK (("severity" = ANY (ARRAY['high'::"text", 'medium'::"text", 'low'::"text"]))),
    CONSTRAINT "fuel_anomalies_status_check" CHECK (("status" = ANY (ARRAY['open'::"text", 'dismissed'::"text", 'confirmed'::"text"])))
);


ALTER TABLE "public"."fuel_anomalies" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."general_business_clients" (
    "organization_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."general_business_clients" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."geocode_cache" (
    "organization_id" "uuid" NOT NULL,
    "query_norm" "text" NOT NULL,
    "label" "text" NOT NULL,
    "latitude" double precision NOT NULL,
    "longitude" double precision NOT NULL,
    "provider" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "geocode_cache_label_check" CHECK (("char_length"("label") <= 240)),
    CONSTRAINT "geocode_cache_latitude_check" CHECK ((("latitude" >= ('-90'::integer)::double precision) AND ("latitude" <= (90)::double precision))),
    CONSTRAINT "geocode_cache_longitude_check" CHECK ((("longitude" >= ('-180'::integer)::double precision) AND ("longitude" <= (180)::double precision))),
    CONSTRAINT "geocode_cache_provider_check" CHECK (("provider" = ANY (ARRAY['census'::"text", 'nominatim'::"text", 'geoapify'::"text"]))),
    CONSTRAINT "geocode_cache_query_norm_check" CHECK ((("char_length"("query_norm") >= 3) AND ("char_length"("query_norm") <= 200)))
);


ALTER TABLE "public"."geocode_cache" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."gig_app_packages" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "gig_app_id" "text" NOT NULL,
    "os" "text" DEFAULT 'android'::"text" NOT NULL,
    "package_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "gig_app_packages_os_check" CHECK (("os" = 'android'::"text"))
);


ALTER TABLE "public"."gig_app_packages" OWNER TO "postgres";


COMMENT ON TABLE "public"."gig_app_packages" IS 'Verified Android package names for foreground-app gig detection (auto trip detection premium feature). Dev-maintained via migration only.';



CREATE TABLE IF NOT EXISTS "public"."gig_app_suggestions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" DEFAULT "auth"."uid"() NOT NULL,
    "app_name" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "gig_app_suggestions_app_name_check" CHECK ((("length"("btrim"("app_name")) >= 2) AND ("length"("btrim"("app_name")) <= 80)))
);


ALTER TABLE "public"."gig_app_suggestions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."gig_apps" (
    "id" "text" NOT NULL,
    "name" "text" NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "sort_order" integer DEFAULT 0 NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."gig_apps" OWNER TO "postgres";


COMMENT ON TABLE "public"."gig_apps" IS 'Catálogo de sistema. Solo lectura para authenticated. Escritura solo service_role.';



CREATE TABLE IF NOT EXISTS "public"."gig_clients" (
    "profile_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."gig_clients" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."guardian_invites" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "guardian_id" "uuid" NOT NULL,
    "email" "text" NOT NULL,
    "token_hash" "text" NOT NULL,
    "status" "text" DEFAULT 'pending'::"text" NOT NULL,
    "expires_at" timestamp with time zone DEFAULT ("now"() + '7 days'::interval) NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "accepted_at" timestamp with time zone,
    CONSTRAINT "guardian_invites_status_check" CHECK (("status" = ANY (ARRAY['pending'::"text", 'accepted'::"text", 'expired'::"text", 'revoked'::"text"])))
);


ALTER TABLE "public"."guardian_invites" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ifta_fuel_tax_rates" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "quarter" "text" NOT NULL,
    "jurisdiction_code" "text" NOT NULL,
    "fuel_type" "text" NOT NULL,
    "rate_usd" numeric,
    "source_quarter_label" "text" NOT NULL,
    "fetched_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "kind" "text" DEFAULT 'base'::"text" NOT NULL,
    CONSTRAINT "ifta_fuel_tax_rates_kind_check" CHECK (("kind" = ANY (ARRAY['base'::"text", 'surcharge'::"text"])))
);


ALTER TABLE "public"."ifta_fuel_tax_rates" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ifta_us_state_boundaries" (
    "fips_code" "text" NOT NULL,
    "state_code" "text" NOT NULL,
    "name" "text" NOT NULL,
    "geom" "extensions"."geometry" NOT NULL
);


ALTER TABLE "public"."ifta_us_state_boundaries" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."odometer_ocr_feedback" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" DEFAULT "auth"."uid"() NOT NULL,
    "vehicle_id" "uuid",
    "ocr_value" numeric,
    "ocr_confidence" numeric,
    "final_value" numeric NOT NULL,
    "was_edited" boolean NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."odometer_ocr_feedback" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."organization_members" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "member_role" "text" NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "invited_at" timestamp with time zone,
    "joined_at" timestamp with time zone DEFAULT "now"(),
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "branch_id" "uuid",
    "any_branch" boolean DEFAULT false NOT NULL,
    "languages" "text"[] DEFAULT '{en}'::"text"[] NOT NULL,
    CONSTRAINT "organization_members_languages_check" CHECK (((("cardinality"("languages") >= 1) AND ("cardinality"("languages") <= 2)) AND ("languages" <@ ARRAY['en'::"text", 'es'::"text"]))),
    CONSTRAINT "organization_members_member_role_check" CHECK (("member_role" = ANY (ARRAY['owner'::"text", 'admin'::"text", 'operator'::"text", 'driver'::"text", 'monitor'::"text"])))
);


ALTER TABLE "public"."organization_members" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."organizations" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "name" "text" NOT NULL,
    "slug" "text",
    "created_by" "uuid",
    "is_active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "compliance_mode" "text" DEFAULT 'light_duty'::"text" NOT NULL,
    "vehicle_assignment_mode" "text" DEFAULT 'fixed'::"text" NOT NULL,
    "stripe_customer_id" "text",
    "subscription_tier" "text",
    "subscription_status" "text",
    "subscription_vehicle_count" integer,
    "subscription_updated_at" timestamp with time zone,
    "tier_enforcement_exempt" boolean DEFAULT false NOT NULL,
    "timezone" "text" DEFAULT 'America/New_York'::"text" NOT NULL,
    "shift_start_window_minutes" integer DEFAULT 10 NOT NULL,
    "industry_template" "text" DEFAULT 'general'::"text" NOT NULL,
    "fleet_type_confirmed_at" timestamp with time zone,
    "allow_driver_owned_vehicles" boolean DEFAULT false NOT NULL,
    "show_all_modules" boolean DEFAULT false NOT NULL,
    "require_pretrip_inspection" boolean DEFAULT true NOT NULL,
    "use_shift_schedules" boolean DEFAULT false NOT NULL,
    "stripe_subscription_id" "text",
    "report_display_name" "text",
    "report_logo_path" "text",
    "service_acquired_at" timestamp with time zone,
    "service_acquisition_cents" integer,
    "service_acquisition_tier" "text",
    "service" "text" NOT NULL,
    CONSTRAINT "organizations_compliance_mode_check" CHECK (("compliance_mode" = ANY (ARRAY['light_duty'::"text", 'regulated_cmv'::"text"]))),
    CONSTRAINT "organizations_industry_template_check" CHECK (("industry_template" = ANY (ARRAY['general'::"text", 'delivery'::"text", 'field_service'::"text", 'trucking'::"text", 'construction'::"text", 'passenger'::"text", 'sales'::"text", 'driving_school'::"text", 'school_transport'::"text"]))),
    CONSTRAINT "organizations_report_display_name_check" CHECK ((("report_display_name" IS NULL) OR ("length"("report_display_name") <= 120))),
    CONSTRAINT "organizations_service_check" CHECK (("service" = ANY (ARRAY['driving_school'::"text", 'school_bus'::"text", 'sales'::"text", 'trucking'::"text", 'general_business'::"text"]))),
    CONSTRAINT "organizations_shift_window_check" CHECK ((("shift_start_window_minutes" >= 0) AND ("shift_start_window_minutes" <= 120))),
    CONSTRAINT "organizations_subscription_tier_check" CHECK (("subscription_tier" = ANY (ARRAY['starter'::"text", 'growth'::"text", 'enterprise'::"text"]))),
    CONSTRAINT "organizations_vehicle_assignment_mode_check" CHECK (("vehicle_assignment_mode" = ANY (ARRAY['fixed'::"text", 'open'::"text"])))
);


ALTER TABLE "public"."organizations" OWNER TO "postgres";


COMMENT ON COLUMN "public"."organizations"."compliance_mode" IS 'light_duty: phone-GPS fleet tracking (Phase 1-5 of the Fleet module). regulated_cmv: reserved for future FMCSA-certified ELD hardware integration, not yet built.';



CREATE TABLE IF NOT EXISTS "public"."pdf_export_log" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "exported_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."pdf_export_log" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."plan_feature_rules" (
    "id" bigint NOT NULL,
    "feature" "text" NOT NULL,
    "min_plan" "text" NOT NULL,
    "templates" "text"[],
    "note" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "plan_feature_rules_feature_check" CHECK (("feature" ~ '^[a-z][a-z0-9_]*$'::"text")),
    CONSTRAINT "plan_feature_rules_min_plan_check" CHECK (("min_plan" = ANY (ARRAY['starter'::"text", 'growth'::"text", 'enterprise'::"text"])))
);


ALTER TABLE "public"."plan_feature_rules" OWNER TO "postgres";


COMMENT ON TABLE "public"."plan_feature_rules" IS 'Internal: read only by fn_plan_features (SECURITY DEFINER). Which features each service (industry template) gets at each plan.';



ALTER TABLE "public"."plan_feature_rules" ALTER COLUMN "id" ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME "public"."plan_feature_rules_id_seq"
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);



CREATE TABLE IF NOT EXISTS "public"."platform_id_policy" (
    "id" boolean DEFAULT true NOT NULL,
    "reuse_after_days" integer,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "platform_id_policy_id_check" CHECK ("id"),
    CONSTRAINT "platform_id_policy_reuse_after_days_check" CHECK ((("reuse_after_days" IS NULL) OR ("reuse_after_days" >= 30)))
);


ALTER TABLE "public"."platform_id_policy" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."play_subscriptions" (
    "purchase_token" "text" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "product_id" "text" NOT NULL,
    "tier" "text" NOT NULL,
    "order_id" "text",
    "state" "text" NOT NULL,
    "expiry_time" timestamp with time zone,
    "auto_renewing" boolean,
    "linked_purchase_token" "text",
    "raw" "jsonb",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "play_subscriptions_tier_check" CHECK (("tier" = ANY (ARRAY['base'::"text", 'premium'::"text"])))
);


ALTER TABLE "public"."play_subscriptions" OWNER TO "postgres";


CREATE SEQUENCE IF NOT EXISTS "public"."profile_display_id_seq"
    START WITH 10000
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE "public"."profile_display_id_seq" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."profiles" (
    "id" "uuid" NOT NULL,
    "display_id" "text" NOT NULL,
    "email" "text",
    "first_name" "text",
    "last_name" "text",
    "full_name" "text" GENERATED ALWAYS AS (TRIM(BOTH FROM ((COALESCE("first_name", ''::"text") || ' '::"text") || COALESCE("last_name", ''::"text")))) STORED,
    "account_type" "text" DEFAULT 'gig'::"text" NOT NULL,
    "avatar_url" "text",
    "phone" "text",
    "default_org_id" "uuid",
    "is_active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "multi_org_entitled" boolean DEFAULT false NOT NULL,
    "premium_entitled" boolean DEFAULT false NOT NULL,
    "base_entitled" boolean DEFAULT false NOT NULL,
    "mileage_method" "text" DEFAULT 'standard'::"text",
    "tier_enforcement_exempt" boolean DEFAULT false NOT NULL,
    "time_format" "text" DEFAULT '12h'::"text" NOT NULL,
    "legal_accepted_at" timestamp with time zone,
    "legal_terms_version" "text",
    "personal_plan" "text" GENERATED ALWAYS AS (
CASE
    WHEN "premium_entitled" THEN 'premium'::"text"
    WHEN "base_entitled" THEN 'basic'::"text"
    ELSE 'none'::"text"
END) STORED,
    CONSTRAINT "profiles_account_type_check" CHECK (("account_type" = ANY (ARRAY['gig'::"text", 'fleet_admin'::"text", 'fleet_driver'::"text"]))),
    CONSTRAINT "profiles_mileage_method_check" CHECK (("mileage_method" = ANY (ARRAY['standard'::"text", 'actual'::"text"]))),
    CONSTRAINT "profiles_premium_includes_base" CHECK (((NOT "premium_entitled") OR "base_entitled")),
    CONSTRAINT "profiles_time_format_check" CHECK (("time_format" = ANY (ARRAY['12h'::"text", '24h'::"text"])))
);


ALTER TABLE "public"."profiles" OWNER TO "postgres";


COMMENT ON COLUMN "public"."profiles"."multi_org_entitled" IS 'Paid add-on: lets an owner create more than one fleet organization. No billing integration wired yet -- set manually until real payment processing is built.';



COMMENT ON COLUMN "public"."profiles"."premium_entitled" IS 'Gates paid Gig features (starting with automatic trip detection). Enforcement-only -- no payment processing wired yet, see multi_org_entitled for the same pattern.';



CREATE TABLE IF NOT EXISTS "public"."report_access_attempts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "ip_hash" "text" NOT NULL,
    "success" boolean NOT NULL,
    "report_id" "uuid",
    "attempted_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."report_access_attempts" OWNER TO "postgres";


COMMENT ON TABLE "public"."report_access_attempts" IS 'Internal: written by redeem_report_access_code (SECURITY DEFINER). No client policies by design.';



CREATE TABLE IF NOT EXISTS "public"."reports" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "report_type" "text" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "organization_id" "uuid",
    "vehicle_id" "uuid",
    "start_date" "date" NOT NULL,
    "end_date" "date" NOT NULL,
    "total_miles" double precision DEFAULT 0 NOT NULL,
    "total_sessions" integer DEFAULT 0 NOT NULL,
    "generated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "generated_by" "uuid",
    "metadata" "jsonb" DEFAULT '{}'::"jsonb",
    "qr_token" "text",
    "qr_expires_at" timestamp with time zone,
    "qr_uses" integer DEFAULT 0 NOT NULL,
    "qr_max_uses" integer DEFAULT 2 NOT NULL,
    CONSTRAINT "reports_report_type_check" CHECK (("report_type" = ANY (ARRAY['daily'::"text", 'weekly'::"text", 'monthly'::"text", 'custom'::"text", 'irs'::"text"])))
);


ALTER TABLE "public"."reports" OWNER TO "postgres";


COMMENT ON COLUMN "public"."reports"."qr_token" IS 'SHA-256 hex hash of the access code shown to the driver. The plaintext code is never stored -- only returned once, at generation time.';



COMMENT ON COLUMN "public"."reports"."qr_expires_at" IS 'Code becomes invalid after this time even if qr_uses < qr_max_uses.';



COMMENT ON COLUMN "public"."reports"."qr_uses" IS 'How many times this code has been successfully redeemed.';



COMMENT ON COLUMN "public"."reports"."qr_max_uses" IS 'Max successful redemptions before the code is dead, independent of expiry.';



CREATE TABLE IF NOT EXISTS "public"."retired_display_ids" (
    "display_id" "text" NOT NULL,
    "kind" "text" NOT NULL,
    "retired_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."retired_display_ids" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."ridership_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "run_id" "uuid" NOT NULL,
    "stop_id" "uuid",
    "student_id" "uuid" NOT NULL,
    "action" "text" NOT NULL,
    "at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "method" "text" DEFAULT 'manual'::"text" NOT NULL,
    "reason" "text",
    "note" "text",
    "recorded_by" "uuid",
    CONSTRAINT "ridership_events_action_check" CHECK (("action" = ANY (ARRAY['board'::"text", 'alight'::"text", 'released'::"text"]))),
    CONSTRAINT "ridership_events_method_check" CHECK (("method" = 'manual'::"text")),
    CONSTRAINT "ridership_events_note_check" CHECK ((("note" IS NULL) OR ("length"("note") <= 300))),
    CONSTRAINT "ridership_events_reason_check" CHECK ((("reason" IS NULL) OR ("reason" = ANY (ARRAY['parent_pickup'::"text", 'early_dismissal'::"text", 'activity'::"text", 'other'::"text"]))))
);


ALTER TABLE "public"."ridership_events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."route_crew_overrides" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "route_id" "uuid" NOT NULL,
    "service_date" "date" NOT NULL,
    "driver_id" "uuid",
    "vehicle_id" "uuid",
    "monitor_name" "text",
    "reason" "text",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "monitor_id" "uuid",
    CONSTRAINT "route_crew_overrides_monitor_name_check" CHECK ((("monitor_name" IS NULL) OR ("length"("monitor_name") <= 80))),
    CONSTRAINT "route_crew_overrides_reason_check" CHECK ((("reason" IS NULL) OR ("length"("reason") <= 200)))
);


ALTER TABLE "public"."route_crew_overrides" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."route_stop_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "run_id" "uuid" NOT NULL,
    "stop_id" "uuid" NOT NULL,
    "arrived_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "departed_at" timestamp with time zone,
    "method" "text" DEFAULT 'auto'::"text" NOT NULL,
    CONSTRAINT "route_stop_events_method_check" CHECK (("method" = ANY (ARRAY['auto'::"text", 'manual'::"text"])))
);


ALTER TABLE "public"."route_stop_events" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."route_stops" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "route_id" "uuid" NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "seq" integer NOT NULL,
    "name" "text" NOT NULL,
    "address" "text",
    "latitude" double precision NOT NULL,
    "longitude" double precision NOT NULL,
    "radius_meters" integer DEFAULT 80 NOT NULL,
    "scheduled_time" time without time zone,
    "stop_kind" "text" DEFAULT 'pickup'::"text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "leg_distance_m" integer,
    "leg_duration_s" integer,
    CONSTRAINT "route_stops_leg_distance_m_check" CHECK ((("leg_distance_m" IS NULL) OR ("leg_distance_m" >= 0))),
    CONSTRAINT "route_stops_leg_duration_s_check" CHECK ((("leg_duration_s" IS NULL) OR ("leg_duration_s" >= 0))),
    CONSTRAINT "route_stops_name_check" CHECK (("length"(TRIM(BOTH FROM "name")) > 0)),
    CONSTRAINT "route_stops_radius_meters_check" CHECK ((("radius_meters" >= 20) AND ("radius_meters" <= 500))),
    CONSTRAINT "route_stops_stop_kind_check" CHECK (("stop_kind" = ANY (ARRAY['pickup'::"text", 'school'::"text", 'dropoff'::"text"])))
);


ALTER TABLE "public"."route_stops" OWNER TO "postgres";


COMMENT ON COLUMN "public"."route_stops"."leg_duration_s" IS 'Driving seconds from the previous stop (null for the first stop or when the path is not computed).';



CREATE TABLE IF NOT EXISTS "public"."routes" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "origin" "text",
    "destination" "text",
    "assigned_driver_id" "uuid",
    "assigned_vehicle_id" "uuid",
    "scheduled_date" "date",
    "notes" "text",
    "status" "text" DEFAULT 'draft'::"text" NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "closed_at" timestamp with time zone,
    "scheduled_start_time" time without time zone,
    "scheduled_end_time" time without time zone,
    "route_type" "text" DEFAULT 'general'::"text" NOT NULL,
    "school_site_id" "uuid",
    "service_days" smallint[] DEFAULT '{1,2,3,4,5}'::smallint[] NOT NULL,
    "monitor_name" "text",
    "monitor_id" "uuid",
    "path_polyline" "text",
    "path_distance_m" integer,
    "path_duration_s" integer,
    "path_computed_at" timestamp with time zone,
    "path_signature" "text",
    CONSTRAINT "routes_monitor_name_check" CHECK ((("monitor_name" IS NULL) OR ("length"("monitor_name") <= 80))),
    CONSTRAINT "routes_path_distance_m_check" CHECK ((("path_distance_m" IS NULL) OR ("path_distance_m" >= 0))),
    CONSTRAINT "routes_path_duration_s_check" CHECK ((("path_duration_s" IS NULL) OR ("path_duration_s" >= 0))),
    CONSTRAINT "routes_path_polyline_check" CHECK ((("path_polyline" IS NULL) OR ("char_length"("path_polyline") <= 250000))),
    CONSTRAINT "routes_route_type_check" CHECK (("route_type" = ANY (ARRAY['general'::"text", 'school_am'::"text", 'school_pm'::"text"]))),
    CONSTRAINT "routes_status_check" CHECK (("status" = ANY (ARRAY['draft'::"text", 'active'::"text", 'closed'::"text"])))
);


ALTER TABLE "public"."routes" OWNER TO "postgres";


COMMENT ON TABLE "public"."routes" IS 'Fleet route/dispatch. Admin-managed (web only, per the standing "heavy planning modules go to web" decision). Frozen once status=closed, same rule as sessions/session_sections.';



COMMENT ON COLUMN "public"."routes"."path_polyline" IS 'Road path through the route stops in order, Valhalla polyline6 (computed by our own routing server when the stops are saved; null when not computed). Planned path only, never a GPS trail.';



COMMENT ON COLUMN "public"."routes"."path_signature" IS 'Hash of the stops (order and coordinates) the path was computed for, to know when it is stale.';



CREATE TABLE IF NOT EXISTS "public"."sales_clients" (
    "organization_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."sales_clients" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."school_bus_clients" (
    "organization_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."school_bus_clients" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."school_guardians" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "first_name" "text" NOT NULL,
    "last_name" "text" NOT NULL,
    "email" "text" NOT NULL,
    "display_id" "text",
    "user_id" "uuid",
    "claimed_at" timestamp with time zone,
    "is_active" boolean DEFAULT true NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "revoked_at" timestamp with time zone,
    CONSTRAINT "school_guardians_email_check" CHECK (("email" = "lower"("btrim"("email")))),
    CONSTRAINT "school_guardians_first_name_check" CHECK ((("length"("btrim"("first_name")) >= 1) AND ("length"("btrim"("first_name")) <= 60))),
    CONSTRAINT "school_guardians_last_name_check" CHECK ((("length"("btrim"("last_name")) >= 1) AND ("length"("btrim"("last_name")) <= 60)))
);


ALTER TABLE "public"."school_guardians" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."school_sites" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "address" "text",
    "latitude" double precision,
    "longitude" double precision,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "school_sites_name_check" CHECK (("length"(TRIM(BOTH FROM "name")) > 0))
);


ALTER TABLE "public"."school_sites" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."service_license_fees" (
    "service" "text" NOT NULL,
    "tier" "text" NOT NULL,
    "cents" integer NOT NULL,
    CONSTRAINT "service_license_fees_cents_check" CHECK (("cents" >= 0)),
    CONSTRAINT "service_license_fees_service_check" CHECK (("service" = ANY (ARRAY['general'::"text", 'delivery'::"text", 'field_service'::"text", 'trucking'::"text", 'construction'::"text", 'passenger'::"text", 'sales'::"text", 'driving_school'::"text", 'school_transport'::"text"])))
);


ALTER TABLE "public"."service_license_fees" OWNER TO "postgres";


COMMENT ON TABLE "public"."service_license_fees" IS 'Internal: one-time acquisition fee per service and plan. Read through public_pricing_catalog().';



CREATE TABLE IF NOT EXISTS "public"."session_gps_breadcrumbs" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "session_id" "uuid" NOT NULL,
    "section_id" "uuid",
    "organization_id" "uuid",
    "vehicle_id" "uuid",
    "user_id" "uuid",
    "latitude" double precision NOT NULL,
    "longitude" double precision NOT NULL,
    "recorded_at" timestamp with time zone NOT NULL
);


ALTER TABLE "public"."session_gps_breadcrumbs" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."sessions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "organization_id" "uuid",
    "vehicle_id" "uuid",
    "started_by_user_id" "uuid",
    "ended_by_user_id" "uuid",
    "session_status" "text" DEFAULT 'active'::"text" NOT NULL,
    "start_time" timestamp with time zone DEFAULT "now"() NOT NULL,
    "end_time" timestamp with time zone,
    "total_miles" double precision DEFAULT 0 NOT NULL,
    "total_duration_seconds" integer DEFAULT 0 NOT NULL,
    "start_odometer_value" numeric(12,2),
    "end_odometer_value" numeric(12,2),
    "start_odometer_image_url" "text",
    "end_odometer_image_url" "text",
    "session_hash" "text",
    "prev_session_hash" "text",
    "date_key" "date" DEFAULT CURRENT_DATE NOT NULL,
    "is_closed" boolean DEFAULT false NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "cgc_decision_id" "text",
    "cgc_sealed_at" timestamp with time zone,
    "shift_block_id" "uuid",
    "map_token" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    CONSTRAINT "sessions_session_status_check" CHECK (("session_status" = ANY (ARRAY['active'::"text", 'paused'::"text", 'closed'::"text", 'cancelled'::"text"])))
);


ALTER TABLE "public"."sessions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."shifts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "driver_id" "uuid" NOT NULL,
    "vehicle_id" "uuid",
    "day_of_week" smallint NOT NULL,
    "start_time" time without time zone NOT NULL,
    "end_time" time without time zone NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "notes" "text",
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "shifts_day_of_week_check" CHECK ((("day_of_week" >= 0) AND ("day_of_week" <= 6)))
);


ALTER TABLE "public"."shifts" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."student_guardians" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "student_id" "uuid" NOT NULL,
    "guardian_id" "uuid" NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "removed_at" timestamp with time zone
);


ALTER TABLE "public"."student_guardians" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."student_ride_notices" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "student_id" "uuid" NOT NULL,
    "notice_date" "date" NOT NULL,
    "part" "text" DEFAULT 'am'::"text" NOT NULL,
    "reason" "text" NOT NULL,
    "will_attend_school" boolean DEFAULT true NOT NULL,
    "note" "text",
    "reported_by" "uuid",
    "reported_by_role" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "student_ride_notices_note_check" CHECK ((("note" IS NULL) OR ("char_length"("note") <= 300))),
    CONSTRAINT "student_ride_notices_part_check" CHECK (("part" = ANY (ARRAY['am'::"text", 'pm'::"text", 'both'::"text"]))),
    CONSTRAINT "student_ride_notices_reason_check" CHECK (("reason" = ANY (ARRAY['medical'::"text", 'overslept'::"text", 'sick'::"text", 'other'::"text"]))),
    CONSTRAINT "student_ride_notices_reported_by_role_check" CHECK (("reported_by_role" = ANY (ARRAY['guardian'::"text", 'staff'::"text"])))
);


ALTER TABLE "public"."student_ride_notices" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."student_stop_assignments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "student_id" "uuid" NOT NULL,
    "route_id" "uuid" NOT NULL,
    "stop_id" "uuid" NOT NULL,
    "action" "text" NOT NULL,
    CONSTRAINT "student_stop_assignments_action_check" CHECK (("action" = ANY (ARRAY['board'::"text", 'alight'::"text"])))
);


ALTER TABLE "public"."student_stop_assignments" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."students" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "first_name" "text" NOT NULL,
    "last_initial" "text",
    "grade" "text",
    "school_site_id" "uuid",
    "external_id" "text",
    "notes" "text",
    "is_active" boolean DEFAULT true NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "home_address" "text",
    "home_latitude" double precision,
    "home_longitude" double precision,
    "parent1_name" "text",
    "parent1_phone" "text",
    "parent2_name" "text",
    "parent2_phone" "text",
    CONSTRAINT "students_first_name_check" CHECK (("length"(TRIM(BOTH FROM "first_name")) > 0)),
    CONSTRAINT "students_home_address_len" CHECK ((("home_address" IS NULL) OR ("char_length"("home_address") <= 240))),
    CONSTRAINT "students_home_coords" CHECK (((("home_latitude" IS NULL) AND ("home_longitude" IS NULL)) OR ((("home_latitude" >= ('-90'::integer)::double precision) AND ("home_latitude" <= (90)::double precision)) AND (("home_longitude" >= ('-180'::integer)::double precision) AND ("home_longitude" <= (180)::double precision))))),
    CONSTRAINT "students_last_initial_check" CHECK ((("last_initial" IS NULL) OR ("length"("last_initial") <= 2))),
    CONSTRAINT "students_parent_len" CHECK (((("parent1_name" IS NULL) OR ("char_length"("parent1_name") <= 120)) AND (("parent2_name" IS NULL) OR ("char_length"("parent2_name") <= 120)) AND (("parent1_phone" IS NULL) OR ("char_length"("parent1_phone") <= 30)) AND (("parent2_phone" IS NULL) OR ("char_length"("parent2_phone") <= 30))))
);


ALTER TABLE "public"."students" OWNER TO "postgres";


COMMENT ON COLUMN "public"."students"."home_address" IS 'Home address; the route builder turns it into a pick-up stop.';



COMMENT ON COLUMN "public"."students"."parent1_phone" IS 'Emergency contact, first parent or guardian.';



COMMENT ON COLUMN "public"."students"."parent2_phone" IS 'Emergency contact, second parent or guardian (optional).';



CREATE TABLE IF NOT EXISTS "public"."subscription_events" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "stripe_event_id" "text" NOT NULL,
    "event_type" "text" NOT NULL,
    "user_id" "uuid",
    "payload" "jsonb" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."subscription_events" OWNER TO "postgres";


COMMENT ON TABLE "public"."subscription_events" IS 'Internal: service_role only (stripe-webhook). No client policies by design.';



CREATE TABLE IF NOT EXISTS "public"."subscriptions" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "user_id" "uuid" NOT NULL,
    "stripe_customer_id" "text",
    "stripe_subscription_id" "text",
    "status" "text" DEFAULT 'incomplete'::"text" NOT NULL,
    "price_id" "text",
    "current_period_end" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "tier" "text"
);


ALTER TABLE "public"."subscriptions" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."trip_approvals" (
    "session_id" "uuid" NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "status" "text" NOT NULL,
    "note" "text",
    "decided_by" "uuid" NOT NULL,
    "decided_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "trip_approvals_note_check" CHECK ((("note" IS NULL) OR ("length"("note") <= 500))),
    CONSTRAINT "trip_approvals_status_check" CHECK (("status" = ANY (ARRAY['approved'::"text", 'rejected'::"text"])))
);


ALTER TABLE "public"."trip_approvals" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."trip_classification_settings" (
    "user_id" "uuid" NOT NULL,
    "regular_enabled" boolean DEFAULT true NOT NULL,
    "suggestions_enabled" boolean DEFAULT true NOT NULL,
    "work_hours_inside" boolean DEFAULT false NOT NULL,
    "work_hours_outside" boolean DEFAULT false NOT NULL,
    "work_days" integer[] DEFAULT '{1,2,3,4,5}'::integer[] NOT NULL,
    "work_start_minute" integer DEFAULT 540 NOT NULL,
    "work_end_minute" integer DEFAULT 1080 NOT NULL,
    "time_zone" "text" DEFAULT 'America/New_York'::"text" NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "trip_classification_settings_time_zone_check" CHECK (("char_length"("time_zone") <= 64)),
    CONSTRAINT "trip_classification_settings_work_end_minute_check" CHECK ((("work_end_minute" >= 0) AND ("work_end_minute" <= 1440))),
    CONSTRAINT "trip_classification_settings_work_start_minute_check" CHECK ((("work_start_minute" >= 0) AND ("work_start_minute" <= 1439)))
);


ALTER TABLE "public"."trip_classification_settings" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."trip_incidents" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "session_id" "uuid",
    "user_id" "uuid",
    "organization_id" "uuid" NOT NULL,
    "vehicle_id" "uuid",
    "category" "text" NOT NULL,
    "description" "text" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "trip_incidents_category_check" CHECK (("category" = ANY (ARRAY['breakdown'::"text", 'accident'::"text", 'delay'::"text", 'other'::"text"])))
);


ALTER TABLE "public"."trip_incidents" OWNER TO "postgres";


COMMENT ON TABLE "public"."trip_incidents" IS 'Driver-reported mid-trip incidents (breakdown/accident/delay/other). Written by the driver, visible to their org admin -- no admin-facing viewer built yet on either mobile or web, same disclosed gap as DVIR inspection review.';



CREATE TABLE IF NOT EXISTS "public"."trip_vehicle_assignments" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "session_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "miles" double precision,
    "assigned_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."trip_vehicle_assignments" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."trucking_clients" (
    "organization_id" "uuid" NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."trucking_clients" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."user_onboarding" (
    "user_id" "uuid" NOT NULL,
    "welcome_seen" boolean DEFAULT false NOT NULL,
    "permissions_completed" boolean DEFAULT false NOT NULL,
    "vehicle_setup_completed" boolean DEFAULT false NOT NULL,
    "profile_completed" boolean DEFAULT false NOT NULL,
    "welcome_seen_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "account_type_chosen" boolean DEFAULT false NOT NULL,
    "tour_seen" "text"[] DEFAULT '{}'::"text"[] NOT NULL
);


ALTER TABLE "public"."user_onboarding" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicle_geofence_alerts" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "geofence_id" "uuid" NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "latitude" double precision NOT NULL,
    "longitude" double precision NOT NULL,
    "distance_meters" double precision NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL
);


ALTER TABLE "public"."vehicle_geofence_alerts" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicle_geofences" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "organization_id" "uuid" NOT NULL,
    "name" "text" NOT NULL,
    "center_latitude" double precision NOT NULL,
    "center_longitude" double precision NOT NULL,
    "radius_meters" double precision NOT NULL,
    "is_active" boolean DEFAULT true NOT NULL,
    "created_by" "uuid",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    CONSTRAINT "vehicle_geofences_radius_meters_check" CHECK (("radius_meters" > (0)::double precision))
);


ALTER TABLE "public"."vehicle_geofences" OWNER TO "postgres";


CREATE TABLE IF NOT EXISTS "public"."vehicle_maintenance_records" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "vehicle_id" "uuid" NOT NULL,
    "user_id" "uuid" NOT NULL,
    "type" "text" NOT NULL,
    "performed_at" "date" NOT NULL,
    "odometer_at_service" numeric,
    "next_due_odometer" numeric,
    "next_due_date" "date",
    "cost" numeric,
    "notes" "text",
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "organization_id" "uuid",
    CONSTRAINT "chk_maintenance_type_valid" CHECK (("type" = ANY (ARRAY['oil_change'::"text", 'tire_rotation'::"text", 'brake_service'::"text", 'inspection'::"text", 'registration'::"text", 'battery'::"text", 'other'::"text"])))
);


ALTER TABLE "public"."vehicle_maintenance_records" OWNER TO "postgres";


COMMENT ON TABLE "public"."vehicle_maintenance_records" IS 'Historial de mantenimiento por vehículo (cambio de aceite, etc.). Ligado a vehicles con ON DELETE CASCADE porque un vehículo nunca se borra físicamente (se archiva) — este cascade solo aplicaría en un borrado manual directo en DB, no desde la app.';



CREATE TABLE IF NOT EXISTS "public"."vehicles" (
    "id" "uuid" DEFAULT "gen_random_uuid"() NOT NULL,
    "owner_user_id" "uuid",
    "organization_id" "uuid",
    "nickname" "text",
    "make" "text",
    "model" "text",
    "color" "text",
    "year" integer,
    "plate" "text",
    "vin" "text",
    "odometer" numeric(12,2),
    "is_active" boolean DEFAULT true NOT NULL,
    "is_primary" boolean DEFAULT false NOT NULL,
    "created_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT "now"() NOT NULL,
    "is_archived" boolean DEFAULT false NOT NULL,
    "assigned_driver_id" "uuid",
    "last_latitude" double precision,
    "last_longitude" double precision,
    "last_speed" double precision,
    "last_location_at" timestamp with time zone,
    "display_id" "text",
    "placed_in_service_date" "date",
    "odometer_cycle" "text" DEFAULT 'weekly'::"text" NOT NULL,
    "odometer_cycle_anchor" "date",
    "ifta_qualified" boolean DEFAULT false NOT NULL,
    "ifta_fuel_type" "text" DEFAULT 'diesel'::"text" NOT NULL,
    "fuel_tank_capacity_gal" numeric,
    "ownership" "text" DEFAULT 'company'::"text" NOT NULL,
    "branch_id" "uuid",
    "active_session_id" "uuid",
    "fleet_template" "text",
    "service" "text" NOT NULL,
    CONSTRAINT "vehicles_fuel_tank_capacity_gal_check" CHECK ((("fuel_tank_capacity_gal" IS NULL) OR ("fuel_tank_capacity_gal" > (0)::numeric))),
    CONSTRAINT "vehicles_ifta_fuel_type_check" CHECK (("ifta_fuel_type" = ANY (ARRAY['diesel'::"text", 'gasoline'::"text"]))),
    CONSTRAINT "vehicles_odometer_cycle_check" CHECK (("odometer_cycle" = ANY (ARRAY['weekly'::"text", 'biweekly'::"text", 'monthly'::"text", 'semimonthly'::"text", 'annual'::"text", 'daily'::"text"]))),
    CONSTRAINT "vehicles_owner_check" CHECK (((("owner_user_id" IS NOT NULL) AND ("organization_id" IS NULL)) OR (("owner_user_id" IS NULL) AND ("organization_id" IS NOT NULL)))),
    CONSTRAINT "vehicles_ownership_check" CHECK (("ownership" = ANY (ARRAY['company'::"text", 'driver_owned'::"text"]))),
    CONSTRAINT "vehicles_service_check" CHECK (("service" = ANY (ARRAY['gig'::"text", 'driving_school'::"text", 'school_bus'::"text", 'sales'::"text", 'trucking'::"text", 'general_business'::"text"]))),
    CONSTRAINT "vehicles_year_check" CHECK ((("year" >= 1980) AND ("year" <= 2100)))
);


ALTER TABLE "public"."vehicles" OWNER TO "postgres";


COMMENT ON COLUMN "public"."vehicles"."is_archived" IS 'Vehículo archivado por el usuario ("eliminado" desde la UI). Nunca se hace DELETE físico de vehicles para no romper sessions.vehicle_id (FK ON DELETE SET NULL) en viajes históricos.';



COMMENT ON COLUMN "public"."vehicles"."assigned_driver_id" IS 'Fleet Phase 2: which org member (member_role=driver) this vehicle is currently assigned to. NULL for unassigned fleet vehicles and for all Gig-mode vehicles (owner_user_id is the relevant column there instead).';



COMMENT ON COLUMN "public"."vehicles"."display_id" IS 'Human-facing fleet vehicle ID, CM-T####. Assigned automatically on insert, never user-editable.';



ALTER TABLE ONLY "public"."edge_function_rate_limits" ALTER COLUMN "id" SET DEFAULT "nextval"('"public"."edge_function_rate_limits_id_seq"'::"regclass");



ALTER TABLE ONLY "ops"."domain_allowed_functions"
    ADD CONSTRAINT "domain_allowed_functions_pkey" PRIMARY KEY ("fn");



ALTER TABLE ONLY "ops"."domain_check_log"
    ADD CONSTRAINT "domain_check_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "ops"."domain_tables"
    ADD CONSTRAINT "domain_tables_pkey" PRIMARY KEY ("tbl");



ALTER TABLE ONLY "ops"."domain_triggers"
    ADD CONSTRAINT "domain_triggers_pkey" PRIMARY KEY ("tbl", "tg");



ALTER TABLE ONLY "public"."app_versions"
    ADD CONSTRAINT "app_versions_pkey" PRIMARY KEY ("app");



ALTER TABLE ONLY "public"."audit_events"
    ADD CONSTRAINT "audit_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."auth_signup_errors"
    ADD CONSTRAINT "auth_signup_errors_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."branch_moves"
    ADD CONSTRAINT "branch_moves_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."branches"
    ADD CONSTRAINT "branches_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."device_permission_status"
    ADD CONSTRAINT "device_permission_status_pkey" PRIMARY KEY ("user_id");



ALTER TABLE ONLY "public"."diagnostic_logs"
    ADD CONSTRAINT "diagnostic_logs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."driver_invites"
    ADD CONSTRAINT "driver_invites_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."driver_notifications"
    ADD CONSTRAINT "driver_notifications_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."driver_safety_events"
    ADD CONSTRAINT "driver_safety_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."driver_slot_claim_attempts"
    ADD CONSTRAINT "driver_slot_claim_attempts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."driver_workdays"
    ADD CONSTRAINT "driver_workdays_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."driver_workdays"
    ADD CONSTRAINT "driver_workdays_unique" UNIQUE ("organization_id", "driver_id", "work_date");



ALTER TABLE ONLY "public"."driving_school_clients"
    ADD CONSTRAINT "driving_school_clients_pkey" PRIMARY KEY ("organization_id");



ALTER TABLE ONLY "public"."ds_availability"
    ADD CONSTRAINT "ds_availability_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_blocked_hours"
    ADD CONSTRAINT "ds_blocked_hours_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_certificates"
    ADD CONSTRAINT "ds_certificates_number_key" UNIQUE ("number");



ALTER TABLE ONLY "public"."ds_certificates"
    ADD CONSTRAINT "ds_certificates_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_client_students"
    ADD CONSTRAINT "ds_client_students_client_id_student_id_key" UNIQUE ("client_id", "student_id");



ALTER TABLE ONLY "public"."ds_client_students"
    ADD CONSTRAINT "ds_client_students_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_client_tokens"
    ADD CONSTRAINT "ds_client_tokens_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_client_tokens"
    ADD CONSTRAINT "ds_client_tokens_token_hash_key" UNIQUE ("token_hash");



ALTER TABLE ONLY "public"."ds_clients"
    ADD CONSTRAINT "ds_clients_organization_id_email_key" UNIQUE ("organization_id", "email");



ALTER TABLE ONLY "public"."ds_clients"
    ADD CONSTRAINT "ds_clients_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_enrollment_requests"
    ADD CONSTRAINT "ds_enrollment_requests_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_evaluation_scores"
    ADD CONSTRAINT "ds_evaluation_scores_pkey" PRIMARY KEY ("evaluation_id", "skill_id");



ALTER TABLE ONLY "public"."ds_evaluations"
    ADD CONSTRAINT "ds_evaluations_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_evaluations"
    ADD CONSTRAINT "ds_evaluations_shift_block_id_key" UNIQUE ("shift_block_id");



ALTER TABLE ONLY "public"."ds_packages"
    ADD CONSTRAINT "ds_packages_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_portal_links"
    ADD CONSTRAINT "ds_portal_links_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_portal_links"
    ADD CONSTRAINT "ds_portal_links_token_hash_key" UNIQUE ("token_hash");



ALTER TABLE ONLY "public"."ds_programs"
    ADD CONSTRAINT "ds_programs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_public_pages"
    ADD CONSTRAINT "ds_public_pages_custom_domain_key" UNIQUE ("custom_domain");



ALTER TABLE ONLY "public"."ds_public_pages"
    ADD CONSTRAINT "ds_public_pages_pkey" PRIMARY KEY ("organization_id");



ALTER TABLE ONLY "public"."ds_public_pages"
    ADD CONSTRAINT "ds_public_pages_slug_key" UNIQUE ("slug");



ALTER TABLE ONLY "public"."ds_reminders_sent"
    ADD CONSTRAINT "ds_reminders_sent_pkey" PRIMARY KEY ("shift_block_id", "recipient");



ALTER TABLE ONLY "public"."ds_settings"
    ADD CONSTRAINT "ds_settings_pkey" PRIMARY KEY ("organization_id");



ALTER TABLE ONLY "public"."ds_skills"
    ADD CONSTRAINT "ds_skills_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_slot_notices"
    ADD CONSTRAINT "ds_slot_notices_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_student_packages"
    ADD CONSTRAINT "ds_student_packages_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_student_private"
    ADD CONSTRAINT "ds_student_private_pkey" PRIMARY KEY ("student_id");



ALTER TABLE ONLY "public"."ds_students"
    ADD CONSTRAINT "ds_students_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ds_time_off"
    ADD CONSTRAINT "ds_time_off_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."edge_function_rate_limits"
    ADD CONSTRAINT "edge_function_rate_limits_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."fleet_driver_slots"
    ADD CONSTRAINT "fleet_driver_slots_display_id_key" UNIQUE ("display_id");



ALTER TABLE ONLY "public"."fleet_driver_slots"
    ADD CONSTRAINT "fleet_driver_slots_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."fleet_plans"
    ADD CONSTRAINT "fleet_plans_pkey" PRIMARY KEY ("tier");



ALTER TABLE ONLY "public"."fleet_type_changes"
    ADD CONSTRAINT "fleet_type_changes_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."fuel_anomalies"
    ADD CONSTRAINT "fuel_anomalies_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."fuel_anomalies"
    ADD CONSTRAINT "fuel_anomalies_purchase_id_kind_key" UNIQUE ("purchase_id", "kind");



ALTER TABLE ONLY "public"."fuel_purchases"
    ADD CONSTRAINT "fuel_purchases_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."general_business_clients"
    ADD CONSTRAINT "general_business_clients_pkey" PRIMARY KEY ("organization_id");



ALTER TABLE ONLY "public"."geocode_cache"
    ADD CONSTRAINT "geocode_cache_pkey" PRIMARY KEY ("organization_id", "query_norm");



ALTER TABLE ONLY "public"."gig_app_packages"
    ADD CONSTRAINT "gig_app_packages_os_package_name_key" UNIQUE ("os", "package_name");



ALTER TABLE ONLY "public"."gig_app_packages"
    ADD CONSTRAINT "gig_app_packages_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."gig_app_suggestions"
    ADD CONSTRAINT "gig_app_suggestions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."gig_apps"
    ADD CONSTRAINT "gig_apps_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."gig_clients"
    ADD CONSTRAINT "gig_clients_pkey" PRIMARY KEY ("profile_id");



ALTER TABLE ONLY "public"."guardian_invites"
    ADD CONSTRAINT "guardian_invites_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."guardian_invites"
    ADD CONSTRAINT "guardian_invites_token_hash_key" UNIQUE ("token_hash");



ALTER TABLE ONLY "public"."ifta_fuel_tax_rates"
    ADD CONSTRAINT "ifta_fuel_tax_rates_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ifta_fuel_tax_rates"
    ADD CONSTRAINT "ifta_fuel_tax_rates_quarter_jurisdiction_fuel_kind_key" UNIQUE ("quarter", "jurisdiction_code", "fuel_type", "kind");



ALTER TABLE ONLY "public"."ifta_us_state_boundaries"
    ADD CONSTRAINT "ifta_us_state_boundaries_pkey" PRIMARY KEY ("fips_code");



ALTER TABLE ONLY "public"."ifta_us_state_boundaries"
    ADD CONSTRAINT "ifta_us_state_boundaries_state_code_key" UNIQUE ("state_code");



ALTER TABLE ONLY "public"."odometer_ocr_feedback"
    ADD CONSTRAINT "odometer_ocr_feedback_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."organization_members"
    ADD CONSTRAINT "organization_members_organization_id_user_id_key" UNIQUE ("organization_id", "user_id");



ALTER TABLE ONLY "public"."organization_members"
    ADD CONSTRAINT "organization_members_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."organizations"
    ADD CONSTRAINT "organizations_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."organizations"
    ADD CONSTRAINT "organizations_slug_key" UNIQUE ("slug");



ALTER TABLE ONLY "public"."pdf_export_log"
    ADD CONSTRAINT "pdf_export_log_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."plan_feature_rules"
    ADD CONSTRAINT "plan_feature_rules_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."platform_id_policy"
    ADD CONSTRAINT "platform_id_policy_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."play_subscriptions"
    ADD CONSTRAINT "play_subscriptions_pkey" PRIMARY KEY ("purchase_token");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_display_id_key" UNIQUE ("display_id");



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."regular_trips"
    ADD CONSTRAINT "regular_trips_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."report_access_attempts"
    ADD CONSTRAINT "report_access_attempts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."reports"
    ADD CONSTRAINT "reports_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."reports"
    ADD CONSTRAINT "reports_qr_token_key" UNIQUE ("qr_token");



ALTER TABLE ONLY "public"."retired_display_ids"
    ADD CONSTRAINT "retired_display_ids_pkey" PRIMARY KEY ("display_id");



ALTER TABLE ONLY "public"."ridership_events"
    ADD CONSTRAINT "ridership_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."ridership_events"
    ADD CONSTRAINT "ridership_events_run_id_student_id_action_key" UNIQUE ("run_id", "student_id", "action");



ALTER TABLE ONLY "public"."route_crew_overrides"
    ADD CONSTRAINT "route_crew_overrides_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."route_crew_overrides"
    ADD CONSTRAINT "route_crew_overrides_route_id_service_date_key" UNIQUE ("route_id", "service_date");



ALTER TABLE ONLY "public"."route_runs"
    ADD CONSTRAINT "route_runs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."route_runs"
    ADD CONSTRAINT "route_runs_route_id_run_date_key" UNIQUE ("route_id", "run_date");



ALTER TABLE ONLY "public"."route_stop_events"
    ADD CONSTRAINT "route_stop_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."route_stop_events"
    ADD CONSTRAINT "route_stop_events_run_id_stop_id_key" UNIQUE ("run_id", "stop_id");



ALTER TABLE ONLY "public"."route_stops"
    ADD CONSTRAINT "route_stops_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."route_stops"
    ADD CONSTRAINT "route_stops_route_id_seq_key" UNIQUE ("route_id", "seq") DEFERRABLE INITIALLY DEFERRED;



ALTER TABLE ONLY "public"."routes"
    ADD CONSTRAINT "routes_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."sales_clients"
    ADD CONSTRAINT "sales_clients_pkey" PRIMARY KEY ("organization_id");



ALTER TABLE ONLY "public"."school_bus_clients"
    ADD CONSTRAINT "school_bus_clients_pkey" PRIMARY KEY ("organization_id");



ALTER TABLE ONLY "public"."school_guardians"
    ADD CONSTRAINT "school_guardians_display_id_key" UNIQUE ("display_id");



ALTER TABLE ONLY "public"."school_guardians"
    ADD CONSTRAINT "school_guardians_organization_id_email_key" UNIQUE ("organization_id", "email");



ALTER TABLE ONLY "public"."school_guardians"
    ADD CONSTRAINT "school_guardians_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."school_sites"
    ADD CONSTRAINT "school_sites_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."service_license_fees"
    ADD CONSTRAINT "service_license_fees_pkey" PRIMARY KEY ("service", "tier");



ALTER TABLE ONLY "public"."session_gps_breadcrumbs"
    ADD CONSTRAINT "session_gps_breadcrumbs_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."session_sections"
    ADD CONSTRAINT "session_sections_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_template_date_key" UNIQUE ("template_shift_id", "block_date");



ALTER TABLE ONLY "public"."shifts"
    ADD CONSTRAINT "shifts_driver_id_day_of_week_start_time_key" UNIQUE ("driver_id", "day_of_week", "start_time");



ALTER TABLE ONLY "public"."shifts"
    ADD CONSTRAINT "shifts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."student_guardians"
    ADD CONSTRAINT "student_guardians_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."student_guardians"
    ADD CONSTRAINT "student_guardians_student_id_guardian_id_key" UNIQUE ("student_id", "guardian_id");



ALTER TABLE ONLY "public"."student_ride_notices"
    ADD CONSTRAINT "student_ride_notices_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."student_ride_notices"
    ADD CONSTRAINT "student_ride_notices_student_id_notice_date_key" UNIQUE ("student_id", "notice_date");



ALTER TABLE ONLY "public"."student_stop_assignments"
    ADD CONSTRAINT "student_stop_assignments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."student_stop_assignments"
    ADD CONSTRAINT "student_stop_assignments_student_id_route_id_action_key" UNIQUE ("student_id", "route_id", "action");



ALTER TABLE ONLY "public"."students"
    ADD CONSTRAINT "students_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscription_events"
    ADD CONSTRAINT "subscription_events_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscription_events"
    ADD CONSTRAINT "subscription_events_stripe_event_id_key" UNIQUE ("stripe_event_id");



ALTER TABLE ONLY "public"."subscriptions"
    ADD CONSTRAINT "subscriptions_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."subscriptions"
    ADD CONSTRAINT "subscriptions_stripe_subscription_id_key" UNIQUE ("stripe_subscription_id");



ALTER TABLE ONLY "public"."trip_approvals"
    ADD CONSTRAINT "trip_approvals_pkey" PRIMARY KEY ("session_id");



ALTER TABLE ONLY "public"."trip_classification_settings"
    ADD CONSTRAINT "trip_classification_settings_pkey" PRIMARY KEY ("user_id");



ALTER TABLE ONLY "public"."trip_incidents"
    ADD CONSTRAINT "trip_incidents_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."trip_vehicle_assignments"
    ADD CONSTRAINT "trip_vehicle_assignments_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."trucking_clients"
    ADD CONSTRAINT "trucking_clients_pkey" PRIMARY KEY ("organization_id");



ALTER TABLE ONLY "public"."user_onboarding"
    ADD CONSTRAINT "user_onboarding_pkey" PRIMARY KEY ("user_id");



ALTER TABLE ONLY "public"."vehicle_geofence_alerts"
    ADD CONSTRAINT "vehicle_geofence_alerts_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicle_geofences"
    ADD CONSTRAINT "vehicle_geofences_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicle_inspections"
    ADD CONSTRAINT "vehicle_inspections_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicle_maintenance_records"
    ADD CONSTRAINT "vehicle_maintenance_records_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicle_odometer_checkpoints"
    ADD CONSTRAINT "vehicle_odometer_checkpoints_pkey" PRIMARY KEY ("id");



ALTER TABLE ONLY "public"."vehicle_odometer_checkpoints"
    ADD CONSTRAINT "vehicle_odometer_checkpoints_vehicle_id_week_start_date_key" UNIQUE ("vehicle_id", "week_start_date");



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_display_id_key" UNIQUE ("display_id");



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_pkey" PRIMARY KEY ("id");



CREATE INDEX "domain_check_log_checked_at_idx" ON "ops"."domain_check_log" USING "btree" ("checked_at" DESC);



CREATE INDEX "branch_moves_org_idx" ON "public"."branch_moves" USING "btree" ("organization_id", "moved_at" DESC);



CREATE INDEX "branch_moves_subject_idx" ON "public"."branch_moves" USING "btree" ("subject_id", "moved_at" DESC);



CREATE UNIQUE INDEX "branches_org_active_name_key" ON "public"."branches" USING "btree" ("organization_id", "lower"("name")) WHERE (NOT "is_archived");



CREATE UNIQUE INDEX "driver_notifications_trip_once" ON "public"."driver_notifications" USING "btree" ("session_id") WHERE ("kind" = 'trip_safety'::"text");



CREATE INDEX "driver_notifications_user_idx" ON "public"."driver_notifications" USING "btree" ("user_id", "created_at" DESC);



CREATE INDEX "driver_safety_events_org_time_idx" ON "public"."driver_safety_events" USING "btree" ("organization_id", "recorded_at");



CREATE INDEX "ds_availability_org_idx" ON "public"."ds_availability" USING "btree" ("organization_id", "weekday");



CREATE INDEX "ds_blocked_hours_org_idx" ON "public"."ds_blocked_hours" USING "btree" ("organization_id");



CREATE UNIQUE INDEX "ds_client_students_one_self" ON "public"."ds_client_students" USING "btree" ("student_id") WHERE (("relation" = 'self'::"text") AND "is_active");



CREATE INDEX "ds_client_students_student_idx" ON "public"."ds_client_students" USING "btree" ("student_id");



CREATE INDEX "ds_client_tokens_client_idx" ON "public"."ds_client_tokens" USING "btree" ("client_id");



CREATE INDEX "ds_enrollment_requests_org_idx" ON "public"."ds_enrollment_requests" USING "btree" ("organization_id", "created_at" DESC);



CREATE INDEX "ds_evaluations_student_idx" ON "public"."ds_evaluations" USING "btree" ("student_id");



CREATE INDEX "ds_programs_org_idx" ON "public"."ds_programs" USING "btree" ("organization_id", "sort");



CREATE INDEX "ds_skills_org_idx" ON "public"."ds_skills" USING "btree" ("organization_id", "sort");



CREATE INDEX "ds_student_packages_student_idx" ON "public"."ds_student_packages" USING "btree" ("student_id");



CREATE INDEX "ds_students_org_idx" ON "public"."ds_students" USING "btree" ("organization_id", "status");



CREATE INDEX "fleet_type_changes_org_idx" ON "public"."fleet_type_changes" USING "btree" ("organization_id", "created_at" DESC);



CREATE INDEX "fuel_anomalies_org_status_idx" ON "public"."fuel_anomalies" USING "btree" ("organization_id", "status", "created_at" DESC);



CREATE INDEX "fuel_purchases_org_date_idx" ON "public"."fuel_purchases" USING "btree" ("organization_id", "purchase_date") WHERE ("organization_id" IS NOT NULL);



CREATE INDEX "fuel_purchases_receipt_path_idx" ON "public"."fuel_purchases" USING "btree" ("receipt_path");



CREATE INDEX "fuel_purchases_vehicle_date_idx" ON "public"."fuel_purchases" USING "btree" ("vehicle_id", "purchase_date");



CREATE INDEX "geocode_cache_created_idx" ON "public"."geocode_cache" USING "btree" ("created_at");



CREATE INDEX "guardian_invites_guardian_idx" ON "public"."guardian_invites" USING "btree" ("guardian_id");



CREATE UNIQUE INDEX "idx_audit_events_odometer_dedupe" ON "public"."audit_events" USING "btree" ("session_id", "event_type") WHERE ("event_type" = ANY (ARRAY['ODOMETER_START'::"text", 'ODOMETER_END'::"text"]));



CREATE INDEX "idx_audit_org_activity" ON "public"."audit_events" USING "btree" ("organization_id", "created_at" DESC) WHERE ("event_type" <> 'GPS_TICK'::"text");



CREATE INDEX "idx_audit_session_created" ON "public"."audit_events" USING "btree" ("session_id", "created_at");



CREATE INDEX "idx_audit_user_created" ON "public"."audit_events" USING "btree" ("user_id", "created_at" DESC);



CREATE UNIQUE INDEX "idx_driver_invites_org_email_pending" ON "public"."driver_invites" USING "btree" ("organization_id", "lower"("email")) WHERE ("status" = 'pending'::"text");



CREATE INDEX "idx_driver_invites_org_status" ON "public"."driver_invites" USING "btree" ("organization_id", "status");



CREATE INDEX "idx_driver_invites_token_hash" ON "public"."driver_invites" USING "btree" ("token_hash");



CREATE INDEX "idx_driver_safety_events_org_recorded" ON "public"."driver_safety_events" USING "btree" ("organization_id", "recorded_at" DESC);



CREATE INDEX "idx_driver_slot_claim_attempts_user_time" ON "public"."driver_slot_claim_attempts" USING "btree" ("user_id", "attempted_at" DESC);



CREATE INDEX "idx_edge_function_rate_limits_lookup" ON "public"."edge_function_rate_limits" USING "btree" ("fn_name", "client_key", "created_at" DESC);



CREATE INDEX "idx_pdf_export_log_user_month" ON "public"."pdf_export_log" USING "btree" ("user_id", "exported_at");



CREATE INDEX "idx_report_access_attempts_ip_time" ON "public"."report_access_attempts" USING "btree" ("ip_hash", "attempted_at" DESC);



CREATE INDEX "idx_reports_org_date" ON "public"."reports" USING "btree" ("organization_id", "start_date");



CREATE INDEX "idx_reports_qr_token" ON "public"."reports" USING "btree" ("qr_token") WHERE ("qr_token" IS NOT NULL);



CREATE INDEX "idx_reports_user_date" ON "public"."reports" USING "btree" ("user_id", "start_date");



CREATE INDEX "idx_routes_org_status" ON "public"."routes" USING "btree" ("organization_id", "status");



CREATE INDEX "idx_sections_session" ON "public"."session_sections" USING "btree" ("session_id");



CREATE INDEX "idx_sections_user_time" ON "public"."session_sections" USING "btree" ("user_id", "start_time" DESC);



CREATE INDEX "idx_session_sections_irs_purpose" ON "public"."session_sections" USING "btree" ("irs_purpose") WHERE ("irs_purpose" IS NOT NULL);



CREATE INDEX "idx_sessions_org_time" ON "public"."sessions" USING "btree" ("organization_id", "start_time" DESC);



CREATE INDEX "idx_sessions_user_time" ON "public"."sessions" USING "btree" ("user_id", "start_time" DESC);



CREATE INDEX "idx_subscriptions_user_id" ON "public"."subscriptions" USING "btree" ("user_id");



CREATE INDEX "idx_trip_incidents_org_time" ON "public"."trip_incidents" USING "btree" ("organization_id", "created_at" DESC);



CREATE INDEX "idx_vehicle_maintenance_records_vehicle_id" ON "public"."vehicle_maintenance_records" USING "btree" ("vehicle_id");



CREATE INDEX "ifta_fuel_tax_rates_quarter_idx" ON "public"."ifta_fuel_tax_rates" USING "btree" ("quarter");



CREATE INDEX "ifta_us_state_boundaries_geom_idx" ON "public"."ifta_us_state_boundaries" USING "gist" ("geom");



CREATE INDEX "organization_members_branch_idx" ON "public"."organization_members" USING "btree" ("branch_id") WHERE ("branch_id" IS NOT NULL);



CREATE UNIQUE INDEX "plan_feature_rules_unique" ON "public"."plan_feature_rules" USING "btree" ("feature", "min_plan", "templates") NULLS NOT DISTINCT;



CREATE INDEX "play_subscriptions_user_idx" ON "public"."play_subscriptions" USING "btree" ("user_id");



CREATE INDEX "regular_trips_user_idx" ON "public"."regular_trips" USING "btree" ("user_id");



CREATE INDEX "ridership_events_run_idx" ON "public"."ridership_events" USING "btree" ("run_id");



CREATE INDEX "route_crew_overrides_org_date" ON "public"."route_crew_overrides" USING "btree" ("organization_id", "service_date");



CREATE INDEX "route_runs_org_date_idx" ON "public"."route_runs" USING "btree" ("organization_id", "run_date");



CREATE INDEX "route_runs_vehicle_active_idx" ON "public"."route_runs" USING "btree" ("vehicle_id") WHERE ("status" = 'in_progress'::"text");



CREATE INDEX "route_stops_route_idx" ON "public"."route_stops" USING "btree" ("route_id", "seq");



CREATE INDEX "school_guardians_user_idx" ON "public"."school_guardians" USING "btree" ("user_id") WHERE ("user_id" IS NOT NULL);



CREATE INDEX "school_sites_org_idx" ON "public"."school_sites" USING "btree" ("organization_id");



CREATE INDEX "session_gps_breadcrumbs_org_idx" ON "public"."session_gps_breadcrumbs" USING "btree" ("organization_id", "recorded_at");



CREATE INDEX "session_gps_breadcrumbs_session_idx" ON "public"."session_gps_breadcrumbs" USING "btree" ("session_id", "recorded_at");



CREATE INDEX "shift_blocks_driver_date_idx" ON "public"."shift_blocks" USING "btree" ("driver_id", "block_date");



CREATE INDEX "shift_blocks_org_date_idx" ON "public"."shift_blocks" USING "btree" ("organization_id", "block_date");



CREATE INDEX "shift_blocks_student_idx" ON "public"."shift_blocks" USING "btree" ("student_id") WHERE ("student_id" IS NOT NULL);



CREATE INDEX "shifts_driver_idx" ON "public"."shifts" USING "btree" ("driver_id");



CREATE INDEX "shifts_org_idx" ON "public"."shifts" USING "btree" ("organization_id");



CREATE INDEX "student_guardians_guardian_idx" ON "public"."student_guardians" USING "btree" ("guardian_id");



CREATE INDEX "student_ride_notices_org_date_idx" ON "public"."student_ride_notices" USING "btree" ("organization_id", "notice_date");



CREATE INDEX "student_stop_assignments_stop_idx" ON "public"."student_stop_assignments" USING "btree" ("stop_id");



CREATE INDEX "students_org_idx" ON "public"."students" USING "btree" ("organization_id");



CREATE INDEX "trip_approvals_org_idx" ON "public"."trip_approvals" USING "btree" ("organization_id", "decided_at" DESC);



CREATE INDEX "trip_vehicle_assignments_user_idx" ON "public"."trip_vehicle_assignments" USING "btree" ("user_id");



CREATE UNIQUE INDEX "uk_vehicles_one_active_per_owner" ON "public"."vehicles" USING "btree" ("owner_user_id") WHERE (("is_active" = true) AND ("is_archived" = false) AND ("owner_user_id" IS NOT NULL));



CREATE UNIQUE INDEX "uq_session_sections_one_open_per_session" ON "public"."session_sections" USING "btree" ("session_id") WHERE ("section_status" = ANY (ARRAY['active'::"text", 'paused'::"text"]));



CREATE UNIQUE INDEX "uq_sessions_one_open_personal_trip" ON "public"."sessions" USING "btree" ("user_id") WHERE (("organization_id" IS NULL) AND ("is_closed" IS NOT TRUE));



CREATE INDEX "vehicles_branch_idx" ON "public"."vehicles" USING "btree" ("branch_id") WHERE ("branch_id" IS NOT NULL);



CREATE OR REPLACE TRIGGER "fuel_purchases_evaluate" AFTER INSERT OR UPDATE OF "state_code", "fuel_type", "gallons" ON "public"."fuel_purchases" FOR EACH ROW EXECUTE FUNCTION "public"."fn_fuel_purchase_evaluate_trigger"();



CREATE OR REPLACE TRIGGER "sessions_notify_trip_safety" AFTER UPDATE OF "is_closed" ON "public"."sessions" FOR EACH ROW WHEN (("new"."organization_id" IS NOT NULL)) EXECUTE FUNCTION "public"."fn_notify_trip_safety"();



CREATE OR REPLACE TRIGGER "sessions_vehicle_active_trip" AFTER INSERT OR DELETE OR UPDATE OF "is_closed" ON "public"."sessions" FOR EACH ROW EXECUTE FUNCTION "public"."fn_vehicle_active_trip"();



CREATE OR REPLACE TRIGGER "shift_blocks_touch_updated_at" BEFORE UPDATE ON "public"."shift_blocks" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "shifts_touch_updated_at" BEFORE UPDATE ON "public"."shifts" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "tr_audit_events_inherit_tenant" BEFORE INSERT ON "public"."audit_events" FOR EACH ROW EXECUTE FUNCTION "public"."fn_inherit_session_tenant"();



CREATE OR REPLACE TRIGGER "tr_branches_plan_limit" BEFORE INSERT OR UPDATE OF "is_archived" ON "public"."branches" FOR EACH ROW EXECUTE FUNCTION "public"."fn_branches_plan_limit"();



CREATE OR REPLACE TRIGGER "tr_enforce_fleet_org" AFTER INSERT OR UPDATE OF "account_type" ON "public"."profiles" FOR EACH ROW WHEN (("new"."account_type" = ANY (ARRAY['fleet_admin'::"text", 'fleet_driver'::"text"]))) EXECUTE FUNCTION "public"."enforce_fleet_org_membership"();



CREATE OR REPLACE TRIGGER "tr_maintenance_guard_tenant" BEFORE INSERT OR UPDATE OF "vehicle_id", "user_id", "organization_id" ON "public"."vehicle_maintenance_records" FOR EACH ROW EXECUTE FUNCTION "public"."fn_guard_maintenance_tenant"();



CREATE OR REPLACE TRIGGER "tr_org_driving_school_cycle" AFTER UPDATE OF "industry_template" ON "public"."organizations" FOR EACH ROW EXECUTE FUNCTION "public"."fn_org_driving_school_cycle"();



CREATE OR REPLACE TRIGGER "tr_org_svc_driving_school_add" AFTER INSERT OR UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN (("new"."service" = 'driving_school'::"text")) EXECUTE FUNCTION "public"."fn_sync_driving_school_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_driving_school_drop" AFTER UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN ((("old"."service" = 'driving_school'::"text") AND ("new"."service" <> 'driving_school'::"text"))) EXECUTE FUNCTION "public"."fn_sync_driving_school_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_general_business_add" AFTER INSERT OR UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN (("new"."service" = 'general_business'::"text")) EXECUTE FUNCTION "public"."fn_sync_general_business_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_general_business_drop" AFTER UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN ((("old"."service" = 'general_business'::"text") AND ("new"."service" <> 'general_business'::"text"))) EXECUTE FUNCTION "public"."fn_sync_general_business_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_sales_add" AFTER INSERT OR UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN (("new"."service" = 'sales'::"text")) EXECUTE FUNCTION "public"."fn_sync_sales_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_sales_drop" AFTER UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN ((("old"."service" = 'sales'::"text") AND ("new"."service" <> 'sales'::"text"))) EXECUTE FUNCTION "public"."fn_sync_sales_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_school_bus_add" AFTER INSERT OR UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN (("new"."service" = 'school_bus'::"text")) EXECUTE FUNCTION "public"."fn_sync_school_bus_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_school_bus_drop" AFTER UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN ((("old"."service" = 'school_bus'::"text") AND ("new"."service" <> 'school_bus'::"text"))) EXECUTE FUNCTION "public"."fn_sync_school_bus_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_trucking_add" AFTER INSERT OR UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN (("new"."service" = 'trucking'::"text")) EXECUTE FUNCTION "public"."fn_sync_trucking_client"();



CREATE OR REPLACE TRIGGER "tr_org_svc_trucking_drop" AFTER UPDATE OF "service" ON "public"."organizations" FOR EACH ROW WHEN ((("old"."service" = 'trucking'::"text") AND ("new"."service" <> 'trucking'::"text"))) EXECUTE FUNCTION "public"."fn_sync_trucking_client"();



CREATE OR REPLACE TRIGGER "tr_organizations_enforce_assignment_mode_tier" BEFORE UPDATE OF "vehicle_assignment_mode" ON "public"."organizations" FOR EACH ROW EXECUTE FUNCTION "public"."fn_enforce_vehicle_assignment_mode_tier"();



CREATE OR REPLACE TRIGGER "tr_organizations_fleet_template" AFTER UPDATE OF "industry_template" ON "public"."organizations" FOR EACH ROW WHEN (("new"."industry_template" IS DISTINCT FROM "old"."industry_template")) EXECUTE FUNCTION "public"."fn_org_fleet_template_to_vehicles"();



CREATE OR REPLACE TRIGGER "tr_organizations_service" BEFORE INSERT OR UPDATE OF "industry_template" ON "public"."organizations" FOR EACH ROW EXECUTE FUNCTION "public"."fn_sync_org_service"();



CREATE OR REPLACE TRIGGER "tr_organizations_touch_updated_at" BEFORE UPDATE ON "public"."organizations" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "tr_organizations_validate_timezone" BEFORE INSERT OR UPDATE OF "timezone" ON "public"."organizations" FOR EACH ROW EXECUTE FUNCTION "public"."fn_validate_org_timezone"();



CREATE OR REPLACE TRIGGER "tr_profiles_assign_display_id" BEFORE INSERT ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_assign_profile_display_id"();



CREATE OR REPLACE TRIGGER "tr_profiles_gig_client" AFTER INSERT OR UPDATE OF "account_type" ON "public"."profiles" FOR EACH ROW WHEN (("new"."account_type" = 'gig'::"text")) EXECUTE FUNCTION "public"."fn_sync_gig_client"();



CREATE OR REPLACE TRIGGER "tr_profiles_touch_updated_at" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "tr_regular_trips_touch_updated_at" BEFORE UPDATE ON "public"."regular_trips" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "tr_school_guardians_display_id" BEFORE INSERT ON "public"."school_guardians" FOR EACH ROW EXECUTE FUNCTION "public"."fn_assign_guardian_display_id"();



CREATE OR REPLACE TRIGGER "tr_session_sections_inherit_tenant" BEFORE INSERT OR UPDATE OF "session_id", "user_id", "organization_id" ON "public"."session_sections" FOR EACH ROW EXECUTE FUNCTION "public"."fn_inherit_session_tenant"();



CREATE OR REPLACE TRIGGER "tr_session_sections_touch_updated_at" BEFORE UPDATE ON "public"."session_sections" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "tr_sessions_block_cross_app_open_trip" BEFORE INSERT ON "public"."sessions" FOR EACH ROW EXECUTE FUNCTION "public"."fn_block_cross_app_open_trip"();



CREATE OR REPLACE TRIGGER "tr_sessions_enforce_active_org_membership" BEFORE INSERT ON "public"."sessions" FOR EACH ROW WHEN (("new"."organization_id" IS NOT NULL)) EXECUTE FUNCTION "public"."fn_enforce_active_org_membership"();



CREATE OR REPLACE TRIGGER "tr_sessions_enforce_trial" BEFORE INSERT ON "public"."sessions" FOR EACH ROW WHEN (("new"."organization_id" IS NULL)) EXECUTE FUNCTION "public"."fn_enforce_trial_or_subscription"();



CREATE OR REPLACE TRIGGER "tr_sessions_guard_tenant" BEFORE INSERT OR UPDATE OF "user_id", "organization_id", "vehicle_id" ON "public"."sessions" FOR EACH ROW EXECUTE FUNCTION "public"."fn_guard_session_tenant"();



CREATE OR REPLACE TRIGGER "tr_sessions_link_shift_block" AFTER INSERT ON "public"."sessions" FOR EACH ROW WHEN (("new"."shift_block_id" IS NOT NULL)) EXECUTE FUNCTION "public"."fn_link_session_to_shift_block"();



CREATE OR REPLACE TRIGGER "tr_sessions_touch_updated_at" BEFORE UPDATE ON "public"."sessions" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "tr_shift_blocks_freeze_started" BEFORE UPDATE ON "public"."shift_blocks" FOR EACH ROW EXECUTE FUNCTION "public"."fn_freeze_started_shift_block"();



CREATE OR REPLACE TRIGGER "tr_trip_classification_settings_touch_updated_at" BEFORE UPDATE ON "public"."trip_classification_settings" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "tr_user_onboarding_touch_updated_at" BEFORE UPDATE ON "public"."user_onboarding" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "tr_vehicles_0_fleet_template" BEFORE INSERT OR UPDATE OF "organization_id", "fleet_template" ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_vehicles_fleet_template"();



CREATE OR REPLACE TRIGGER "tr_vehicles_1_service" BEFORE INSERT OR UPDATE OF "organization_id", "owner_user_id" ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_set_vehicle_service"();



CREATE OR REPLACE TRIGGER "tr_vehicles_block_switch_during_session" BEFORE INSERT OR UPDATE ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_block_vehicle_switch_during_active_session"();



CREATE OR REPLACE TRIGGER "tr_vehicles_driving_school_cycle" BEFORE INSERT OR UPDATE OF "organization_id" ON "public"."vehicles" FOR EACH ROW WHEN (("new"."fleet_template" = 'driving_school'::"text")) EXECUTE FUNCTION "public"."fn_vehicles_driving_school_cycle"();



CREATE OR REPLACE TRIGGER "tr_vehicles_enforce_count_limit" BEFORE INSERT ON "public"."vehicles" FOR EACH ROW WHEN (("new"."organization_id" IS NULL)) EXECUTE FUNCTION "public"."fn_enforce_vehicle_count_limit"();



CREATE OR REPLACE TRIGGER "tr_vehicles_enforce_odometer_cycle_tier" BEFORE INSERT OR UPDATE OF "odometer_cycle" ON "public"."vehicles" FOR EACH ROW WHEN (("new"."organization_id" IS NULL)) EXECUTE FUNCTION "public"."fn_enforce_odometer_cycle_tier"();



CREATE OR REPLACE TRIGGER "tr_vehicles_enforce_odometer_floor" BEFORE INSERT OR UPDATE ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_enforce_vehicle_odometer_floor"();



CREATE OR REPLACE TRIGGER "tr_vehicles_plan_limit" BEFORE INSERT OR UPDATE OF "is_archived", "organization_id" ON "public"."vehicles" FOR EACH ROW WHEN (("new"."organization_id" IS NOT NULL)) EXECUTE FUNCTION "public"."fn_vehicles_plan_limit"();



CREATE OR REPLACE TRIGGER "tr_vehicles_set_cycle_anchor" BEFORE INSERT ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_vehicles_set_cycle_anchor"();



CREATE OR REPLACE TRIGGER "tr_vehicles_touch_updated_at" BEFORE UPDATE ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_touch_updated_at"();



CREATE OR REPLACE TRIGGER "trg_assign_driver_slot_display_id" BEFORE INSERT ON "public"."fleet_driver_slots" FOR EACH ROW EXECUTE FUNCTION "public"."fn_assign_driver_slot_display_id"();



CREATE OR REPLACE TRIGGER "trg_assign_vehicle_display_id" BEFORE INSERT ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_assign_vehicle_display_id"();



CREATE OR REPLACE TRIGGER "trg_classify_section_on_close" BEFORE UPDATE ON "public"."session_sections" FOR EACH ROW WHEN (("new"."organization_id" IS NULL)) EXECUTE FUNCTION "public"."fn_classify_section_on_close"();



CREATE OR REPLACE TRIGGER "trg_delete_personal_rows_on_profile_delete" BEFORE DELETE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_delete_personal_rows_on_profile_delete"();



CREATE OR REPLACE TRIGGER "trg_discard_zero_mile_trip" AFTER UPDATE OF "is_closed" ON "public"."sessions" FOR EACH ROW WHEN (("new"."is_closed" AND (NOT COALESCE("old"."is_closed", false)))) EXECUTE FUNCTION "public"."fn_discard_zero_mile_trip"();



CREATE OR REPLACE TRIGGER "trg_ds_block_student_same_org" BEFORE INSERT OR UPDATE OF "student_id" ON "public"."shift_blocks" FOR EACH ROW EXECUTE FUNCTION "public"."fn_ds_block_student_same_org"();



CREATE OR REPLACE TRIGGER "trg_ds_certificates_immutable" BEFORE UPDATE ON "public"."ds_certificates" FOR EACH ROW EXECUTE FUNCTION "public"."fn_ds_certificates_immutable"();



CREATE OR REPLACE TRIGGER "trg_ds_evaluations_touch" BEFORE UPDATE ON "public"."ds_evaluations" FOR EACH ROW EXECUTE FUNCTION "public"."fn_ds_touch"();



CREATE OR REPLACE TRIGGER "trg_ds_student_program_same_org" BEFORE INSERT OR UPDATE OF "program_id" ON "public"."ds_students" FOR EACH ROW EXECUTE FUNCTION "public"."fn_ds_student_program_same_org"();



CREATE OR REPLACE TRIGGER "trg_ds_students_touch" BEFORE UPDATE ON "public"."ds_students" FOR EACH ROW EXECUTE FUNCTION "public"."fn_ds_touch"();



CREATE OR REPLACE TRIGGER "trg_enforce_org_feature_switches" BEFORE UPDATE OF "allow_driver_owned_vehicles", "use_shift_schedules" ON "public"."organizations" FOR EACH ROW EXECUTE FUNCTION "public"."fn_enforce_org_feature_switches"();



CREATE OR REPLACE TRIGGER "trg_freeze_closed_route" BEFORE UPDATE ON "public"."routes" FOR EACH ROW EXECUTE FUNCTION "public"."fn_freeze_closed_route"();



CREATE OR REPLACE TRIGGER "trg_freeze_closed_session" BEFORE UPDATE ON "public"."sessions" FOR EACH ROW EXECUTE FUNCTION "public"."fn_freeze_closed_session"();



CREATE OR REPLACE TRIGGER "trg_freeze_closed_session_section" BEFORE UPDATE ON "public"."session_sections" FOR EACH ROW EXECUTE FUNCTION "public"."fn_freeze_closed_session_section"();



CREATE OR REPLACE TRIGGER "trg_freeze_profile_display_id" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_freeze_profile_display_id"();



CREATE OR REPLACE TRIGGER "trg_freeze_vehicle_display_id" BEFORE UPDATE ON "public"."vehicles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_freeze_vehicle_display_id"();



CREATE OR REPLACE TRIGGER "trg_guard_org_billing_columns" BEFORE INSERT OR UPDATE ON "public"."organizations" FOR EACH ROW EXECUTE FUNCTION "public"."fn_guard_org_billing_columns"();



CREATE OR REPLACE TRIGGER "trg_guard_profile_protected_columns" BEFORE UPDATE ON "public"."profiles" FOR EACH ROW EXECUTE FUNCTION "public"."fn_guard_profile_protected_columns"();



CREATE OR REPLACE TRIGGER "trg_retire_driver_slot_id" AFTER DELETE ON "public"."fleet_driver_slots" FOR EACH ROW WHEN (("old"."display_id" IS NOT NULL)) EXECUTE FUNCTION "public"."fn_retire_display_id"('driver');



CREATE OR REPLACE TRIGGER "trg_retire_guardian_id" AFTER DELETE ON "public"."school_guardians" FOR EACH ROW WHEN (("old"."display_id" IS NOT NULL)) EXECUTE FUNCTION "public"."fn_retire_display_id"('guardian');



CREATE OR REPLACE TRIGGER "trg_retire_profile_id" AFTER DELETE ON "public"."profiles" FOR EACH ROW WHEN (("old"."display_id" IS NOT NULL)) EXECUTE FUNCTION "public"."fn_retire_display_id"('profile');



CREATE OR REPLACE TRIGGER "trg_retire_vehicle_id" AFTER DELETE ON "public"."vehicles" FOR EACH ROW WHEN (("old"."display_id" IS NOT NULL)) EXECUTE FUNCTION "public"."fn_retire_display_id"('vehicle');



CREATE OR REPLACE TRIGGER "trg_route_crew_overrides_check_monitor" BEFORE INSERT OR UPDATE OF "monitor_id" ON "public"."route_crew_overrides" FOR EACH ROW EXECUTE FUNCTION "public"."fn_check_route_monitor"();



CREATE OR REPLACE TRIGGER "trg_route_runs_set_monitor" BEFORE INSERT ON "public"."route_runs" FOR EACH ROW EXECUTE FUNCTION "public"."fn_route_run_set_monitor"();



CREATE OR REPLACE TRIGGER "trg_route_stops_same_org" BEFORE INSERT OR UPDATE ON "public"."route_stops" FOR EACH ROW EXECUTE FUNCTION "public"."fn_school_same_org"();



CREATE OR REPLACE TRIGGER "trg_routes_check_monitor" BEFORE INSERT OR UPDATE OF "monitor_id" ON "public"."routes" FOR EACH ROW EXECUTE FUNCTION "public"."fn_check_route_monitor"();



CREATE OR REPLACE TRIGGER "trg_session_miles_from_sections" BEFORE UPDATE ON "public"."sessions" FOR EACH ROW EXECUTE FUNCTION "public"."fn_session_miles_from_sections"();



CREATE OR REPLACE TRIGGER "trg_student_stop_assignments_same_org" BEFORE INSERT OR UPDATE ON "public"."student_stop_assignments" FOR EACH ROW EXECUTE FUNCTION "public"."fn_school_same_org"();



CREATE OR REPLACE TRIGGER "trg_vehicles_route_run_stops" AFTER UPDATE OF "last_latitude", "last_longitude" ON "public"."vehicles" FOR EACH ROW WHEN ((("new"."fleet_template" = 'school_transport'::"text") AND (("new"."last_latitude" IS DISTINCT FROM "old"."last_latitude") OR ("new"."last_longitude" IS DISTINCT FROM "old"."last_longitude")))) EXECUTE FUNCTION "public"."fn_route_run_track_stops"();



ALTER TABLE ONLY "public"."audit_events"
    ADD CONSTRAINT "audit_events_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."audit_events"
    ADD CONSTRAINT "audit_events_section_id_fkey" FOREIGN KEY ("section_id") REFERENCES "public"."session_sections"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."audit_events"
    ADD CONSTRAINT "audit_events_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."audit_events"
    ADD CONSTRAINT "audit_events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."branch_moves"
    ADD CONSTRAINT "branch_moves_from_branch_id_fkey" FOREIGN KEY ("from_branch_id") REFERENCES "public"."branches"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."branch_moves"
    ADD CONSTRAINT "branch_moves_moved_by_fkey" FOREIGN KEY ("moved_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."branch_moves"
    ADD CONSTRAINT "branch_moves_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."branch_moves"
    ADD CONSTRAINT "branch_moves_to_branch_id_fkey" FOREIGN KEY ("to_branch_id") REFERENCES "public"."branches"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."branches"
    ADD CONSTRAINT "branches_manager_id_fkey" FOREIGN KEY ("manager_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."branches"
    ADD CONSTRAINT "branches_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."device_permission_status"
    ADD CONSTRAINT "device_permission_status_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."diagnostic_logs"
    ADD CONSTRAINT "diagnostic_logs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."driver_invites"
    ADD CONSTRAINT "driver_invites_accepted_by_fkey" FOREIGN KEY ("accepted_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."driver_invites"
    ADD CONSTRAINT "driver_invites_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."driver_invites"
    ADD CONSTRAINT "driver_invites_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."driver_invites"
    ADD CONSTRAINT "driver_invites_slot_id_fkey" FOREIGN KEY ("slot_id") REFERENCES "public"."fleet_driver_slots"("id");



ALTER TABLE ONLY "public"."driver_notifications"
    ADD CONSTRAINT "driver_notifications_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."driver_notifications"
    ADD CONSTRAINT "driver_notifications_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."driver_notifications"
    ADD CONSTRAINT "driver_notifications_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."driver_slot_claim_attempts"
    ADD CONSTRAINT "driver_slot_claim_attempts_slot_id_fkey" FOREIGN KEY ("slot_id") REFERENCES "public"."fleet_driver_slots"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."driver_workdays"
    ADD CONSTRAINT "driver_workdays_driver_id_fkey" FOREIGN KEY ("driver_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."driver_workdays"
    ADD CONSTRAINT "driver_workdays_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."driving_school_clients"
    ADD CONSTRAINT "driving_school_clients_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_availability"
    ADD CONSTRAINT "ds_availability_instructor_id_fkey" FOREIGN KEY ("instructor_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_availability"
    ADD CONSTRAINT "ds_availability_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_availability"
    ADD CONSTRAINT "ds_availability_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_blocked_hours"
    ADD CONSTRAINT "ds_blocked_hours_instructor_id_fkey" FOREIGN KEY ("instructor_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_blocked_hours"
    ADD CONSTRAINT "ds_blocked_hours_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_certificates"
    ADD CONSTRAINT "ds_certificates_issued_by_fkey" FOREIGN KEY ("issued_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_certificates"
    ADD CONSTRAINT "ds_certificates_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_certificates"
    ADD CONSTRAINT "ds_certificates_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."ds_students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_client_students"
    ADD CONSTRAINT "ds_client_students_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."ds_clients"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_client_students"
    ADD CONSTRAINT "ds_client_students_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_client_students"
    ADD CONSTRAINT "ds_client_students_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."ds_students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_client_tokens"
    ADD CONSTRAINT "ds_client_tokens_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."ds_clients"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_client_tokens"
    ADD CONSTRAINT "ds_client_tokens_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_clients"
    ADD CONSTRAINT "ds_clients_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_clients"
    ADD CONSTRAINT "ds_clients_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_enrollment_requests"
    ADD CONSTRAINT "ds_enrollment_requests_branch_id_fkey" FOREIGN KEY ("branch_id") REFERENCES "public"."branches"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_enrollment_requests"
    ADD CONSTRAINT "ds_enrollment_requests_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "public"."ds_clients"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_enrollment_requests"
    ADD CONSTRAINT "ds_enrollment_requests_decided_by_fkey" FOREIGN KEY ("decided_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_enrollment_requests"
    ADD CONSTRAINT "ds_enrollment_requests_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_enrollment_requests"
    ADD CONSTRAINT "ds_enrollment_requests_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "public"."ds_programs"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_enrollment_requests"
    ADD CONSTRAINT "ds_enrollment_requests_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."ds_students"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_evaluation_scores"
    ADD CONSTRAINT "ds_evaluation_scores_evaluation_id_fkey" FOREIGN KEY ("evaluation_id") REFERENCES "public"."ds_evaluations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_evaluation_scores"
    ADD CONSTRAINT "ds_evaluation_scores_skill_id_fkey" FOREIGN KEY ("skill_id") REFERENCES "public"."ds_skills"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_evaluations"
    ADD CONSTRAINT "ds_evaluations_instructor_id_fkey" FOREIGN KEY ("instructor_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_evaluations"
    ADD CONSTRAINT "ds_evaluations_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_evaluations"
    ADD CONSTRAINT "ds_evaluations_shift_block_id_fkey" FOREIGN KEY ("shift_block_id") REFERENCES "public"."shift_blocks"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_evaluations"
    ADD CONSTRAINT "ds_evaluations_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."ds_students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_packages"
    ADD CONSTRAINT "ds_packages_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_portal_links"
    ADD CONSTRAINT "ds_portal_links_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_portal_links"
    ADD CONSTRAINT "ds_portal_links_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_portal_links"
    ADD CONSTRAINT "ds_portal_links_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."ds_students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_programs"
    ADD CONSTRAINT "ds_programs_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_public_pages"
    ADD CONSTRAINT "ds_public_pages_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_reminders_sent"
    ADD CONSTRAINT "ds_reminders_sent_shift_block_id_fkey" FOREIGN KEY ("shift_block_id") REFERENCES "public"."shift_blocks"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_settings"
    ADD CONSTRAINT "ds_settings_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_skills"
    ADD CONSTRAINT "ds_skills_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_slot_notices"
    ADD CONSTRAINT "ds_slot_notices_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_slot_notices"
    ADD CONSTRAINT "ds_slot_notices_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "public"."ds_programs"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_student_packages"
    ADD CONSTRAINT "ds_student_packages_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_student_packages"
    ADD CONSTRAINT "ds_student_packages_package_id_fkey" FOREIGN KEY ("package_id") REFERENCES "public"."ds_packages"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_student_packages"
    ADD CONSTRAINT "ds_student_packages_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."ds_students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_student_private"
    ADD CONSTRAINT "ds_student_private_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_student_private"
    ADD CONSTRAINT "ds_student_private_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."ds_students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_students"
    ADD CONSTRAINT "ds_students_branch_id_fkey" FOREIGN KEY ("branch_id") REFERENCES "public"."branches"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_students"
    ADD CONSTRAINT "ds_students_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_students"
    ADD CONSTRAINT "ds_students_emancipated_by_fkey" FOREIGN KEY ("emancipated_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_students"
    ADD CONSTRAINT "ds_students_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_students"
    ADD CONSTRAINT "ds_students_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "public"."ds_programs"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ds_time_off"
    ADD CONSTRAINT "ds_time_off_instructor_id_fkey" FOREIGN KEY ("instructor_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ds_time_off"
    ADD CONSTRAINT "ds_time_off_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."fleet_driver_slots"
    ADD CONSTRAINT "fleet_driver_slots_claimed_by_fkey" FOREIGN KEY ("claimed_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."fleet_driver_slots"
    ADD CONSTRAINT "fleet_driver_slots_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."fleet_driver_slots"
    ADD CONSTRAINT "fleet_driver_slots_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."fleet_type_changes"
    ADD CONSTRAINT "fleet_type_changes_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."fuel_anomalies"
    ADD CONSTRAINT "fuel_anomalies_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."fuel_anomalies"
    ADD CONSTRAINT "fuel_anomalies_purchase_id_fkey" FOREIGN KEY ("purchase_id") REFERENCES "public"."fuel_purchases"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."fuel_anomalies"
    ADD CONSTRAINT "fuel_anomalies_reviewed_by_fkey" FOREIGN KEY ("reviewed_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."fuel_anomalies"
    ADD CONSTRAINT "fuel_anomalies_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."fuel_purchases"
    ADD CONSTRAINT "fuel_purchases_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id");



ALTER TABLE ONLY "public"."fuel_purchases"
    ADD CONSTRAINT "fuel_purchases_state_code_fkey" FOREIGN KEY ("state_code") REFERENCES "public"."ifta_us_state_boundaries"("state_code");



ALTER TABLE ONLY "public"."fuel_purchases"
    ADD CONSTRAINT "fuel_purchases_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."fuel_purchases"
    ADD CONSTRAINT "fuel_purchases_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."general_business_clients"
    ADD CONSTRAINT "general_business_clients_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."geocode_cache"
    ADD CONSTRAINT "geocode_cache_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."gig_app_suggestions"
    ADD CONSTRAINT "gig_app_suggestions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."gig_clients"
    ADD CONSTRAINT "gig_clients_profile_id_fkey" FOREIGN KEY ("profile_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."guardian_invites"
    ADD CONSTRAINT "guardian_invites_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."guardian_invites"
    ADD CONSTRAINT "guardian_invites_guardian_id_fkey" FOREIGN KEY ("guardian_id") REFERENCES "public"."school_guardians"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."guardian_invites"
    ADD CONSTRAINT "guardian_invites_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."odometer_ocr_feedback"
    ADD CONSTRAINT "odometer_ocr_feedback_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."odometer_ocr_feedback"
    ADD CONSTRAINT "odometer_ocr_feedback_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."organization_members"
    ADD CONSTRAINT "organization_members_branch_id_fkey" FOREIGN KEY ("branch_id") REFERENCES "public"."branches"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."organization_members"
    ADD CONSTRAINT "organization_members_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."organization_members"
    ADD CONSTRAINT "organization_members_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."organizations"
    ADD CONSTRAINT "organizations_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."pdf_export_log"
    ADD CONSTRAINT "pdf_export_log_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."play_subscriptions"
    ADD CONSTRAINT "play_subscriptions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_default_org_id_fkey" FOREIGN KEY ("default_org_id") REFERENCES "public"."organizations"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."profiles"
    ADD CONSTRAINT "profiles_id_fkey" FOREIGN KEY ("id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."regular_trips"
    ADD CONSTRAINT "regular_trips_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."report_access_attempts"
    ADD CONSTRAINT "report_access_attempts_report_id_fkey" FOREIGN KEY ("report_id") REFERENCES "public"."reports"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."reports"
    ADD CONSTRAINT "reports_generated_by_fkey" FOREIGN KEY ("generated_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."reports"
    ADD CONSTRAINT "reports_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."reports"
    ADD CONSTRAINT "reports_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."reports"
    ADD CONSTRAINT "reports_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ridership_events"
    ADD CONSTRAINT "ridership_events_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ridership_events"
    ADD CONSTRAINT "ridership_events_recorded_by_fkey" FOREIGN KEY ("recorded_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ridership_events"
    ADD CONSTRAINT "ridership_events_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "public"."route_runs"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."ridership_events"
    ADD CONSTRAINT "ridership_events_stop_id_fkey" FOREIGN KEY ("stop_id") REFERENCES "public"."route_stops"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."ridership_events"
    ADD CONSTRAINT "ridership_events_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_crew_overrides"
    ADD CONSTRAINT "route_crew_overrides_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."route_crew_overrides"
    ADD CONSTRAINT "route_crew_overrides_driver_id_fkey" FOREIGN KEY ("driver_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."route_crew_overrides"
    ADD CONSTRAINT "route_crew_overrides_monitor_id_fkey" FOREIGN KEY ("monitor_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."route_crew_overrides"
    ADD CONSTRAINT "route_crew_overrides_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_crew_overrides"
    ADD CONSTRAINT "route_crew_overrides_route_id_fkey" FOREIGN KEY ("route_id") REFERENCES "public"."routes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_crew_overrides"
    ADD CONSTRAINT "route_crew_overrides_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."route_runs"
    ADD CONSTRAINT "route_runs_driver_id_fkey" FOREIGN KEY ("driver_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."route_runs"
    ADD CONSTRAINT "route_runs_monitor_id_fkey" FOREIGN KEY ("monitor_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."route_runs"
    ADD CONSTRAINT "route_runs_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_runs"
    ADD CONSTRAINT "route_runs_route_id_fkey" FOREIGN KEY ("route_id") REFERENCES "public"."routes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_runs"
    ADD CONSTRAINT "route_runs_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."route_runs"
    ADD CONSTRAINT "route_runs_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."route_stop_events"
    ADD CONSTRAINT "route_stop_events_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_stop_events"
    ADD CONSTRAINT "route_stop_events_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "public"."route_runs"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_stop_events"
    ADD CONSTRAINT "route_stop_events_stop_id_fkey" FOREIGN KEY ("stop_id") REFERENCES "public"."route_stops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_stops"
    ADD CONSTRAINT "route_stops_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."route_stops"
    ADD CONSTRAINT "route_stops_route_id_fkey" FOREIGN KEY ("route_id") REFERENCES "public"."routes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."routes"
    ADD CONSTRAINT "routes_assigned_driver_id_fkey" FOREIGN KEY ("assigned_driver_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."routes"
    ADD CONSTRAINT "routes_assigned_vehicle_id_fkey" FOREIGN KEY ("assigned_vehicle_id") REFERENCES "public"."vehicles"("id");



ALTER TABLE ONLY "public"."routes"
    ADD CONSTRAINT "routes_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."routes"
    ADD CONSTRAINT "routes_monitor_id_fkey" FOREIGN KEY ("monitor_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."routes"
    ADD CONSTRAINT "routes_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."routes"
    ADD CONSTRAINT "routes_school_site_id_fkey" FOREIGN KEY ("school_site_id") REFERENCES "public"."school_sites"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."sales_clients"
    ADD CONSTRAINT "sales_clients_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."school_bus_clients"
    ADD CONSTRAINT "school_bus_clients_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."school_guardians"
    ADD CONSTRAINT "school_guardians_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."school_guardians"
    ADD CONSTRAINT "school_guardians_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."school_guardians"
    ADD CONSTRAINT "school_guardians_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."school_sites"
    ADD CONSTRAINT "school_sites_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."service_license_fees"
    ADD CONSTRAINT "service_license_fees_tier_fkey" FOREIGN KEY ("tier") REFERENCES "public"."fleet_plans"("tier");



ALTER TABLE ONLY "public"."session_gps_breadcrumbs"
    ADD CONSTRAINT "session_gps_breadcrumbs_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id");



ALTER TABLE ONLY "public"."session_gps_breadcrumbs"
    ADD CONSTRAINT "session_gps_breadcrumbs_section_id_fkey" FOREIGN KEY ("section_id") REFERENCES "public"."session_sections"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."session_gps_breadcrumbs"
    ADD CONSTRAINT "session_gps_breadcrumbs_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."session_gps_breadcrumbs"
    ADD CONSTRAINT "session_gps_breadcrumbs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."session_gps_breadcrumbs"
    ADD CONSTRAINT "session_gps_breadcrumbs_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id");



ALTER TABLE ONLY "public"."session_sections"
    ADD CONSTRAINT "session_sections_gig_app_fkey" FOREIGN KEY ("gig_app") REFERENCES "public"."gig_apps"("id") ON UPDATE CASCADE ON DELETE RESTRICT;



ALTER TABLE ONLY "public"."session_sections"
    ADD CONSTRAINT "session_sections_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."session_sections"
    ADD CONSTRAINT "session_sections_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."session_sections"
    ADD CONSTRAINT "session_sections_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_ended_by_user_id_fkey" FOREIGN KEY ("ended_by_user_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_shift_block_id_fkey" FOREIGN KEY ("shift_block_id") REFERENCES "public"."shift_blocks"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_started_by_user_id_fkey" FOREIGN KEY ("started_by_user_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."sessions"
    ADD CONSTRAINT "sessions_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_driver_id_fkey" FOREIGN KEY ("driver_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_session_fk" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."ds_students"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_template_shift_id_fkey" FOREIGN KEY ("template_shift_id") REFERENCES "public"."shifts"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."shift_blocks"
    ADD CONSTRAINT "shift_blocks_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."shifts"
    ADD CONSTRAINT "shifts_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."shifts"
    ADD CONSTRAINT "shifts_driver_id_fkey" FOREIGN KEY ("driver_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."shifts"
    ADD CONSTRAINT "shifts_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."shifts"
    ADD CONSTRAINT "shifts_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."student_guardians"
    ADD CONSTRAINT "student_guardians_guardian_id_fkey" FOREIGN KEY ("guardian_id") REFERENCES "public"."school_guardians"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."student_guardians"
    ADD CONSTRAINT "student_guardians_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."student_guardians"
    ADD CONSTRAINT "student_guardians_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."student_ride_notices"
    ADD CONSTRAINT "student_ride_notices_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."student_ride_notices"
    ADD CONSTRAINT "student_ride_notices_reported_by_fkey" FOREIGN KEY ("reported_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."student_ride_notices"
    ADD CONSTRAINT "student_ride_notices_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."student_stop_assignments"
    ADD CONSTRAINT "student_stop_assignments_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."student_stop_assignments"
    ADD CONSTRAINT "student_stop_assignments_route_id_fkey" FOREIGN KEY ("route_id") REFERENCES "public"."routes"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."student_stop_assignments"
    ADD CONSTRAINT "student_stop_assignments_stop_id_fkey" FOREIGN KEY ("stop_id") REFERENCES "public"."route_stops"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."student_stop_assignments"
    ADD CONSTRAINT "student_stop_assignments_student_id_fkey" FOREIGN KEY ("student_id") REFERENCES "public"."students"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."students"
    ADD CONSTRAINT "students_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."students"
    ADD CONSTRAINT "students_school_site_id_fkey" FOREIGN KEY ("school_site_id") REFERENCES "public"."school_sites"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."subscription_events"
    ADD CONSTRAINT "subscription_events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."subscriptions"
    ADD CONSTRAINT "subscriptions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."trip_approvals"
    ADD CONSTRAINT "trip_approvals_decided_by_fkey" FOREIGN KEY ("decided_by") REFERENCES "auth"."users"("id");



ALTER TABLE ONLY "public"."trip_approvals"
    ADD CONSTRAINT "trip_approvals_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."trip_approvals"
    ADD CONSTRAINT "trip_approvals_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."trip_classification_settings"
    ADD CONSTRAINT "trip_classification_settings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."trip_incidents"
    ADD CONSTRAINT "trip_incidents_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id");



ALTER TABLE ONLY "public"."trip_incidents"
    ADD CONSTRAINT "trip_incidents_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "public"."sessions"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."trip_incidents"
    ADD CONSTRAINT "trip_incidents_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."trip_incidents"
    ADD CONSTRAINT "trip_incidents_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id");



ALTER TABLE ONLY "public"."trucking_clients"
    ADD CONSTRAINT "trucking_clients_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."user_onboarding"
    ADD CONSTRAINT "user_onboarding_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_geofence_alerts"
    ADD CONSTRAINT "vehicle_geofence_alerts_geofence_id_fkey" FOREIGN KEY ("geofence_id") REFERENCES "public"."vehicle_geofences"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_geofence_alerts"
    ADD CONSTRAINT "vehicle_geofence_alerts_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id");



ALTER TABLE ONLY "public"."vehicle_geofence_alerts"
    ADD CONSTRAINT "vehicle_geofence_alerts_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_geofences"
    ADD CONSTRAINT "vehicle_geofences_created_by_fkey" FOREIGN KEY ("created_by") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicle_geofences"
    ADD CONSTRAINT "vehicle_geofences_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id");



ALTER TABLE ONLY "public"."vehicle_geofences"
    ADD CONSTRAINT "vehicle_geofences_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_inspections"
    ADD CONSTRAINT "vehicle_inspections_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id");



ALTER TABLE ONLY "public"."vehicle_inspections"
    ADD CONSTRAINT "vehicle_inspections_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicle_inspections"
    ADD CONSTRAINT "vehicle_inspections_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_maintenance_records"
    ADD CONSTRAINT "vehicle_maintenance_records_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id");



ALTER TABLE ONLY "public"."vehicle_maintenance_records"
    ADD CONSTRAINT "vehicle_maintenance_records_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_maintenance_records"
    ADD CONSTRAINT "vehicle_maintenance_records_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicle_odometer_checkpoints"
    ADD CONSTRAINT "vehicle_odometer_checkpoints_end_captured_by_fkey" FOREIGN KEY ("end_captured_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicle_odometer_checkpoints"
    ADD CONSTRAINT "vehicle_odometer_checkpoints_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id");



ALTER TABLE ONLY "public"."vehicle_odometer_checkpoints"
    ADD CONSTRAINT "vehicle_odometer_checkpoints_start_captured_by_fkey" FOREIGN KEY ("start_captured_by") REFERENCES "auth"."users"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicle_odometer_checkpoints"
    ADD CONSTRAINT "vehicle_odometer_checkpoints_vehicle_id_fkey" FOREIGN KEY ("vehicle_id") REFERENCES "public"."vehicles"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_active_session_id_fkey" FOREIGN KEY ("active_session_id") REFERENCES "public"."sessions"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_assigned_driver_id_fkey" FOREIGN KEY ("assigned_driver_id") REFERENCES "public"."profiles"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_branch_id_fkey" FOREIGN KEY ("branch_id") REFERENCES "public"."branches"("id") ON DELETE SET NULL;



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE CASCADE;



ALTER TABLE ONLY "public"."vehicles"
    ADD CONSTRAINT "vehicles_owner_user_id_fkey" FOREIGN KEY ("owner_user_id") REFERENCES "public"."profiles"("id") ON DELETE CASCADE;



ALTER TABLE "public"."app_versions" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "app_versions_read" ON "public"."app_versions" FOR SELECT TO "authenticated", "anon" USING (true);



CREATE POLICY "audit_delete_blocked" ON "public"."audit_events" FOR DELETE TO "authenticated" USING (false);



ALTER TABLE "public"."audit_events" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "audit_insert" ON "public"."audit_events" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "audit_select" ON "public"."audit_events" FOR SELECT TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."fn_org_has_feature"("organization_id", 'activity_log'::"text"))));



CREATE POLICY "audit_update_blocked" ON "public"."audit_events" FOR UPDATE TO "authenticated" USING (false);



ALTER TABLE "public"."auth_signup_errors" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."branch_moves" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "branch_moves_select" ON "public"."branch_moves" FOR SELECT USING ("public"."is_org_operator_or_above"("organization_id"));



ALTER TABLE "public"."branches" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "branches_delete" ON "public"."branches" FOR DELETE USING ("public"."is_org_admin_or_owner"("organization_id"));



CREATE POLICY "branches_insert" ON "public"."branches" FOR INSERT WITH CHECK ("public"."is_org_admin_or_owner"("organization_id"));



CREATE POLICY "branches_select" ON "public"."branches" FOR SELECT USING ("public"."is_org_member"("organization_id"));



CREATE POLICY "branches_update" ON "public"."branches" FOR UPDATE USING ("public"."is_org_admin_or_owner"("organization_id")) WITH CHECK ("public"."is_org_admin_or_owner"("organization_id"));



ALTER TABLE "public"."device_permission_status" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "device_permission_status_select_own" ON "public"."device_permission_status" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."diagnostic_logs" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "diagnostic_logs_insert_own" ON "public"."diagnostic_logs" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "diagnostic_logs_select_own" ON "public"."diagnostic_logs" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."driver_invites" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "driver_invites_select_admin" ON "public"."driver_invites" FOR SELECT TO "authenticated" USING ("public"."is_org_operator_or_above"("organization_id"));



ALTER TABLE "public"."driver_notifications" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "driver_notifications_select_own" ON "public"."driver_notifications" FOR SELECT USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."driver_safety_events" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "driver_safety_events_insert" ON "public"."driver_safety_events" FOR INSERT WITH CHECK ((("user_id" = "auth"."uid"()) AND "public"."is_org_member"("organization_id")));



CREATE POLICY "driver_safety_events_select" ON "public"."driver_safety_events" FOR SELECT USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'safety_scores'::"text")));



ALTER TABLE "public"."driver_slot_claim_attempts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."driver_workdays" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "driver_workdays_select" ON "public"."driver_workdays" FOR SELECT TO "authenticated" USING ((("driver_id" = "auth"."uid"()) OR "public"."is_org_operator_or_above"("organization_id")));



ALTER TABLE "public"."driving_school_clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "driving_school_clients_members" ON "public"."driving_school_clients" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "driving_school_clients"."organization_id") AND ("m"."user_id" = "auth"."uid"()) AND "m"."is_active"))));



ALTER TABLE "public"."ds_availability" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_availability_select" ON "public"."ds_availability" FOR SELECT TO "authenticated" USING (("public"."fn_org_has_feature"("organization_id", 'classes'::"text") AND ("public"."is_org_operator_or_above"("organization_id") OR ("instructor_id" = "auth"."uid"()))));



CREATE POLICY "ds_availability_write" ON "public"."ds_availability" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'classes'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'classes'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "ds_availability"."organization_id") AND ("m"."user_id" = "ds_availability"."instructor_id") AND "m"."is_active"))) AND (("vehicle_id" IS NULL) OR (EXISTS ( SELECT 1
   FROM "public"."vehicles" "v"
  WHERE (("v"."id" = "ds_availability"."vehicle_id") AND ("v"."organization_id" = "ds_availability"."organization_id")))))));



ALTER TABLE "public"."ds_blocked_hours" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_blocked_hours_select" ON "public"."ds_blocked_hours" FOR SELECT USING (("public"."fn_org_has_feature"("organization_id", 'classes'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "ds_blocked_hours"."organization_id") AND ("m"."user_id" = "auth"."uid"()) AND "m"."is_active")))));



CREATE POLICY "ds_blocked_hours_write" ON "public"."ds_blocked_hours" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'classes'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'classes'::"text") AND (("instructor_id" IS NULL) OR (EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "ds_blocked_hours"."organization_id") AND ("m"."user_id" = "ds_blocked_hours"."instructor_id") AND "m"."is_active"))))));



ALTER TABLE "public"."ds_certificates" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_certificates_select" ON "public"."ds_certificates" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_certificates'::"text")));



ALTER TABLE "public"."ds_client_students" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_client_students_select" ON "public"."ds_client_students" FOR SELECT USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_portal'::"text")));



ALTER TABLE "public"."ds_client_tokens" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."ds_clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_clients_select" ON "public"."ds_clients" FOR SELECT USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_portal'::"text")));



ALTER TABLE "public"."ds_enrollment_requests" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_enrollment_requests_select" ON "public"."ds_enrollment_requests" FOR SELECT USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_portal'::"text")));



ALTER TABLE "public"."ds_evaluation_scores" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_evaluation_scores_select" ON "public"."ds_evaluation_scores" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."ds_evaluations" "e"
  WHERE ("e"."id" = "ds_evaluation_scores"."evaluation_id"))));



ALTER TABLE "public"."ds_evaluations" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_evaluations_select" ON "public"."ds_evaluations" FOR SELECT TO "authenticated" USING (("public"."fn_org_has_feature"("organization_id", 'student_evaluations'::"text") AND ("public"."is_org_operator_or_above"("organization_id") OR ("instructor_id" = "auth"."uid"()))));



ALTER TABLE "public"."ds_packages" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_packages_select" ON "public"."ds_packages" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_packages'::"text")));



CREATE POLICY "ds_packages_write" ON "public"."ds_packages" TO "authenticated" USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_packages'::"text"))) WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_packages'::"text")));



ALTER TABLE "public"."ds_portal_links" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_portal_links_select" ON "public"."ds_portal_links" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_portal'::"text")));



ALTER TABLE "public"."ds_programs" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_programs_select" ON "public"."ds_programs" FOR SELECT TO "authenticated" USING ("public"."fn_org_has_feature"("organization_id", 'students'::"text"));



CREATE POLICY "ds_programs_write" ON "public"."ds_programs" TO "authenticated" USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'students'::"text"))) WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'students'::"text")));



ALTER TABLE "public"."ds_public_pages" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_public_pages_insert" ON "public"."ds_public_pages" FOR INSERT WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_portal'::"text")));



CREATE POLICY "ds_public_pages_select" ON "public"."ds_public_pages" FOR SELECT USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_portal'::"text")));



CREATE POLICY "ds_public_pages_update" ON "public"."ds_public_pages" FOR UPDATE USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_portal'::"text"))) WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_portal'::"text")));



ALTER TABLE "public"."ds_reminders_sent" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."ds_settings" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_settings_select" ON "public"."ds_settings" FOR SELECT TO "authenticated" USING ("public"."fn_org_has_feature"("organization_id", 'students'::"text"));



CREATE POLICY "ds_settings_write" ON "public"."ds_settings" TO "authenticated" USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'students'::"text"))) WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'students'::"text")));



ALTER TABLE "public"."ds_skills" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_skills_select" ON "public"."ds_skills" FOR SELECT TO "authenticated" USING ("public"."fn_org_has_feature"("organization_id", 'student_evaluations'::"text"));



CREATE POLICY "ds_skills_write" ON "public"."ds_skills" TO "authenticated" USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_evaluations'::"text"))) WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_evaluations'::"text")));



ALTER TABLE "public"."ds_slot_notices" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."ds_student_packages" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_student_packages_all" ON "public"."ds_student_packages" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_packages'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'student_packages'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."ds_students" "s"
  WHERE (("s"."id" = "ds_student_packages"."student_id") AND ("s"."organization_id" = "ds_student_packages"."organization_id"))))));



ALTER TABLE "public"."ds_student_private" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_student_private_all" ON "public"."ds_student_private" TO "authenticated" USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'students'::"text"))) WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'students'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."ds_students" "s"
  WHERE (("s"."id" = "ds_student_private"."student_id") AND ("s"."organization_id" = "ds_student_private"."organization_id"))))));



ALTER TABLE "public"."ds_students" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_students_select" ON "public"."ds_students" FOR SELECT TO "authenticated" USING (("public"."fn_org_has_feature"("organization_id", 'students'::"text") AND ("public"."is_org_operator_or_above"("organization_id") OR (EXISTS ( SELECT 1
   FROM "public"."shift_blocks" "b"
  WHERE (("b"."student_id" = "ds_students"."id") AND ("b"."driver_id" = "auth"."uid"())))))));



CREATE POLICY "ds_students_write" ON "public"."ds_students" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'students'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'students'::"text") AND (("branch_id" IS NULL) OR (EXISTS ( SELECT 1
   FROM "public"."branches" "br"
  WHERE (("br"."id" = "ds_students"."branch_id") AND ("br"."organization_id" = "ds_students"."organization_id")))))));



ALTER TABLE "public"."ds_time_off" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ds_time_off_select" ON "public"."ds_time_off" FOR SELECT TO "authenticated" USING (("public"."fn_org_has_feature"("organization_id", 'classes'::"text") AND ("public"."is_org_operator_or_above"("organization_id") OR ("instructor_id" = "auth"."uid"()))));



CREATE POLICY "ds_time_off_write" ON "public"."ds_time_off" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'classes'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'classes'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "ds_time_off"."organization_id") AND ("m"."user_id" = "ds_time_off"."instructor_id") AND "m"."is_active")))));



ALTER TABLE "public"."edge_function_rate_limits" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."fleet_driver_slots" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "fleet_driver_slots_delete_admin" ON "public"."fleet_driver_slots" FOR DELETE TO "authenticated" USING ("public"."is_org_operator_or_above"("organization_id"));



CREATE POLICY "fleet_driver_slots_select_admin" ON "public"."fleet_driver_slots" FOR SELECT TO "authenticated" USING ("public"."is_org_operator_or_above"("organization_id"));



ALTER TABLE "public"."fleet_plans" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."fleet_type_changes" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "fleet_type_changes_select_admin" ON "public"."fleet_type_changes" FOR SELECT TO "authenticated" USING ("public"."is_org_admin_or_owner"("organization_id"));



ALTER TABLE "public"."fuel_anomalies" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "fuel_anomalies_select" ON "public"."fuel_anomalies" FOR SELECT USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'fuel_alerts'::"text")));



ALTER TABLE "public"."fuel_purchases" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "fuel_purchases_delete" ON "public"."fuel_purchases" FOR DELETE USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id"))));



CREATE POLICY "fuel_purchases_select" ON "public"."fuel_purchases" FOR SELECT USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_member"("organization_id"))));



ALTER TABLE "public"."general_business_clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "general_business_clients_members" ON "public"."general_business_clients" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "general_business_clients"."organization_id") AND ("m"."user_id" = "auth"."uid"()) AND "m"."is_active"))));



ALTER TABLE "public"."geocode_cache" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "geocode_cache_insert" ON "public"."geocode_cache" FOR INSERT TO "authenticated" WITH CHECK ("public"."is_org_operator_or_above"("organization_id"));



CREATE POLICY "geocode_cache_select" ON "public"."geocode_cache" FOR SELECT TO "authenticated" USING ("public"."is_org_operator_or_above"("organization_id"));



CREATE POLICY "geocode_cache_update" ON "public"."geocode_cache" FOR UPDATE TO "authenticated" USING ("public"."is_org_operator_or_above"("organization_id")) WITH CHECK ("public"."is_org_operator_or_above"("organization_id"));



ALTER TABLE "public"."gig_app_packages" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "gig_app_packages_select_all" ON "public"."gig_app_packages" FOR SELECT TO "authenticated" USING (true);



ALTER TABLE "public"."gig_app_suggestions" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "gig_app_suggestions_insert_own" ON "public"."gig_app_suggestions" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "gig_app_suggestions_select_own" ON "public"."gig_app_suggestions" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."gig_apps" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "gig_apps_select" ON "public"."gig_apps" FOR SELECT TO "authenticated" USING (true);



ALTER TABLE "public"."gig_clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "gig_clients_own" ON "public"."gig_clients" FOR SELECT USING (("profile_id" = "auth"."uid"()));



ALTER TABLE "public"."guardian_invites" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "guardian_invites_select" ON "public"."guardian_invites" FOR SELECT USING ("public"."is_org_admin_or_owner"("organization_id"));



ALTER TABLE "public"."ifta_fuel_tax_rates" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ifta_fuel_tax_rates_select" ON "public"."ifta_fuel_tax_rates" FOR SELECT USING (("auth"."role"() = 'authenticated'::"text"));



ALTER TABLE "public"."ifta_us_state_boundaries" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ifta_us_state_boundaries_select" ON "public"."ifta_us_state_boundaries" FOR SELECT USING (true);



ALTER TABLE "public"."odometer_ocr_feedback" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "odometer_ocr_feedback_insert_own" ON "public"."odometer_ocr_feedback" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "odometer_ocr_feedback_select_own" ON "public"."odometer_ocr_feedback" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



CREATE POLICY "onboarding_delete_own" ON "public"."user_onboarding" FOR DELETE TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "onboarding_insert_own" ON "public"."user_onboarding" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "onboarding_select_own" ON "public"."user_onboarding" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "onboarding_update_own" ON "public"."user_onboarding" FOR UPDATE TO "authenticated" USING (("auth"."uid"() = "user_id")) WITH CHECK (("auth"."uid"() = "user_id"));



CREATE POLICY "org_members_delete_admin_or_self" ON "public"."organization_members" FOR DELETE TO "authenticated" USING ((("auth"."uid"() = "user_id") OR ("public"."is_org_admin_or_owner"("organization_id") AND ("member_role" <> 'owner'::"text")) OR ("public"."is_org_operator_or_above"("organization_id") AND ("member_role" = 'driver'::"text"))));



CREATE POLICY "org_members_insert_admin" ON "public"."organization_members" FOR INSERT TO "authenticated" WITH CHECK (("public"."is_org_owner"("organization_id") OR ("public"."is_org_admin_or_owner"("organization_id") AND ("member_role" = ANY (ARRAY['driver'::"text", 'operator'::"text"]))) OR ("public"."is_org_operator_or_above"("organization_id") AND ("member_role" = 'driver'::"text")) OR (("user_id" = "auth"."uid"()) AND "public"."fn_is_org_creator"("organization_id") AND (NOT (EXISTS ( SELECT 1
   FROM "public"."organization_members" "om2"
  WHERE ("om2"."organization_id" = "organization_members"."organization_id")))))));



CREATE POLICY "org_members_select_admin" ON "public"."organization_members" FOR SELECT TO "authenticated" USING ("public"."is_org_operator_or_above"("organization_id"));



CREATE POLICY "org_members_select_own" ON "public"."organization_members" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "user_id"));



CREATE POLICY "org_members_update_admin" ON "public"."organization_members" FOR UPDATE TO "authenticated" USING ((("public"."is_org_admin_or_owner"("organization_id") AND ("member_role" <> 'owner'::"text")) OR ("public"."is_org_operator_or_above"("organization_id") AND ("member_role" = 'driver'::"text")))) WITH CHECK (("public"."is_org_owner"("organization_id") OR ("public"."is_org_admin_or_owner"("organization_id") AND ("member_role" = ANY (ARRAY['driver'::"text", 'operator'::"text"]))) OR ("public"."is_org_operator_or_above"("organization_id") AND ("member_role" = 'driver'::"text"))));



ALTER TABLE "public"."organization_members" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."organizations" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "organizations_delete_owner" ON "public"."organizations" FOR DELETE TO "authenticated" USING ("public"."is_org_member"("id", 'owner'::"text"));



CREATE POLICY "organizations_insert_auth" ON "public"."organizations" FOR INSERT TO "authenticated" WITH CHECK (("created_by" = "auth"."uid"()));



CREATE POLICY "organizations_select_member" ON "public"."organizations" FOR SELECT TO "authenticated" USING ("public"."is_org_member"("id"));



CREATE POLICY "organizations_update_admin" ON "public"."organizations" FOR UPDATE TO "authenticated" USING ("public"."is_org_admin_or_owner"("id")) WITH CHECK ("public"."is_org_admin_or_owner"("id"));



ALTER TABLE "public"."pdf_export_log" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "pdf_export_log_select_own" ON "public"."pdf_export_log" FOR SELECT USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."plan_feature_rules" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."platform_id_policy" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."play_subscriptions" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "play_subscriptions_select_own" ON "public"."play_subscriptions" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "profiles_delete_own" ON "public"."profiles" FOR DELETE TO "authenticated" USING (("auth"."uid"() = "id"));



CREATE POLICY "profiles_insert_blocked" ON "public"."profiles" FOR INSERT TO "authenticated" WITH CHECK (false);



CREATE POLICY "profiles_select_org_admin" ON "public"."profiles" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM "public"."organization_members" "om"
  WHERE (("om"."user_id" = "profiles"."id") AND "public"."is_org_admin_or_owner"("om"."organization_id")))));



CREATE POLICY "profiles_select_own" ON "public"."profiles" FOR SELECT TO "authenticated" USING (("auth"."uid"() = "id"));



CREATE POLICY "profiles_update_own" ON "public"."profiles" FOR UPDATE TO "authenticated" USING (("auth"."uid"() = "id")) WITH CHECK (("auth"."uid"() = "id"));



ALTER TABLE "public"."regular_trips" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "regular_trips_own" ON "public"."regular_trips" TO "authenticated" USING ((( SELECT "auth"."uid"() AS "uid") = "user_id")) WITH CHECK ((( SELECT "auth"."uid"() AS "uid") = "user_id"));



ALTER TABLE "public"."report_access_attempts" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."reports" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "reports_select_own" ON "public"."reports" FOR SELECT TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_member"("organization_id"))));



ALTER TABLE "public"."retired_display_ids" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."ridership_events" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "ridership_events_select_admin" ON "public"."ridership_events" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



ALTER TABLE "public"."route_crew_overrides" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "route_crew_overrides_read" ON "public"."route_crew_overrides" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school_live'::"text")));



CREATE POLICY "route_crew_overrides_write_admin" ON "public"."route_crew_overrides" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school_live'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school_live'::"text") AND (EXISTS ( SELECT 1
   FROM "public"."routes" "r"
  WHERE (("r"."id" = "route_crew_overrides"."route_id") AND ("r"."organization_id" = "route_crew_overrides"."organization_id")))) AND (("vehicle_id" IS NULL) OR (EXISTS ( SELECT 1
   FROM "public"."vehicles" "v"
  WHERE (("v"."id" = "route_crew_overrides"."vehicle_id") AND ("v"."organization_id" = "route_crew_overrides"."organization_id"))))) AND (("driver_id" IS NULL) OR (EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."user_id" = "route_crew_overrides"."driver_id") AND ("m"."organization_id" = "route_crew_overrides"."organization_id") AND "m"."is_active"))))));



ALTER TABLE "public"."route_runs" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "route_runs_select_admin" ON "public"."route_runs" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



ALTER TABLE "public"."route_stop_events" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "route_stop_events_select_admin" ON "public"."route_stop_events" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



ALTER TABLE "public"."route_stops" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "route_stops_select_admin" ON "public"."route_stops" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



CREATE POLICY "route_stops_write_admin" ON "public"."route_stops" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



ALTER TABLE "public"."routes" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "routes_delete_admin" ON "public"."routes" FOR DELETE TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND ("status" = 'draft'::"text") AND "public"."fn_route_feature_ok"("organization_id", "route_type")));



CREATE POLICY "routes_insert_admin" ON "public"."routes" FOR INSERT TO "authenticated" WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND ("created_by" = "auth"."uid"()) AND "public"."fn_route_feature_ok"("organization_id", "route_type")));



CREATE POLICY "routes_select_admin" ON "public"."routes" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_route_feature_ok"("organization_id", "route_type")));



CREATE POLICY "routes_select_assigned_driver" ON "public"."routes" FOR SELECT TO "authenticated" USING ((("assigned_driver_id" = "auth"."uid"()) AND "public"."fn_route_feature_ok"("organization_id", "route_type")));



CREATE POLICY "routes_update_admin" ON "public"."routes" FOR UPDATE TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_route_feature_ok"("organization_id", "route_type"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_route_feature_ok"("organization_id", "route_type")));



ALTER TABLE "public"."sales_clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "sales_clients_members" ON "public"."sales_clients" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "sales_clients"."organization_id") AND ("m"."user_id" = "auth"."uid"()) AND "m"."is_active"))));



ALTER TABLE "public"."school_bus_clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "school_bus_clients_members" ON "public"."school_bus_clients" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "school_bus_clients"."organization_id") AND ("m"."user_id" = "auth"."uid"()) AND "m"."is_active"))));



ALTER TABLE "public"."school_guardians" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "school_guardians_select" ON "public"."school_guardians" FOR SELECT USING (("public"."is_org_operator_or_above"("organization_id") OR ("user_id" = ( SELECT "auth"."uid"() AS "uid"))));



ALTER TABLE "public"."school_sites" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "school_sites_select_admin" ON "public"."school_sites" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



CREATE POLICY "school_sites_write_admin" ON "public"."school_sites" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



CREATE POLICY "sections_delete" ON "public"."session_sections" FOR DELETE TO "authenticated" USING (((("organization_id" IS NULL) AND ("user_id" = "auth"."uid"())) OR (("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id"))));



CREATE POLICY "sections_insert" ON "public"."session_sections" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "sections_select" ON "public"."session_sections" FOR SELECT TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_member"("organization_id"))));



CREATE POLICY "sections_update" ON "public"."session_sections" FOR UPDATE TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id")))) WITH CHECK ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id"))));



ALTER TABLE "public"."service_license_fees" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."session_gps_breadcrumbs" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "session_gps_breadcrumbs_insert" ON "public"."session_gps_breadcrumbs" FOR INSERT WITH CHECK ((("user_id" = "auth"."uid"()) AND (("organization_id" IS NULL) OR "public"."is_org_member"("organization_id"))));



CREATE POLICY "session_gps_breadcrumbs_select" ON "public"."session_gps_breadcrumbs" FOR SELECT USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_member"("organization_id"))));



ALTER TABLE "public"."session_sections" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."sessions" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "sessions_delete" ON "public"."sessions" FOR DELETE TO "authenticated" USING (((("organization_id" IS NULL) AND ("user_id" = "auth"."uid"())) OR (("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id")) OR (("organization_id" IS NOT NULL) AND ("user_id" = "auth"."uid"()) AND (NOT COALESCE("is_closed", false)) AND (NOT (EXISTS ( SELECT 1
   FROM "public"."session_gps_breadcrumbs" "b"
  WHERE ("b"."session_id" = "sessions"."id")))))));



CREATE POLICY "sessions_insert" ON "public"."sessions" FOR INSERT TO "authenticated" WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "sessions_select" ON "public"."sessions" FOR SELECT TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_member"("organization_id"))));



CREATE POLICY "sessions_update" ON "public"."sessions" FOR UPDATE TO "authenticated" USING ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id")))) WITH CHECK ((("user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id"))));



ALTER TABLE "public"."shift_blocks" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "shift_blocks_delete" ON "public"."shift_blocks" FOR DELETE USING (("public"."is_org_operator_or_above"("organization_id") AND ("status" = 'scheduled'::"text") AND ("public"."fn_org_has_classes"("organization_id") OR "public"."fn_org_has_feature"("organization_id", 'shift_schedules'::"text"))));



CREATE POLICY "shift_blocks_insert" ON "public"."shift_blocks" FOR INSERT TO "authenticated" WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND ("source" = 'one_off'::"text") AND "public"."fn_org_has_classes"("organization_id")));



CREATE POLICY "shift_blocks_select" ON "public"."shift_blocks" FOR SELECT TO "authenticated" USING ((("driver_id" = "auth"."uid"()) OR "public"."is_org_operator_or_above"("organization_id")));



CREATE POLICY "shift_blocks_update" ON "public"."shift_blocks" FOR UPDATE USING (("public"."is_org_operator_or_above"("organization_id") AND ("public"."fn_org_has_classes"("organization_id") OR "public"."fn_org_has_feature"("organization_id", 'shift_schedules'::"text")))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND ("public"."fn_org_has_classes"("organization_id") OR "public"."fn_org_has_feature"("organization_id", 'shift_schedules'::"text"))));



ALTER TABLE "public"."shifts" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "shifts_delete" ON "public"."shifts" FOR DELETE USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'shift_schedules'::"text")));



CREATE POLICY "shifts_insert" ON "public"."shifts" FOR INSERT WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'shift_schedules'::"text")));



CREATE POLICY "shifts_select" ON "public"."shifts" FOR SELECT USING ("public"."fn_org_has_feature"("organization_id", 'shift_schedules'::"text"));



CREATE POLICY "shifts_update" ON "public"."shifts" FOR UPDATE USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'shift_schedules'::"text")));



ALTER TABLE "public"."student_guardians" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "student_guardians_select" ON "public"."student_guardians" FOR SELECT USING (("public"."is_org_operator_or_above"("organization_id") OR ("is_active" AND (EXISTS ( SELECT 1
   FROM "public"."school_guardians" "g"
  WHERE (("g"."id" = "student_guardians"."guardian_id") AND ("g"."user_id" = ( SELECT "auth"."uid"() AS "uid")) AND "g"."is_active"))))));



ALTER TABLE "public"."student_ride_notices" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "student_ride_notices_select_guardian" ON "public"."student_ride_notices" FOR SELECT TO "authenticated" USING ((EXISTS ( SELECT 1
   FROM ("public"."school_guardians" "g"
     JOIN "public"."student_guardians" "sg" ON ((("sg"."guardian_id" = "g"."id") AND "sg"."is_active")))
  WHERE (("g"."user_id" = "auth"."uid"()) AND "g"."is_active" AND ("sg"."student_id" = "student_ride_notices"."student_id")))));



CREATE POLICY "student_ride_notices_select_staff" ON "public"."student_ride_notices" FOR SELECT TO "authenticated" USING ("public"."is_org_operator_or_above"("organization_id"));



ALTER TABLE "public"."student_stop_assignments" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "student_stop_assignments_select_admin" ON "public"."student_stop_assignments" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



CREATE POLICY "student_stop_assignments_write_admin" ON "public"."student_stop_assignments" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



ALTER TABLE "public"."students" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "students_select_admin" ON "public"."students" FOR SELECT TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



CREATE POLICY "students_write_admin" ON "public"."students" TO "authenticated" USING (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text"))) WITH CHECK (("public"."is_org_operator_or_above"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'school'::"text")));



ALTER TABLE "public"."subscription_events" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."subscriptions" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "subscriptions_select_own" ON "public"."subscriptions" FOR SELECT USING (("auth"."uid"() = "user_id"));



ALTER TABLE "public"."trip_approvals" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "trip_approvals_select" ON "public"."trip_approvals" FOR SELECT TO "authenticated" USING (("public"."fn_org_has_feature"("organization_id", 'trip_approval'::"text") AND ("public"."is_org_operator_or_above"("organization_id") OR (EXISTS ( SELECT 1
   FROM "public"."sessions" "s"
  WHERE (("s"."id" = "trip_approvals"."session_id") AND ("s"."user_id" = "auth"."uid"())))))));



ALTER TABLE "public"."trip_classification_settings" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "trip_classification_settings_own" ON "public"."trip_classification_settings" TO "authenticated" USING ((( SELECT "auth"."uid"() AS "uid") = "user_id")) WITH CHECK ((( SELECT "auth"."uid"() AS "uid") = "user_id"));



ALTER TABLE "public"."trip_incidents" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "trip_incidents_insert_own" ON "public"."trip_incidents" FOR INSERT TO "authenticated" WITH CHECK ((("user_id" = "auth"."uid"()) AND "public"."is_org_member"("organization_id")));



CREATE POLICY "trip_incidents_select_admin" ON "public"."trip_incidents" FOR SELECT TO "authenticated" USING ("public"."is_org_admin_or_owner"("organization_id"));



CREATE POLICY "trip_incidents_select_own" ON "public"."trip_incidents" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."trip_vehicle_assignments" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "trip_vehicle_assignments_select_own" ON "public"."trip_vehicle_assignments" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."trucking_clients" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "trucking_clients_members" ON "public"."trucking_clients" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."organization_members" "m"
  WHERE (("m"."organization_id" = "trucking_clients"."organization_id") AND ("m"."user_id" = "auth"."uid"()) AND "m"."is_active"))));



ALTER TABLE "public"."user_onboarding" ENABLE ROW LEVEL SECURITY;


ALTER TABLE "public"."vehicle_geofence_alerts" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "vehicle_geofence_alerts_select" ON "public"."vehicle_geofence_alerts" FOR SELECT USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'geofences'::"text")));



ALTER TABLE "public"."vehicle_geofences" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "vehicle_geofences_delete" ON "public"."vehicle_geofences" FOR DELETE USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'geofences'::"text")));



CREATE POLICY "vehicle_geofences_insert" ON "public"."vehicle_geofences" FOR INSERT WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'geofences'::"text")));



CREATE POLICY "vehicle_geofences_select" ON "public"."vehicle_geofences" FOR SELECT USING ("public"."fn_org_has_feature"("organization_id", 'geofences'::"text"));



CREATE POLICY "vehicle_geofences_update" ON "public"."vehicle_geofences" FOR UPDATE USING (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'geofences'::"text"))) WITH CHECK (("public"."is_org_admin_or_owner"("organization_id") AND "public"."fn_org_has_feature"("organization_id", 'geofences'::"text")));



ALTER TABLE "public"."vehicle_inspections" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "vehicle_inspections_select_admin" ON "public"."vehicle_inspections" FOR SELECT TO "authenticated" USING ((("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id")));



CREATE POLICY "vehicle_inspections_select_assigned_vehicle_latest" ON "public"."vehicle_inspections" FOR SELECT TO "authenticated" USING ((("vehicle_id" IN ( SELECT "vehicles"."id"
   FROM "public"."vehicles"
  WHERE ("vehicles"."assigned_driver_id" = "auth"."uid"()))) AND ("id" = "public"."fn_latest_inspection_id"("vehicle_id"))));



CREATE POLICY "vehicle_inspections_select_own" ON "public"."vehicle_inspections" FOR SELECT TO "authenticated" USING (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."vehicle_maintenance_records" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "vehicle_maintenance_records_delete" ON "public"."vehicle_maintenance_records" FOR DELETE USING (("user_id" = "auth"."uid"()));



CREATE POLICY "vehicle_maintenance_records_insert" ON "public"."vehicle_maintenance_records" FOR INSERT WITH CHECK (("user_id" = "auth"."uid"()));



CREATE POLICY "vehicle_maintenance_records_select" ON "public"."vehicle_maintenance_records" FOR SELECT USING (("user_id" = "auth"."uid"()));



CREATE POLICY "vehicle_maintenance_records_select_org_admin" ON "public"."vehicle_maintenance_records" FOR SELECT USING ((("organization_id" IS NOT NULL) AND "public"."is_org_admin_or_owner"("organization_id")));



CREATE POLICY "vehicle_maintenance_records_update" ON "public"."vehicle_maintenance_records" FOR UPDATE USING (("user_id" = "auth"."uid"())) WITH CHECK (("user_id" = "auth"."uid"()));



ALTER TABLE "public"."vehicle_odometer_checkpoints" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "vehicle_odometer_checkpoints_select" ON "public"."vehicle_odometer_checkpoints" FOR SELECT USING ((EXISTS ( SELECT 1
   FROM "public"."vehicles" "v"
  WHERE (("v"."id" = "vehicle_odometer_checkpoints"."vehicle_id") AND (("v"."owner_user_id" = "auth"."uid"()) OR ("v"."assigned_driver_id" = "auth"."uid"()) OR (("v"."organization_id" IS NOT NULL) AND "public"."is_org_member"("v"."organization_id")))))));



ALTER TABLE "public"."vehicles" ENABLE ROW LEVEL SECURITY;


CREATE POLICY "vehicles_delete" ON "public"."vehicles" FOR DELETE TO "authenticated" USING ((("owner_user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_operator_or_above"("organization_id"))));



CREATE POLICY "vehicles_insert" ON "public"."vehicles" FOR INSERT TO "authenticated" WITH CHECK ((("owner_user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_operator_or_above"("organization_id"))));



CREATE POLICY "vehicles_select" ON "public"."vehicles" FOR SELECT TO "authenticated" USING ((("owner_user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_member"("organization_id"))));



CREATE POLICY "vehicles_update" ON "public"."vehicles" FOR UPDATE TO "authenticated" USING ((("owner_user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_operator_or_above"("organization_id")))) WITH CHECK ((("owner_user_id" = "auth"."uid"()) OR (("organization_id" IS NOT NULL) AND "public"."is_org_operator_or_above"("organization_id"))));





ALTER PUBLICATION "supabase_realtime" OWNER TO "postgres";






ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."fuel_anomalies";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."route_runs";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."route_stop_events";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."vehicle_geofence_alerts";



ALTER PUBLICATION "supabase_realtime" ADD TABLE ONLY "public"."vehicles";






GRANT USAGE ON SCHEMA "public" TO "postgres";
GRANT USAGE ON SCHEMA "public" TO "anon";
GRANT USAGE ON SCHEMA "public" TO "authenticated";
GRANT USAGE ON SCHEMA "public" TO "service_role";
GRANT USAGE ON SCHEMA "public" TO "supabase_auth_admin";







































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































REVOKE ALL ON FUNCTION "ops"."domain_violations"("p_full" boolean, "p_fn" "oid", "p_tg" "oid", "p_tbl" "oid") FROM PUBLIC;



REVOKE ALL ON FUNCTION "ops"."fn_domain_check_daily"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "ops"."fn_domain_guard"() FROM PUBLIC;



REVOKE ALL ON FUNCTION "public"."abort_shift_block_start"("p_block_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."abort_shift_block_start"("p_block_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."abort_shift_block_start"("p_block_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."accept_driver_invite"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."accept_driver_invite"("p_token" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."accept_driver_invite"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."accept_guardian_invite"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."accept_guardian_invite"("p_token" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."accept_guardian_invite"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."accept_legal_terms"("p_version" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."accept_legal_terms"("p_version" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."accept_legal_terms"("p_version" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."accept_my_pending_invite"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."accept_my_pending_invite"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."accept_my_pending_invite"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."apply_regular_trip_to_past"("p_rule_id" "uuid", "p_dry_run" boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."apply_regular_trip_to_past"("p_rule_id" "uuid", "p_dry_run" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."apply_regular_trip_to_past"("p_rule_id" "uuid", "p_dry_run" boolean) TO "service_role";



REVOKE ALL ON FUNCTION "public"."assign_trips_to_vehicle"("p_vehicle_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."assign_trips_to_vehicle"("p_vehicle_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."assign_trips_to_vehicle"("p_vehicle_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."assign_vehicle_to_driver"("p_vehicle_id" "uuid", "p_driver_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."assign_vehicle_to_driver"("p_vehicle_id" "uuid", "p_driver_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."assign_vehicle_to_driver"("p_vehicle_id" "uuid", "p_driver_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."cancel_student_no_ride"("p_student_id" "uuid", "p_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."cancel_student_no_ride"("p_student_id" "uuid", "p_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."cancel_student_no_ride"("p_student_id" "uuid", "p_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."check_active_org_membership"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."check_active_org_membership"("p_org_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_active_org_membership"("p_org_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."check_and_log_pdf_export"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."check_and_log_pdf_export"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."check_and_log_pdf_export"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."check_rate_limit"("p_fn_name" "text", "p_client_key" "text", "p_max_requests" integer, "p_window_seconds" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."check_rate_limit"("p_fn_name" "text", "p_client_key" "text", "p_max_requests" integer, "p_window_seconds" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."claim_driver_slot"("p_claim_code" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."claim_driver_slot"("p_claim_code" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."claim_driver_slot"("p_claim_code" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."close_abandoned_trips"("p_idle" interval) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."close_abandoned_trips"("p_idle" interval) TO "service_role";



REVOKE ALL ON FUNCTION "public"."close_my_workday"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."close_my_workday"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."close_my_workday"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."complete_route_run"("p_run_id" "uuid", "p_child_check" boolean, "p_latitude" double precision, "p_longitude" double precision) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."complete_route_run"("p_run_id" "uuid", "p_child_check" boolean, "p_latitude" double precision, "p_longitude" double precision) TO "authenticated";
GRANT ALL ON FUNCTION "public"."complete_route_run"("p_run_id" "uuid", "p_child_check" boolean, "p_latitude" double precision, "p_longitude" double precision) TO "service_role";



REVOKE ALL ON FUNCTION "public"."compute_idle_events"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."compute_idle_events"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."compute_idle_events"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."compute_ifta_vehicle_state_miles"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."compute_ifta_vehicle_state_miles"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."compute_ifta_vehicle_state_miles"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."compute_state_mileage"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."compute_state_mileage"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."compute_state_mileage"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."correct_fuel_purchase_ifta"("p_purchase_id" "uuid", "p_state_code" "text", "p_fuel_type" "text", "p_tax_paid" boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."correct_fuel_purchase_ifta"("p_purchase_id" "uuid", "p_state_code" "text", "p_fuel_type" "text", "p_tax_paid" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."correct_fuel_purchase_ifta"("p_purchase_id" "uuid", "p_state_code" "text", "p_fuel_type" "text", "p_tax_paid" boolean) TO "service_role";



REVOKE ALL ON FUNCTION "public"."create_driver_invite"("p_org_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_intended_role" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."create_driver_invite"("p_org_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_intended_role" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_driver_invite"("p_org_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_intended_role" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."create_driver_slot"("p_org_id" "uuid", "p_first_name" "text", "p_last_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."create_driver_slot"("p_org_id" "uuid", "p_first_name" "text", "p_last_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_driver_slot"("p_org_id" "uuid", "p_first_name" "text", "p_last_name" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."create_guardian_invite"("p_organization_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_student_ids" "uuid"[]) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."create_guardian_invite"("p_organization_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_student_ids" "uuid"[]) TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_guardian_invite"("p_organization_id" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_student_ids" "uuid"[]) TO "service_role";



REVOKE ALL ON FUNCTION "public"."create_organization"("p_name" "text", "p_industry_template" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."create_organization"("p_name" "text", "p_industry_template" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."create_organization"("p_name" "text", "p_industry_template" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."delete_organization"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."delete_organization"("p_org_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_organization"("p_org_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."delete_trip_section"("p_section_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."delete_trip_section"("p_section_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."delete_trip_section"("p_section_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."driver_safety_scores"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_bucket" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."driver_safety_scores"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_bucket" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."driver_safety_scores"("p_organization_id" "uuid", "p_start_date" "date", "p_end_date" "date", "p_bucket" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_clear_custom_domain"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_clear_custom_domain"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_clear_custom_domain"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_add_child"("p_session" "text", "p" "jsonb") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_add_child"("p_session" "text", "p" "jsonb") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_add_child"("p_session" "text", "p" "jsonb") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_add_child"("p_session" "text", "p" "jsonb") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_book"("p_session" "text", "p_student" "uuid", "p_date" "date", "p_start" time without time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_book"("p_session" "text", "p_student" "uuid", "p_date" "date", "p_start" time without time zone) TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_book"("p_session" "text", "p_student" "uuid", "p_date" "date", "p_start" time without time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_book"("p_session" "text", "p_student" "uuid", "p_date" "date", "p_start" time without time zone) TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_cancel"("p_session" "text", "p_student" "uuid", "p_block" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_cancel"("p_session" "text", "p_student" "uuid", "p_block" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_cancel"("p_session" "text", "p_student" "uuid", "p_block" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_cancel"("p_session" "text", "p_student" "uuid", "p_block" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_certificate"("p_session" "text", "p_student" "uuid", "p_number" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_certificate"("p_session" "text", "p_student" "uuid", "p_number" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_certificate"("p_session" "text", "p_student" "uuid", "p_number" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_certificate"("p_session" "text", "p_student" "uuid", "p_number" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_home"("p_session" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_home"("p_session" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_home"("p_session" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_home"("p_session" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_link"("p_student" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_relation" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_link"("p_student" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_relation" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_link"("p_student" "uuid", "p_email" "text", "p_first_name" "text", "p_last_name" "text", "p_relation" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_link_info"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_link_info"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_open_link"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_open_link"("p_token" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_open_link"("p_token" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_open_link"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_request_links"("p_email" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_request_links"("p_email" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_revoke"("p_client" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_revoke"("p_client" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_revoke"("p_client" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_set_sms"("p_session" "text", "p_student" "uuid", "p_on" boolean, "p_phone" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_set_sms"("p_session" "text", "p_student" "uuid", "p_on" boolean, "p_phone" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_set_sms"("p_session" "text", "p_student" "uuid", "p_on" boolean, "p_phone" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_set_sms"("p_session" "text", "p_student" "uuid", "p_on" boolean, "p_phone" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_sign_out"("p_session" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_sign_out"("p_session" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_sign_out"("p_session" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_sign_out"("p_session" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_slots"("p_session" "text", "p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_slots"("p_session" "text", "p_student" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_slots"("p_session" "text", "p_student" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_slots"("p_session" "text", "p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_student_view"("p_session" "text", "p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_student_view"("p_session" "text", "p_student" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_client_student_view"("p_session" "text", "p_student" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_student_view"("p_session" "text", "p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_unlink"("p_client" "uuid", "p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_unlink"("p_client" "uuid", "p_student" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_unlink"("p_client" "uuid", "p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_client_welcome_link"("p_client" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_client_welcome_link"("p_client" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_client_welcome_link"("p_client" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_create_portal_link"("p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_create_portal_link"("p_student" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_create_portal_link"("p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_due_class_reminders"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_due_class_reminders"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_due_slot_notices"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_due_slot_notices"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_enrollment_approve"("p_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_enrollment_approve"("p_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_enrollment_approve"("p_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_enrollment_decline"("p_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_enrollment_decline"("p_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_enrollment_decline"("p_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_enrollment_undo"("p_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_enrollment_undo"("p_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_enrollment_undo"("p_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_ensure_default_programs"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_ensure_default_programs"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_ensure_default_programs"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_ensure_default_skills"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_ensure_default_skills"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_ensure_default_skills"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_issue_certificate"("p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_issue_certificate"("p_student" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_issue_certificate"("p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_mark_custom_domain"("p_org" "uuid", "p_status" "text", "p_message" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_mark_custom_domain"("p_org" "uuid", "p_status" "text", "p_message" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_mark_custom_domain"("p_org" "uuid", "p_status" "text", "p_message" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_office_add_block"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_student" "uuid", "p_note" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_office_add_block"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_student" "uuid", "p_note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_office_add_block"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_student" "uuid", "p_note" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_office_move_block"("p_block" "uuid", "p_date" "date", "p_start" time without time zone, "p_driver" "uuid", "p_vehicle" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_office_move_block"("p_block" "uuid", "p_date" "date", "p_start" time without time zone, "p_driver" "uuid", "p_vehicle" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_office_move_block"("p_block" "uuid", "p_date" "date", "p_start" time without time zone, "p_driver" "uuid", "p_vehicle" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_portal_book"("p_token" "text", "p_date" "date", "p_start" time without time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_portal_book"("p_token" "text", "p_date" "date", "p_start" time without time zone) TO "anon";
GRANT ALL ON FUNCTION "public"."ds_portal_book"("p_token" "text", "p_date" "date", "p_start" time without time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_portal_book"("p_token" "text", "p_date" "date", "p_start" time without time zone) TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_portal_cancel"("p_token" "text", "p_block" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_portal_cancel"("p_token" "text", "p_block" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_portal_cancel"("p_token" "text", "p_block" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_portal_cancel"("p_token" "text", "p_block" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_portal_certificate"("p_token" "text", "p_number" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_portal_certificate"("p_token" "text", "p_number" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_portal_certificate"("p_token" "text", "p_number" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_portal_certificate"("p_token" "text", "p_number" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_portal_set_sms"("p_token" "text", "p_on" boolean, "p_phone" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_portal_set_sms"("p_token" "text", "p_on" boolean, "p_phone" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_portal_set_sms"("p_token" "text", "p_on" boolean, "p_phone" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_portal_set_sms"("p_token" "text", "p_on" boolean, "p_phone" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_portal_slots"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_portal_slots"("p_token" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_portal_slots"("p_token" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_portal_slots"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_portal_view"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_portal_view"("p_token" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_portal_view"("p_token" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_portal_view"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_public_enroll"("p_slug" "text", "p" "jsonb") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_public_enroll"("p_slug" "text", "p" "jsonb") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_public_origins"("p_slug" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_public_origins"("p_slug" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_public_origins"("p_slug" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_public_origins"("p_slug" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_public_page"("p_slug" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_public_page"("p_slug" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_public_page"("p_slug" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_public_page"("p_slug" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_public_slug_for_host"("p_host" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_public_slug_for_host"("p_host" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."ds_public_slug_for_host"("p_host" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_public_slug_for_host"("p_host" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_record_payment"("p_package" "uuid", "p_amount_cents" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_record_payment"("p_package" "uuid", "p_amount_cents" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_record_payment"("p_package" "uuid", "p_amount_cents" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_revoke_portal_link"("p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_revoke_portal_link"("p_student" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_revoke_portal_link"("p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_set_custom_domain"("p_org" "uuid", "p_domain" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_set_custom_domain"("p_org" "uuid", "p_domain" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_set_custom_domain"("p_org" "uuid", "p_domain" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_set_emancipation"("p_student" "uuid", "p_emancipated" boolean, "p_note" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_set_emancipation"("p_student" "uuid", "p_emancipated" boolean, "p_note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_set_emancipation"("p_student" "uuid", "p_emancipated" boolean, "p_note" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_student_classes"("p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_student_classes"("p_student" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_student_classes"("p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_student_progress"("p_org" "uuid", "p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_student_progress"("p_org" "uuid", "p_student" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_student_progress"("p_org" "uuid", "p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."ds_submit_evaluation"("p_block_id" "uuid", "p_scores" "jsonb", "p_note" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ds_submit_evaluation"("p_block_id" "uuid", "p_scores" "jsonb", "p_note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."ds_submit_evaluation"("p_block_id" "uuid", "p_scores" "jsonb", "p_note" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."end_shift_block"("p_block_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."end_shift_block"("p_block_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."end_shift_block"("p_block_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."enforce_fleet_org_membership"() TO "anon";
GRANT ALL ON FUNCTION "public"."enforce_fleet_org_membership"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."enforce_fleet_org_membership"() TO "service_role";
GRANT ALL ON FUNCTION "public"."enforce_fleet_org_membership"() TO "supabase_auth_admin";



REVOKE ALL ON FUNCTION "public"."expire_lapsed_play_subscriptions"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."expire_lapsed_play_subscriptions"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_assign_driver_slot_display_id"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_assign_driver_slot_display_id"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_assign_guardian_display_id"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_assign_guardian_display_id"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_assign_profile_display_id"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_assign_profile_display_id"() TO "service_role";
GRANT ALL ON FUNCTION "public"."fn_assign_profile_display_id"() TO "supabase_auth_admin";



REVOKE ALL ON FUNCTION "public"."fn_assign_vehicle_display_id"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_assign_vehicle_display_id"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_block_cross_app_open_trip"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_block_cross_app_open_trip"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_block_vehicle_switch_during_active_session"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_block_vehicle_switch_during_active_session"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_block_vehicle_switch_during_active_session"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_branches_plan_limit"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_branches_plan_limit"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_check_route_monitor"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_check_route_monitor"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_classify_section_on_close"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_classify_section_on_close"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_cm_distance_m"("lat1" double precision, "lng1" double precision, "lat2" double precision, "lng2" double precision) TO "anon";
GRANT ALL ON FUNCTION "public"."fn_cm_distance_m"("lat1" double precision, "lng1" double precision, "lat2" double precision, "lng2" double precision) TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_cm_distance_m"("lat1" double precision, "lng1" double precision, "lat2" double precision, "lng2" double precision) TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_delete_personal_rows_on_profile_delete"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_delete_personal_rows_on_profile_delete"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_discard_zero_mile_trip"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_discard_zero_mile_trip"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_display_id_blocked"("p_id" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_display_id_blocked"("p_id" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_drop_empty_switched_section"("p_section_id" "uuid", "p_into_section_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_drop_empty_switched_section"("p_section_id" "uuid", "p_into_section_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_drop_empty_switched_section"("p_section_id" "uuid", "p_into_section_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_balance"("p_student" "uuid", OUT "purchased" integer, OUT "used" integer, OUT "booked" integer, OUT "available" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_balance"("p_student" "uuid", OUT "purchased" integer, OUT "used" integer, OUT "booked" integer, OUT "available" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_block_student_same_org"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_block_student_same_org"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_ds_certificates_immutable"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_ds_certificates_immutable"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_ds_certificates_immutable"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_class_numbers"("p_block_id" "uuid", OUT "minutes" numeric, OUT "night_minutes" numeric, OUT "miles" numeric, OUT "started" timestamp with time zone, OUT "ended" timestamp with time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_class_numbers"("p_block_id" "uuid", OUT "minutes" numeric, OUT "night_minutes" numeric, OUT "miles" numeric, OUT "started" timestamp with time zone, OUT "ended" timestamp with time zone) TO "service_role";



GRANT ALL ON TABLE "public"."ds_clients" TO "anon";
GRANT ALL ON TABLE "public"."ds_clients" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_clients" TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_client_session"("p_session" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_client_session"("p_session" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_client_student"("p_session" "text", "p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_client_student"("p_session" "text", "p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_close_guardian_links"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_close_guardian_links"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_conflict"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_exclude" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_conflict"("p_org" "uuid", "p_driver" "uuid", "p_vehicle" "uuid", "p_date" "date", "p_start" time without time zone, "p_end" time without time zone, "p_exclude" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_free_slots"("p_org" "uuid", "p_minutes" integer, "p_from" "date", "p_days" integer, "p_lead_hours" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_free_slots"("p_org" "uuid", "p_minutes" integer, "p_from" "date", "p_days" integer, "p_lead_hours" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_is_minor"("p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_is_minor"("p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_link_client"("p_client" "uuid", "p_student" "uuid", "p_relation" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_link_client"("p_client" "uuid", "p_student" "uuid", "p_relation" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_link_counts"("p_relation" "text", "p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_link_counts"("p_relation" "text", "p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_portal_book_for"("p_student" "uuid", "p_date" "date", "p_start" time without time zone) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_portal_book_for"("p_student" "uuid", "p_date" "date", "p_start" time without time zone) TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_portal_cancel_for"("p_student" "uuid", "p_block" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_portal_cancel_for"("p_student" "uuid", "p_block" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_portal_certificate_for"("p_student" "uuid", "p_number" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_portal_certificate_for"("p_student" "uuid", "p_number" "text") TO "service_role";



GRANT ALL ON TABLE "public"."ds_portal_links" TO "anon";
GRANT ALL ON TABLE "public"."ds_portal_links" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_portal_links" TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_portal_link"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_portal_link"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_portal_payload"("p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_portal_payload"("p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_portal_set_sms_for"("p_student" "uuid", "p_on" boolean, "p_phone" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_portal_set_sms_for"("p_student" "uuid", "p_on" boolean, "p_phone" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_portal_slots_for"("p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_portal_slots_for"("p_student" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_purge_client_tokens"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_purge_client_tokens"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_purge_enrollment_requests"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_purge_enrollment_requests"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_slot_grid"("p_org" "uuid", "p_minutes" integer, "p_from" "date", "p_days" integer, "p_lead_hours" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_slot_grid"("p_org" "uuid", "p_minutes" integer, "p_from" "date", "p_days" integer, "p_lead_hours" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_student_program_same_org"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_student_program_same_org"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_student_snapshot"("p_student" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_student_snapshot"("p_student" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_ds_touch"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_ds_touch"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_ds_touch"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ds_upsert_client"("p_org" "uuid", "p_email" "text", "p_first" "text", "p_last" "text", "p_reactivate" boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ds_upsert_client"("p_org" "uuid", "p_email" "text", "p_first" "text", "p_last" "text", "p_reactivate" boolean) TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_enforce_active_org_membership"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_enforce_active_org_membership"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_enforce_odometer_cycle_tier"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_enforce_odometer_cycle_tier"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_enforce_org_feature_switches"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_enforce_org_feature_switches"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_enforce_trial_or_subscription"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_enforce_trial_or_subscription"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_enforce_vehicle_assignment_mode_tier"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_enforce_vehicle_assignment_mode_tier"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_enforce_vehicle_count_limit"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_enforce_vehicle_count_limit"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_enforce_vehicle_odometer_floor"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_enforce_vehicle_odometer_floor"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_enforce_vehicle_odometer_floor"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_evaluate_fuel_purchase"("p_purchase_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_evaluate_fuel_purchase"("p_purchase_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_fold_empty_trip_sections"("p_session_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_fold_empty_trip_sections"("p_session_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_freeze_closed_route"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_freeze_closed_route"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_freeze_closed_route"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_freeze_closed_session"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_freeze_closed_session"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_freeze_closed_session"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_freeze_closed_session_section"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_freeze_closed_session_section"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_freeze_closed_session_section"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_freeze_profile_display_id"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_freeze_profile_display_id"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_freeze_profile_display_id"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_freeze_started_shift_block"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_freeze_started_shift_block"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_freeze_started_shift_block"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_freeze_vehicle_display_id"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_freeze_vehicle_display_id"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_freeze_vehicle_display_id"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_fuel_purchase_evaluate_trigger"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_fuel_purchase_evaluate_trigger"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_guard_maintenance_tenant"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_guard_maintenance_tenant"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_guard_org_billing_columns"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_guard_org_billing_columns"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_guard_org_billing_columns"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_guard_profile_protected_columns"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_guard_profile_protected_columns"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_guard_profile_protected_columns"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_guard_session_tenant"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_guard_session_tenant"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_inherit_session_tenant"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_inherit_session_tenant"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_invite_unconfirmed_user"("p_email" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_invite_unconfirmed_user"("p_email" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_is_org_creator"("p_organization_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_is_org_creator"("p_organization_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_is_org_creator"("p_organization_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_latest_inspection_id"("p_vehicle_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_latest_inspection_id"("p_vehicle_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_latest_inspection_id"("p_vehicle_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_link_session_to_shift_block"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_link_session_to_shift_block"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_meters_between"("lat1" double precision, "lon1" double precision, "lat2" double precision, "lon2" double precision) TO "anon";
GRANT ALL ON FUNCTION "public"."fn_meters_between"("lat1" double precision, "lon1" double precision, "lat2" double precision, "lon2" double precision) TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_meters_between"("lat1" double precision, "lon1" double precision, "lat2" double precision, "lon2" double precision) TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."route_runs" TO "authenticated";
GRANT ALL ON TABLE "public"."route_runs" TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_my_crew_run"("p_run_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_my_crew_run"("p_run_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_my_open_run"("p_run_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_my_open_run"("p_run_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_notify_trip_safety"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_notify_trip_safety"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_odometer_cycle_start"("p_vehicle_id" "uuid", "p_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_odometer_cycle_start"("p_vehicle_id" "uuid", "p_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_odometer_cycle_start"("p_vehicle_id" "uuid", "p_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_odometer_period_start"("p_cycle" "text", "p_date" "date", "p_anchor" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_odometer_period_start"("p_cycle" "text", "p_date" "date", "p_anchor" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_odometer_period_start"("p_cycle" "text", "p_date" "date", "p_anchor" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_billable_vehicles"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_billable_vehicles"("p_org_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_branch_allowance"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_branch_allowance"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_org_branch_allowance"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_branch_allowance_internal"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_branch_allowance_internal"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_driving_school_cycle"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_driving_school_cycle"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_effective_tier"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_effective_tier"("p_org_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_org_effective_tier"("p_org_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_enterprise_internal"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_enterprise_internal"("p_org_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_feature_internal"("p_org_id" "uuid", "p_feature" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_feature_internal"("p_org_id" "uuid", "p_feature" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_feature_list_internal"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_feature_list_internal"("p_org_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_features"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_features"("p_org_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_org_features"("p_org_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_fleet_template_to_vehicles"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_fleet_template_to_vehicles"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_has_classes"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_has_classes"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_org_has_classes"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_has_feature"("p_org_id" "uuid", "p_feature" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_has_feature"("p_org_id" "uuid", "p_feature" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_org_has_feature"("p_org_id" "uuid", "p_feature" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_local_today"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_local_today"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_org_local_today"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_org_tier_internal"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_org_tier_internal"("p_org_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_org_today"("p_org" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."fn_org_today"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_org_today"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_plan_features"("p_template" "text", "p_plan_rank" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_plan_features"("p_template" "text", "p_plan_rank" integer) TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_profile_requires_pretrip"("p" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."fn_profile_requires_pretrip"("p" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_profile_requires_pretrip"("p" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_reevaluate_recent_fuel_purchases"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_reevaluate_recent_fuel_purchases"() TO "service_role";



GRANT ALL ON TABLE "public"."regular_trips" TO "authenticated";
GRANT ALL ON TABLE "public"."regular_trips" TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_regular_trip_covers"("r" "public"."regular_trips", "start_lat" double precision, "start_lng" double precision, "end_lat" double precision, "end_lng" double precision) TO "anon";
GRANT ALL ON FUNCTION "public"."fn_regular_trip_covers"("r" "public"."regular_trips", "start_lat" double precision, "start_lng" double precision, "end_lat" double precision, "end_lng" double precision) TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_regular_trip_covers"("r" "public"."regular_trips", "start_lat" double precision, "start_lng" double precision, "end_lat" double precision, "end_lng" double precision) TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_require_org_feature"("p_org_id" "uuid", "p_feature" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_require_org_feature"("p_org_id" "uuid", "p_feature" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_require_org_feature"("p_org_id" "uuid", "p_feature" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_retire_display_id"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_retire_display_id"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ride_notice_applies"("p_student_id" "uuid", "p_date" "date", "p_route_type" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ride_notice_applies"("p_student_id" "uuid", "p_date" "date", "p_route_type" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_ride_notice_role"("p_student_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_ride_notice_role"("p_student_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_rider_status"("p_route_id" "uuid", "p_run_id" "uuid", "p_stop_id" "uuid", "p_student" "uuid", "p_action" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_rider_status"("p_route_id" "uuid", "p_run_id" "uuid", "p_stop_id" "uuid", "p_student" "uuid", "p_action" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_rode_am_today"("p_org" "uuid", "p_student" "uuid", "p_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_rode_am_today"("p_org" "uuid", "p_student" "uuid", "p_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_route_crew"("p_route_id" "uuid", "p_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_route_crew"("p_route_id" "uuid", "p_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_route_feature_ok"("p_org_id" "uuid", "p_route_type" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_route_feature_ok"("p_org_id" "uuid", "p_route_type" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_route_feature_ok"("p_org_id" "uuid", "p_route_type" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_route_run_mark_current_stops"("p_run_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_route_run_mark_current_stops"("p_run_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_route_run_set_monitor"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_route_run_set_monitor"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_route_run_track_stops"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_route_run_track_stops"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_safety_score"("p_points" numeric, "p_miles" numeric) TO "anon";
GRANT ALL ON FUNCTION "public"."fn_safety_score"("p_points" numeric, "p_miles" numeric) TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_safety_score"("p_points" numeric, "p_miles" numeric) TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_school_same_org"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_school_same_org"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_school_same_org"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_send_safety_summaries"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_send_safety_summaries"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_session_miles_from_sections"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_session_miles_from_sections"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_session_miles_from_sections"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_set_vehicle_service"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_set_vehicle_service"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_stop_due"("p_run_id" "uuid", "p_stop_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_stop_due"("p_run_id" "uuid", "p_stop_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_sun_times"("p_lat" double precision, "p_lng" double precision, "p_at" timestamp with time zone, OUT "sunrise" timestamp with time zone, OUT "sunset" timestamp with time zone) TO "anon";
GRANT ALL ON FUNCTION "public"."fn_sun_times"("p_lat" double precision, "p_lng" double precision, "p_at" timestamp with time zone, OUT "sunrise" timestamp with time zone, OUT "sunset" timestamp with time zone) TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_sun_times"("p_lat" double precision, "p_lng" double precision, "p_at" timestamp with time zone, OUT "sunrise" timestamp with time zone, OUT "sunset" timestamp with time zone) TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_sync_driving_school_client"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_sync_driving_school_client"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_sync_general_business_client"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_sync_general_business_client"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_sync_gig_client"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_sync_gig_client"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_sync_org_service"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_sync_org_service"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_sync_sales_client"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_sync_sales_client"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_sync_school_bus_client"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_sync_school_bus_client"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_sync_trucking_client"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_sync_trucking_client"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_touch_updated_at"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_touch_updated_at"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_touch_updated_at"() TO "service_role";
GRANT ALL ON FUNCTION "public"."fn_touch_updated_at"() TO "supabase_auth_admin";



GRANT ALL ON FUNCTION "public"."fn_valid_fleet_profile"("p" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."fn_valid_fleet_profile"("p" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_valid_fleet_profile"("p" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_valid_origins"("p" "text"[]) TO "anon";
GRANT ALL ON FUNCTION "public"."fn_valid_origins"("p" "text"[]) TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_valid_origins"("p" "text"[]) TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_validate_org_timezone"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_validate_org_timezone"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_validate_org_timezone"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_vehicle_active_trip"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_vehicle_active_trip"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_vehicles_driving_school_cycle"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_vehicles_driving_school_cycle"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_vehicles_fleet_template"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_vehicles_fleet_template"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."fn_vehicles_plan_limit"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."fn_vehicles_plan_limit"() TO "service_role";



GRANT ALL ON FUNCTION "public"."fn_vehicles_set_cycle_anchor"() TO "anon";
GRANT ALL ON FUNCTION "public"."fn_vehicles_set_cycle_anchor"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."fn_vehicles_set_cycle_anchor"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."generate_report_access_code"("p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid", "p_weekly_checkpoints" "jsonb", "p_target_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."generate_report_access_code"("p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid", "p_weekly_checkpoints" "jsonb", "p_target_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."generate_report_access_code"("p_start_date" "date", "p_end_date" "date", "p_vehicle_id" "uuid", "p_weekly_checkpoints" "jsonb", "p_target_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_fleet_export_data"("p_org_id" "uuid", "p_start_date" "date", "p_end_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_fleet_export_data"("p_org_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_fleet_export_data"("p_org_id" "uuid", "p_start_date" "date", "p_end_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_my_shift_day"("p_org" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_my_shift_day"("p_org" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_my_shift_day"("p_org" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_my_upcoming_classes"("p_org" "uuid", "p_days" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_my_upcoming_classes"("p_org" "uuid", "p_days" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_my_upcoming_classes"("p_org" "uuid", "p_days" integer) TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."shift_blocks" TO "anon";
GRANT ALL ON TABLE "public"."shift_blocks" TO "authenticated";
GRANT ALL ON TABLE "public"."shift_blocks" TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_org_shift_day"("p_org" "uuid", "p_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_org_shift_day"("p_org" "uuid", "p_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_org_shift_day"("p_org" "uuid", "p_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_org_shift_range"("p_org" "uuid", "p_from" "date", "p_days" integer) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_org_shift_range"("p_org" "uuid", "p_from" "date", "p_days" integer) TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_org_shift_range"("p_org" "uuid", "p_from" "date", "p_days" integer) TO "service_role";



REVOKE ALL ON FUNCTION "public"."get_trip_map"("p_session_id" "uuid", "p_token" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."get_trip_map"("p_session_id" "uuid", "p_token" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."get_trip_map"("p_session_id" "uuid", "p_token" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."get_trip_map"("p_session_id" "uuid", "p_token" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."guardian_login_user"("p_display_id" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."guardian_login_user"("p_display_id" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."handle_new_user"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."handle_new_user"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."ifta_state_at_point"("p_lat" double precision, "p_lng" double precision) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."ifta_state_at_point"("p_lat" double precision, "p_lng" double precision) TO "authenticated";
GRANT ALL ON FUNCTION "public"."ifta_state_at_point"("p_lat" double precision, "p_lng" double precision) TO "service_role";



REVOKE ALL ON FUNCTION "public"."invite_member_by_email"("p_org_id" "uuid", "p_email" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."invite_member_by_email"("p_org_id" "uuid", "p_email" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."invite_member_by_email"("p_org_id" "uuid", "p_email" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_org_admin_or_owner"("p_organization_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_org_admin_or_owner"("p_organization_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_org_admin_or_owner"("p_organization_id" "uuid") TO "service_role";
GRANT ALL ON FUNCTION "public"."is_org_admin_or_owner"("p_organization_id" "uuid") TO "supabase_auth_admin";



GRANT ALL ON FUNCTION "public"."is_org_member"("p_organization_id" "uuid", "p_required_role" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."is_org_member"("p_organization_id" "uuid", "p_required_role" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_org_member"("p_organization_id" "uuid", "p_required_role" "text") TO "service_role";
GRANT ALL ON FUNCTION "public"."is_org_member"("p_organization_id" "uuid", "p_required_role" "text") TO "supabase_auth_admin";



GRANT ALL ON FUNCTION "public"."is_org_operator_or_above"("p_organization_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_org_operator_or_above"("p_organization_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_org_operator_or_above"("p_organization_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."is_org_owner"("p_organization_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."is_org_owner"("p_organization_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."is_org_owner"("p_organization_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."mark_driver_notifications_read"("p_ids" "uuid"[]) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."mark_driver_notifications_read"("p_ids" "uuid"[]) TO "authenticated";
GRANT ALL ON FUNCTION "public"."mark_driver_notifications_read"("p_ids" "uuid"[]) TO "service_role";



REVOKE ALL ON FUNCTION "public"."mark_stop_arrived"("p_run_id" "uuid", "p_stop_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."mark_stop_arrived"("p_run_id" "uuid", "p_stop_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."mark_stop_arrived"("p_run_id" "uuid", "p_stop_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."materialize_shift_blocks"("p_org" "uuid", "p_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."materialize_shift_blocks"("p_org" "uuid", "p_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."materialize_shift_blocks"("p_org" "uuid", "p_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."move_to_branch"("p_organization_id" "uuid", "p_subject_type" "text", "p_subject_id" "uuid", "p_to_branch" "uuid", "p_any" boolean, "p_note" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."move_to_branch"("p_organization_id" "uuid", "p_subject_type" "text", "p_subject_id" "uuid", "p_to_branch" "uuid", "p_any" boolean, "p_note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."move_to_branch"("p_organization_id" "uuid", "p_subject_type" "text", "p_subject_id" "uuid", "p_to_branch" "uuid", "p_any" boolean, "p_note" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."my_fleet_driver_id"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."my_fleet_driver_id"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."my_fleet_driver_id"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."my_guardian_children"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."my_guardian_children"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."my_guardian_children"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."my_pending_invite"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."my_pending_invite"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."my_pending_invite"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."my_school_routes_today"("p_organization_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."my_school_routes_today"("p_organization_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."my_school_routes_today"("p_organization_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."my_shift_today"("p_organization_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."my_shift_today"("p_organization_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."my_shift_today"("p_organization_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."public_pricing_catalog"() FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."public_pricing_catalog"() TO "anon";
GRANT ALL ON FUNCTION "public"."public_pricing_catalog"() TO "authenticated";
GRANT ALL ON FUNCTION "public"."public_pricing_catalog"() TO "service_role";



REVOKE ALL ON FUNCTION "public"."recompute_personal_entitlements"("p_user" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."recompute_personal_entitlements"("p_user" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."record_ridership"("p_run_id" "uuid", "p_stop_id" "uuid", "p_student_id" "uuid", "p_action" "text", "p_done" boolean, "p_reason" "text", "p_note" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."record_ridership"("p_run_id" "uuid", "p_stop_id" "uuid", "p_student_id" "uuid", "p_action" "text", "p_done" boolean, "p_reason" "text", "p_note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."record_ridership"("p_run_id" "uuid", "p_stop_id" "uuid", "p_student_id" "uuid", "p_action" "text", "p_done" boolean, "p_reason" "text", "p_note" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."redeem_report_access_code"("p_code" "text", "p_ip_hash" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."redeem_report_access_code"("p_code" "text", "p_ip_hash" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."redeem_report_access_code"("p_code" "text", "p_ip_hash" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."register_my_own_vehicle"("p_organization_id" "uuid", "p_make" "text", "p_model" "text", "p_year" integer, "p_plate" "text", "p_vin" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."register_my_own_vehicle"("p_organization_id" "uuid", "p_make" "text", "p_model" "text", "p_year" integer, "p_plate" "text", "p_vin" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."register_my_own_vehicle"("p_organization_id" "uuid", "p_make" "text", "p_model" "text", "p_year" integer, "p_plate" "text", "p_vin" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."remove_driver_from_org"("p_org_id" "uuid", "p_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."remove_driver_from_org"("p_org_id" "uuid", "p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."remove_driver_from_org"("p_org_id" "uuid", "p_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."report_permission_status"("p_app_version" "text", "p_os_version" "text", "p_device_model" "text", "p_location_state" "text", "p_location_always" boolean, "p_notifications" boolean, "p_motion" boolean, "p_camera" boolean, "p_battery_unrestricted" boolean, "p_usage_access" boolean, "p_exact_alarm" boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."report_permission_status"("p_app_version" "text", "p_os_version" "text", "p_device_model" "text", "p_location_state" "text", "p_location_always" boolean, "p_notifications" boolean, "p_motion" boolean, "p_camera" boolean, "p_battery_unrestricted" boolean, "p_usage_access" boolean, "p_exact_alarm" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."report_permission_status"("p_app_version" "text", "p_os_version" "text", "p_device_model" "text", "p_location_state" "text", "p_location_always" boolean, "p_notifications" boolean, "p_motion" boolean, "p_camera" boolean, "p_battery_unrestricted" boolean, "p_usage_access" boolean, "p_exact_alarm" boolean) TO "service_role";



REVOKE ALL ON FUNCTION "public"."report_student_no_ride"("p_student_id" "uuid", "p_date" "date", "p_part" "text", "p_reason" "text", "p_will_attend" boolean, "p_note" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."report_student_no_ride"("p_student_id" "uuid", "p_date" "date", "p_part" "text", "p_reason" "text", "p_will_attend" boolean, "p_note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."report_student_no_ride"("p_student_id" "uuid", "p_date" "date", "p_part" "text", "p_reason" "text", "p_will_attend" boolean, "p_note" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."resolve_driver_invite"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."resolve_driver_invite"("p_token" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."resolve_driver_invite"("p_token" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."resolve_driver_invite"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."resolve_guardian_invite"("p_token" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."resolve_guardian_invite"("p_token" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."resolve_guardian_invite"("p_token" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."resolve_guardian_invite"("p_token" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."respond_to_invite"("p_membership_id" "uuid", "p_accept" boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."respond_to_invite"("p_membership_id" "uuid", "p_accept" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."respond_to_invite"("p_membership_id" "uuid", "p_accept" boolean) TO "service_role";



REVOKE ALL ON FUNCTION "public"."review_fuel_anomaly"("p_anomaly_id" "uuid", "p_status" "text", "p_note" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."review_fuel_anomaly"("p_anomaly_id" "uuid", "p_status" "text", "p_note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."review_fuel_anomaly"("p_anomaly_id" "uuid", "p_status" "text", "p_note" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."revoke_guardian"("p_guardian_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."revoke_guardian"("p_guardian_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."revoke_guardian"("p_guardian_id" "uuid") TO "service_role";



GRANT ALL ON FUNCTION "public"."service_for_industry"("p_industry" "text") TO "anon";
GRANT ALL ON FUNCTION "public"."service_for_industry"("p_industry" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."service_for_industry"("p_industry" "text") TO "service_role";



GRANT ALL ON FUNCTION "public"."set_active_vehicle"("p_vehicle_id" "uuid") TO "anon";
GRANT ALL ON FUNCTION "public"."set_active_vehicle"("p_vehicle_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_active_vehicle"("p_vehicle_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_branch_manager"("p_branch_id" "uuid", "p_user_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_branch_manager"("p_branch_id" "uuid", "p_user_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_branch_manager"("p_branch_id" "uuid", "p_user_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_member_admin"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_admin" boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_member_admin"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_admin" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_member_admin"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_admin" boolean) TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_member_branch"("p_organization_id" "uuid", "p_user_id" "uuid", "p_branch_id" "uuid", "p_any_branch" boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_member_branch"("p_organization_id" "uuid", "p_user_id" "uuid", "p_branch_id" "uuid", "p_any_branch" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_member_branch"("p_organization_id" "uuid", "p_user_id" "uuid", "p_branch_id" "uuid", "p_any_branch" boolean) TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_member_languages"("p_organization_id" "uuid", "p_user_id" "uuid", "p_languages" "text"[]) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_member_languages"("p_organization_id" "uuid", "p_user_id" "uuid", "p_languages" "text"[]) TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_member_languages"("p_organization_id" "uuid", "p_user_id" "uuid", "p_languages" "text"[]) TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_member_operator"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_operator" boolean) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_member_operator"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_operator" boolean) TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_member_operator"("p_org_id" "uuid", "p_user_id" "uuid", "p_make_operator" boolean) TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_report_branding"("p_organization_id" "uuid", "p_display_name" "text", "p_logo_path" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_report_branding"("p_organization_id" "uuid", "p_display_name" "text", "p_logo_path" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_report_branding"("p_organization_id" "uuid", "p_display_name" "text", "p_logo_path" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_trip_approval"("p_session_id" "uuid", "p_status" "text", "p_note" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_trip_approval"("p_session_id" "uuid", "p_status" "text", "p_note" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_trip_approval"("p_session_id" "uuid", "p_status" "text", "p_note" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_vehicle_branch"("p_vehicle_id" "uuid", "p_branch_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_vehicle_branch"("p_vehicle_id" "uuid", "p_branch_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_vehicle_branch"("p_vehicle_id" "uuid", "p_branch_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_vehicle_ifta"("p_vehicle_id" "uuid", "p_qualified" boolean, "p_fuel_type" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_vehicle_ifta"("p_vehicle_id" "uuid", "p_qualified" boolean, "p_fuel_type" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_vehicle_ifta"("p_vehicle_id" "uuid", "p_qualified" boolean, "p_fuel_type" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."set_vehicle_tank_capacity"("p_vehicle_id" "uuid", "p_gallons" numeric) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."set_vehicle_tank_capacity"("p_vehicle_id" "uuid", "p_gallons" numeric) TO "authenticated";
GRANT ALL ON FUNCTION "public"."set_vehicle_tank_capacity"("p_vehicle_id" "uuid", "p_gallons" numeric) TO "service_role";



REVOKE ALL ON FUNCTION "public"."start_route_run"("p_route_id" "uuid", "p_session_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."start_route_run"("p_route_id" "uuid", "p_session_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."start_route_run"("p_route_id" "uuid", "p_session_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."start_shift_block"("p_block_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."start_shift_block"("p_block_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."start_shift_block"("p_block_id" "uuid") TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."fuel_purchases" TO "anon";
GRANT ALL ON TABLE "public"."fuel_purchases" TO "authenticated";
GRANT ALL ON TABLE "public"."fuel_purchases" TO "service_role";



REVOKE ALL ON FUNCTION "public"."submit_fuel_purchase"("p_vehicle_id" "uuid", "p_purchase_date" "date", "p_gallons" numeric, "p_state_code" "text", "p_price_per_gallon_usd" numeric, "p_total_cost_usd" numeric, "p_fuel_type" "text", "p_receipt_image_url" "text", "p_file_hash" "text", "p_ocr_source" boolean, "p_ocr_confidence" numeric, "p_vendor_name" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."submit_fuel_purchase"("p_vehicle_id" "uuid", "p_purchase_date" "date", "p_gallons" numeric, "p_state_code" "text", "p_price_per_gallon_usd" numeric, "p_total_cost_usd" numeric, "p_fuel_type" "text", "p_receipt_image_url" "text", "p_file_hash" "text", "p_ocr_source" boolean, "p_ocr_confidence" numeric, "p_vendor_name" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."submit_fuel_purchase"("p_vehicle_id" "uuid", "p_purchase_date" "date", "p_gallons" numeric, "p_state_code" "text", "p_price_per_gallon_usd" numeric, "p_total_cost_usd" numeric, "p_fuel_type" "text", "p_receipt_image_url" "text", "p_file_hash" "text", "p_ocr_source" boolean, "p_ocr_confidence" numeric, "p_vendor_name" "text") TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."vehicle_inspections" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_inspections" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_inspections" TO "service_role";



REVOKE ALL ON FUNCTION "public"."submit_vehicle_inspection"("p_vehicle_id" "uuid", "p_inspection_type" "text", "p_items" "jsonb", "p_odometer" numeric) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."submit_vehicle_inspection"("p_vehicle_id" "uuid", "p_inspection_type" "text", "p_items" "jsonb", "p_odometer" numeric) TO "authenticated";
GRANT ALL ON FUNCTION "public"."submit_vehicle_inspection"("p_vehicle_id" "uuid", "p_inspection_type" "text", "p_items" "jsonb", "p_odometer" numeric) TO "service_role";



GRANT ALL ON TABLE "public"."vehicle_odometer_checkpoints" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_odometer_checkpoints" TO "service_role";



REVOKE ALL ON FUNCTION "public"."submit_vehicle_odometer_checkpoint"("p_vehicle_id" "uuid", "p_odometer_value" numeric, "p_odometer_image_url" "text", "p_file_hash" "text", "p_ocr_source" boolean, "p_ocr_confidence" numeric, "p_capture_date" "date") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."submit_vehicle_odometer_checkpoint"("p_vehicle_id" "uuid", "p_odometer_value" numeric, "p_odometer_image_url" "text", "p_file_hash" "text", "p_ocr_source" boolean, "p_ocr_confidence" numeric, "p_capture_date" "date") TO "authenticated";
GRANT ALL ON FUNCTION "public"."submit_vehicle_odometer_checkpoint"("p_vehicle_id" "uuid", "p_odometer_value" numeric, "p_odometer_image_url" "text", "p_file_hash" "text", "p_ocr_source" boolean, "p_ocr_confidence" numeric, "p_capture_date" "date") TO "service_role";



REVOKE ALL ON FUNCTION "public"."suggest_regular_trip"("p_section_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."suggest_regular_trip"("p_section_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."suggest_regular_trip"("p_section_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."support_change_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text", "p_reason" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."support_change_fleet_type"("p_organization_id" "uuid", "p_industry_template" "text", "p_reason" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."switch_account_mode"("p_mode" "text") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."switch_account_mode"("p_mode" "text") TO "authenticated";
GRANT ALL ON FUNCTION "public"."switch_account_mode"("p_mode" "text") TO "service_role";



REVOKE ALL ON FUNCTION "public"."switch_default_organization"("p_org_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."switch_default_organization"("p_org_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."switch_default_organization"("p_org_id" "uuid") TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."session_sections" TO "anon";
GRANT ALL ON TABLE "public"."session_sections" TO "authenticated";
GRANT ALL ON TABLE "public"."session_sections" TO "service_role";
GRANT ALL ON TABLE "public"."session_sections" TO "supabase_auth_admin";



GRANT ALL ON FUNCTION "public"."switch_gig_app_section"("p_session_id" "uuid", "p_old_section_id" "uuid", "p_new_section_id" "uuid", "p_new_gig_app" "text", "p_new_irs_purpose" "text", "p_old_total_miles" double precision, "p_old_total_duration_seconds" integer, "p_old_end_latitude" double precision, "p_old_end_longitude" double precision) TO "anon";
GRANT ALL ON FUNCTION "public"."switch_gig_app_section"("p_session_id" "uuid", "p_old_section_id" "uuid", "p_new_section_id" "uuid", "p_new_gig_app" "text", "p_new_irs_purpose" "text", "p_old_total_miles" double precision, "p_old_total_duration_seconds" integer, "p_old_end_latitude" double precision, "p_old_end_longitude" double precision) TO "authenticated";
GRANT ALL ON FUNCTION "public"."switch_gig_app_section"("p_session_id" "uuid", "p_old_section_id" "uuid", "p_new_section_id" "uuid", "p_new_gig_app" "text", "p_new_irs_purpose" "text", "p_old_total_miles" double precision, "p_old_total_duration_seconds" integer, "p_old_end_latitude" double precision, "p_old_end_longitude" double precision) TO "service_role";



REVOKE ALL ON FUNCTION "public"."unlink_guardian_student"("p_guardian_id" "uuid", "p_student_id" "uuid") FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."unlink_guardian_student"("p_guardian_id" "uuid", "p_student_id" "uuid") TO "authenticated";
GRANT ALL ON FUNCTION "public"."unlink_guardian_student"("p_guardian_id" "uuid", "p_student_id" "uuid") TO "service_role";



REVOKE ALL ON FUNCTION "public"."update_vehicle_location"("p_vehicle_id" "uuid", "p_latitude" double precision, "p_longitude" double precision, "p_speed" double precision) FROM PUBLIC;
GRANT ALL ON FUNCTION "public"."update_vehicle_location"("p_vehicle_id" "uuid", "p_latitude" double precision, "p_longitude" double precision, "p_speed" double precision) TO "authenticated";
GRANT ALL ON FUNCTION "public"."update_vehicle_location"("p_vehicle_id" "uuid", "p_latitude" double precision, "p_longitude" double precision, "p_speed" double precision) TO "service_role";























































































GRANT ALL ON TABLE "public"."app_versions" TO "anon";
GRANT ALL ON TABLE "public"."app_versions" TO "authenticated";
GRANT ALL ON TABLE "public"."app_versions" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."audit_events" TO "anon";
GRANT ALL ON TABLE "public"."audit_events" TO "authenticated";
GRANT ALL ON TABLE "public"."audit_events" TO "service_role";
GRANT ALL ON TABLE "public"."audit_events" TO "supabase_auth_admin";



GRANT ALL ON TABLE "public"."auth_signup_errors" TO "service_role";



GRANT ALL ON TABLE "public"."branch_moves" TO "anon";
GRANT ALL ON TABLE "public"."branch_moves" TO "authenticated";
GRANT ALL ON TABLE "public"."branch_moves" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."branches" TO "anon";
GRANT ALL ON TABLE "public"."branches" TO "authenticated";
GRANT ALL ON TABLE "public"."branches" TO "service_role";



GRANT ALL ON TABLE "public"."device_permission_status" TO "service_role";
GRANT SELECT ON TABLE "public"."device_permission_status" TO "authenticated";



GRANT ALL ON TABLE "public"."diagnostic_logs" TO "anon";
GRANT ALL ON TABLE "public"."diagnostic_logs" TO "authenticated";
GRANT ALL ON TABLE "public"."diagnostic_logs" TO "service_role";



GRANT ALL ON TABLE "public"."driver_invites" TO "authenticated";
GRANT ALL ON TABLE "public"."driver_invites" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."driver_notifications" TO "anon";
GRANT ALL ON TABLE "public"."driver_notifications" TO "authenticated";
GRANT ALL ON TABLE "public"."driver_notifications" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."driver_safety_events" TO "anon";
GRANT ALL ON TABLE "public"."driver_safety_events" TO "authenticated";
GRANT ALL ON TABLE "public"."driver_safety_events" TO "service_role";



GRANT ALL ON TABLE "public"."driver_slot_claim_attempts" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."driver_workdays" TO "anon";
GRANT ALL ON TABLE "public"."driver_workdays" TO "authenticated";
GRANT ALL ON TABLE "public"."driver_workdays" TO "service_role";



GRANT ALL ON TABLE "public"."driving_school_clients" TO "anon";
GRANT ALL ON TABLE "public"."driving_school_clients" TO "authenticated";
GRANT ALL ON TABLE "public"."driving_school_clients" TO "service_role";



GRANT ALL ON TABLE "public"."ds_availability" TO "anon";
GRANT ALL ON TABLE "public"."ds_availability" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_availability" TO "service_role";



GRANT ALL ON TABLE "public"."ds_blocked_hours" TO "anon";
GRANT ALL ON TABLE "public"."ds_blocked_hours" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_blocked_hours" TO "service_role";



GRANT ALL ON TABLE "public"."ds_certificates" TO "anon";
GRANT ALL ON TABLE "public"."ds_certificates" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_certificates" TO "service_role";



GRANT ALL ON TABLE "public"."ds_client_students" TO "anon";
GRANT ALL ON TABLE "public"."ds_client_students" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_client_students" TO "service_role";



GRANT ALL ON TABLE "public"."ds_client_tokens" TO "anon";
GRANT ALL ON TABLE "public"."ds_client_tokens" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_client_tokens" TO "service_role";



GRANT ALL ON TABLE "public"."ds_enrollment_requests" TO "anon";
GRANT ALL ON TABLE "public"."ds_enrollment_requests" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_enrollment_requests" TO "service_role";



GRANT ALL ON TABLE "public"."ds_evaluation_scores" TO "anon";
GRANT ALL ON TABLE "public"."ds_evaluation_scores" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_evaluation_scores" TO "service_role";



GRANT ALL ON TABLE "public"."ds_evaluations" TO "anon";
GRANT ALL ON TABLE "public"."ds_evaluations" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_evaluations" TO "service_role";



GRANT ALL ON TABLE "public"."ds_packages" TO "anon";
GRANT ALL ON TABLE "public"."ds_packages" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_packages" TO "service_role";



GRANT ALL ON TABLE "public"."ds_programs" TO "anon";
GRANT ALL ON TABLE "public"."ds_programs" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_programs" TO "service_role";



GRANT ALL ON TABLE "public"."ds_public_pages" TO "anon";
GRANT SELECT,REFERENCES,DELETE,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."ds_public_pages" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_public_pages" TO "service_role";



GRANT INSERT("organization_id") ON TABLE "public"."ds_public_pages" TO "authenticated";



GRANT INSERT("slug"),UPDATE("slug") ON TABLE "public"."ds_public_pages" TO "authenticated";



GRANT INSERT("enabled"),UPDATE("enabled") ON TABLE "public"."ds_public_pages" TO "authenticated";



GRANT INSERT("intro"),UPDATE("intro") ON TABLE "public"."ds_public_pages" TO "authenticated";



GRANT INSERT("min_age"),UPDATE("min_age") ON TABLE "public"."ds_public_pages" TO "authenticated";



GRANT INSERT("terms_url"),UPDATE("terms_url") ON TABLE "public"."ds_public_pages" TO "authenticated";



GRANT INSERT("allowed_origins"),UPDATE("allowed_origins") ON TABLE "public"."ds_public_pages" TO "authenticated";



GRANT INSERT("updated_at"),UPDATE("updated_at") ON TABLE "public"."ds_public_pages" TO "authenticated";



GRANT ALL ON TABLE "public"."ds_reminders_sent" TO "anon";
GRANT ALL ON TABLE "public"."ds_reminders_sent" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_reminders_sent" TO "service_role";



GRANT ALL ON TABLE "public"."ds_settings" TO "anon";
GRANT ALL ON TABLE "public"."ds_settings" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_settings" TO "service_role";



GRANT ALL ON TABLE "public"."ds_skills" TO "anon";
GRANT ALL ON TABLE "public"."ds_skills" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_skills" TO "service_role";



GRANT ALL ON TABLE "public"."ds_slot_notices" TO "anon";
GRANT ALL ON TABLE "public"."ds_slot_notices" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_slot_notices" TO "service_role";



GRANT ALL ON TABLE "public"."ds_student_packages" TO "anon";
GRANT ALL ON TABLE "public"."ds_student_packages" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_student_packages" TO "service_role";



GRANT ALL ON TABLE "public"."ds_student_private" TO "anon";
GRANT ALL ON TABLE "public"."ds_student_private" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_student_private" TO "service_role";



GRANT ALL ON TABLE "public"."ds_students" TO "anon";
GRANT ALL ON TABLE "public"."ds_students" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_students" TO "service_role";



GRANT ALL ON TABLE "public"."ds_time_off" TO "anon";
GRANT ALL ON TABLE "public"."ds_time_off" TO "authenticated";
GRANT ALL ON TABLE "public"."ds_time_off" TO "service_role";



GRANT ALL ON TABLE "public"."edge_function_rate_limits" TO "service_role";



GRANT ALL ON SEQUENCE "public"."edge_function_rate_limits_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."edge_function_rate_limits_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."edge_function_rate_limits_id_seq" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."fleet_driver_slots" TO "anon";
GRANT ALL ON TABLE "public"."fleet_driver_slots" TO "authenticated";
GRANT ALL ON TABLE "public"."fleet_driver_slots" TO "service_role";



GRANT ALL ON TABLE "public"."fleet_plans" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."fleet_type_changes" TO "anon";
GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."fleet_type_changes" TO "authenticated";
GRANT ALL ON TABLE "public"."fleet_type_changes" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."fuel_anomalies" TO "anon";
GRANT ALL ON TABLE "public"."fuel_anomalies" TO "authenticated";
GRANT ALL ON TABLE "public"."fuel_anomalies" TO "service_role";



GRANT ALL ON TABLE "public"."general_business_clients" TO "anon";
GRANT ALL ON TABLE "public"."general_business_clients" TO "authenticated";
GRANT ALL ON TABLE "public"."general_business_clients" TO "service_role";



GRANT ALL ON TABLE "public"."geocode_cache" TO "authenticated";
GRANT ALL ON TABLE "public"."geocode_cache" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."gig_app_packages" TO "anon";
GRANT ALL ON TABLE "public"."gig_app_packages" TO "authenticated";
GRANT ALL ON TABLE "public"."gig_app_packages" TO "service_role";



GRANT ALL ON TABLE "public"."gig_app_suggestions" TO "anon";
GRANT ALL ON TABLE "public"."gig_app_suggestions" TO "authenticated";
GRANT ALL ON TABLE "public"."gig_app_suggestions" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."gig_apps" TO "anon";
GRANT ALL ON TABLE "public"."gig_apps" TO "authenticated";
GRANT ALL ON TABLE "public"."gig_apps" TO "service_role";
GRANT ALL ON TABLE "public"."gig_apps" TO "supabase_auth_admin";



GRANT ALL ON TABLE "public"."gig_clients" TO "anon";
GRANT ALL ON TABLE "public"."gig_clients" TO "authenticated";
GRANT ALL ON TABLE "public"."gig_clients" TO "service_role";



GRANT ALL ON TABLE "public"."guardian_invites" TO "anon";
GRANT ALL ON TABLE "public"."guardian_invites" TO "authenticated";
GRANT ALL ON TABLE "public"."guardian_invites" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."ifta_fuel_tax_rates" TO "anon";
GRANT ALL ON TABLE "public"."ifta_fuel_tax_rates" TO "authenticated";
GRANT ALL ON TABLE "public"."ifta_fuel_tax_rates" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."ifta_us_state_boundaries" TO "anon";
GRANT ALL ON TABLE "public"."ifta_us_state_boundaries" TO "authenticated";
GRANT ALL ON TABLE "public"."ifta_us_state_boundaries" TO "service_role";



GRANT ALL ON TABLE "public"."odometer_ocr_feedback" TO "anon";
GRANT ALL ON TABLE "public"."odometer_ocr_feedback" TO "authenticated";
GRANT ALL ON TABLE "public"."odometer_ocr_feedback" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."organization_members" TO "anon";
GRANT ALL ON TABLE "public"."organization_members" TO "authenticated";
GRANT ALL ON TABLE "public"."organization_members" TO "service_role";
GRANT ALL ON TABLE "public"."organization_members" TO "supabase_auth_admin";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."organizations" TO "anon";
GRANT ALL ON TABLE "public"."organizations" TO "authenticated";
GRANT ALL ON TABLE "public"."organizations" TO "service_role";
GRANT ALL ON TABLE "public"."organizations" TO "supabase_auth_admin";



GRANT ALL ON TABLE "public"."pdf_export_log" TO "authenticated";
GRANT ALL ON TABLE "public"."pdf_export_log" TO "service_role";



GRANT ALL ON TABLE "public"."plan_feature_rules" TO "service_role";



GRANT ALL ON SEQUENCE "public"."plan_feature_rules_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."plan_feature_rules_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."plan_feature_rules_id_seq" TO "service_role";



GRANT ALL ON TABLE "public"."platform_id_policy" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."play_subscriptions" TO "anon";
GRANT SELECT,REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."play_subscriptions" TO "authenticated";
GRANT ALL ON TABLE "public"."play_subscriptions" TO "service_role";



GRANT ALL ON SEQUENCE "public"."profile_display_id_seq" TO "anon";
GRANT ALL ON SEQUENCE "public"."profile_display_id_seq" TO "authenticated";
GRANT ALL ON SEQUENCE "public"."profile_display_id_seq" TO "service_role";
GRANT ALL ON SEQUENCE "public"."profile_display_id_seq" TO "supabase_auth_admin";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."profiles" TO "anon";
GRANT ALL ON TABLE "public"."profiles" TO "authenticated";
GRANT ALL ON TABLE "public"."profiles" TO "service_role";
GRANT ALL ON TABLE "public"."profiles" TO "supabase_auth_admin";



GRANT ALL ON TABLE "public"."report_access_attempts" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."reports" TO "anon";
GRANT SELECT,REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."reports" TO "authenticated";
GRANT ALL ON TABLE "public"."reports" TO "service_role";
GRANT ALL ON TABLE "public"."reports" TO "supabase_auth_admin";



GRANT ALL ON TABLE "public"."retired_display_ids" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."ridership_events" TO "authenticated";
GRANT ALL ON TABLE "public"."ridership_events" TO "service_role";



GRANT ALL ON TABLE "public"."route_crew_overrides" TO "anon";
GRANT ALL ON TABLE "public"."route_crew_overrides" TO "authenticated";
GRANT ALL ON TABLE "public"."route_crew_overrides" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."route_stop_events" TO "authenticated";
GRANT ALL ON TABLE "public"."route_stop_events" TO "service_role";



GRANT ALL ON TABLE "public"."route_stops" TO "authenticated";
GRANT ALL ON TABLE "public"."route_stops" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."routes" TO "anon";
GRANT ALL ON TABLE "public"."routes" TO "authenticated";
GRANT ALL ON TABLE "public"."routes" TO "service_role";



GRANT ALL ON TABLE "public"."sales_clients" TO "anon";
GRANT ALL ON TABLE "public"."sales_clients" TO "authenticated";
GRANT ALL ON TABLE "public"."sales_clients" TO "service_role";



GRANT ALL ON TABLE "public"."school_bus_clients" TO "anon";
GRANT ALL ON TABLE "public"."school_bus_clients" TO "authenticated";
GRANT ALL ON TABLE "public"."school_bus_clients" TO "service_role";



GRANT ALL ON TABLE "public"."school_guardians" TO "anon";
GRANT ALL ON TABLE "public"."school_guardians" TO "authenticated";
GRANT ALL ON TABLE "public"."school_guardians" TO "service_role";



GRANT ALL ON TABLE "public"."school_sites" TO "authenticated";
GRANT ALL ON TABLE "public"."school_sites" TO "service_role";



GRANT ALL ON TABLE "public"."service_license_fees" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."session_gps_breadcrumbs" TO "anon";
GRANT ALL ON TABLE "public"."session_gps_breadcrumbs" TO "authenticated";
GRANT ALL ON TABLE "public"."session_gps_breadcrumbs" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."sessions" TO "anon";
GRANT ALL ON TABLE "public"."sessions" TO "authenticated";
GRANT ALL ON TABLE "public"."sessions" TO "service_role";
GRANT ALL ON TABLE "public"."sessions" TO "supabase_auth_admin";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."shifts" TO "anon";
GRANT ALL ON TABLE "public"."shifts" TO "authenticated";
GRANT ALL ON TABLE "public"."shifts" TO "service_role";



GRANT ALL ON TABLE "public"."student_guardians" TO "anon";
GRANT ALL ON TABLE "public"."student_guardians" TO "authenticated";
GRANT ALL ON TABLE "public"."student_guardians" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."student_ride_notices" TO "authenticated";
GRANT ALL ON TABLE "public"."student_ride_notices" TO "service_role";



GRANT ALL ON TABLE "public"."student_stop_assignments" TO "authenticated";
GRANT ALL ON TABLE "public"."student_stop_assignments" TO "service_role";



GRANT ALL ON TABLE "public"."students" TO "authenticated";
GRANT ALL ON TABLE "public"."students" TO "service_role";



GRANT ALL ON TABLE "public"."subscription_events" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."subscriptions" TO "anon";
GRANT ALL ON TABLE "public"."subscriptions" TO "authenticated";
GRANT ALL ON TABLE "public"."subscriptions" TO "service_role";



GRANT ALL ON TABLE "public"."trip_approvals" TO "anon";
GRANT ALL ON TABLE "public"."trip_approvals" TO "authenticated";
GRANT ALL ON TABLE "public"."trip_approvals" TO "service_role";



GRANT ALL ON TABLE "public"."trip_classification_settings" TO "authenticated";
GRANT ALL ON TABLE "public"."trip_classification_settings" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."trip_incidents" TO "anon";
GRANT ALL ON TABLE "public"."trip_incidents" TO "authenticated";
GRANT ALL ON TABLE "public"."trip_incidents" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."trip_vehicle_assignments" TO "anon";
GRANT SELECT,REFERENCES,TRIGGER,TRUNCATE,MAINTAIN ON TABLE "public"."trip_vehicle_assignments" TO "authenticated";
GRANT ALL ON TABLE "public"."trip_vehicle_assignments" TO "service_role";



GRANT ALL ON TABLE "public"."trucking_clients" TO "anon";
GRANT ALL ON TABLE "public"."trucking_clients" TO "authenticated";
GRANT ALL ON TABLE "public"."trucking_clients" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."user_onboarding" TO "anon";
GRANT ALL ON TABLE "public"."user_onboarding" TO "authenticated";
GRANT ALL ON TABLE "public"."user_onboarding" TO "service_role";
GRANT ALL ON TABLE "public"."user_onboarding" TO "supabase_auth_admin";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."vehicle_geofence_alerts" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_geofence_alerts" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_geofence_alerts" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."vehicle_geofences" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_geofences" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_geofences" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."vehicle_maintenance_records" TO "anon";
GRANT ALL ON TABLE "public"."vehicle_maintenance_records" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicle_maintenance_records" TO "service_role";



GRANT SELECT,REFERENCES,TRIGGER,MAINTAIN ON TABLE "public"."vehicles" TO "anon";
GRANT ALL ON TABLE "public"."vehicles" TO "authenticated";
GRANT ALL ON TABLE "public"."vehicles" TO "service_role";
GRANT ALL ON TABLE "public"."vehicles" TO "supabase_auth_admin";









ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON SEQUENCES TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON FUNCTIONS TO "service_role";






ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "postgres";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "anon";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "authenticated";
ALTER DEFAULT PRIVILEGES FOR ROLE "postgres" IN SCHEMA "public" GRANT ALL ON TABLES TO "service_role";



































