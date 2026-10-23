-- Web fleet-admin signup (2026-09-09): controlmiles.com's login page never
-- had a "create account" path -- only sign-in. Adding one means a brand-new
-- admin needs an organization created atomically with their account, but a
-- Supabase project may have email confirmation required, in which case
-- auth.signUp() returns no session yet and the client can't call the
-- existing create_organization() RPC (needs auth.uid()). The trigger fires
-- on the auth.users INSERT itself, before/regardless of email confirmation,
-- so folding org creation into handle_new_user via raw_user_meta_data
-- (which auth.signUp's options.data already populates -- this trigger
-- already reads first_name/last_name from the same place) works
-- unconditionally, matching create_organization()'s own atomic pattern
-- (organizations + organization_members + profiles + user_onboarding, one
-- transaction) without depending on session timing. Mobile's plain gig
-- signup never sends this metadata key, so its behavior is unchanged.

CREATE OR REPLACE FUNCTION public.handle_new_user()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
    INSERT INTO public.organizations (name, created_by)
    VALUES (v_org_name, NEW.id)
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
$function$;
