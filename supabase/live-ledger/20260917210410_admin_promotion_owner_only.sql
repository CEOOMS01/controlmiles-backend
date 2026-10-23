CREATE OR REPLACE FUNCTION public.is_org_owner(p_organization_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $function$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = p_organization_id
      AND user_id = auth.uid()
      AND is_active = true
      AND member_role = 'owner'
  );
$function$;

ALTER POLICY org_members_delete_admin_or_self
ON public.organization_members
USING (
  auth.uid() = user_id
  OR (public.is_org_admin_or_owner(organization_id) AND member_role <> 'owner')
  OR (public.is_org_operator_or_above(organization_id) AND member_role = 'driver')
);

ALTER POLICY org_members_update_admin
ON public.organization_members
USING (
  (public.is_org_admin_or_owner(organization_id) AND member_role <> 'owner')
  OR (public.is_org_operator_or_above(organization_id) AND member_role = 'driver')
)
WITH CHECK (
  public.is_org_owner(organization_id)
  OR (public.is_org_admin_or_owner(organization_id) AND member_role IN ('driver', 'operator'))
  OR (public.is_org_operator_or_above(organization_id) AND member_role = 'driver')
);

ALTER POLICY org_members_insert_admin
ON public.organization_members
WITH CHECK (
  public.is_org_owner(organization_id)
  OR (public.is_org_admin_or_owner(organization_id) AND member_role IN ('driver', 'operator'))
  OR (public.is_org_operator_or_above(organization_id) AND member_role = 'driver')
  OR (NOT EXISTS (
        SELECT 1 FROM public.organization_members om2
        WHERE om2.organization_id = organization_members.organization_id
      ))
);

CREATE OR REPLACE FUNCTION public.set_member_admin(
  p_org_id uuid,
  p_user_id uuid,
  p_make_admin boolean
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if not public.is_org_owner(p_org_id) then
    raise exception 'Only the organization owner can assign admins';
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
$function$;

REVOKE EXECUTE ON FUNCTION public.set_member_admin(uuid, uuid, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.set_member_admin(uuid, uuid, boolean) FROM anon;
GRANT EXECUTE ON FUNCTION public.set_member_admin(uuid, uuid, boolean) TO authenticated;
