-- v1 attempt still resolved the bare "organization_id" inside the subquery to the
-- subquery's own FROM alias (organization_members_1), not the outer row being
-- inserted — same shadowing mistake as the original bug, just re-created.
-- This time the outer reference is explicitly qualified with the real table name
-- so it can't be captured by the subquery's alias.

ALTER POLICY org_members_insert_admin ON public.organization_members
WITH CHECK (
  is_org_admin_or_owner(organization_id)
  OR NOT EXISTS (
    SELECT 1 FROM public.organization_members organization_members_1
    WHERE organization_members_1.organization_id = organization_members.organization_id
  )
);
