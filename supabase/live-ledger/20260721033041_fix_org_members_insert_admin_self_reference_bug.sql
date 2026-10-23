-- BUG: org_members_insert_admin compared organization_members_1.organization_id
-- to itself (always true if the table has ANY row anywhere), instead of comparing
-- it to the organization_id of the row being inserted. This meant only the very
-- FIRST organization ever created in the whole system could bootstrap its first
-- member; every organization created after that was permanently locked out.
--
-- Fix: subquery now checks whether THIS specific organization_id already has any
-- members. If not, the inserting user is allowed to become its first member.

ALTER POLICY org_members_insert_admin ON public.organization_members
WITH CHECK (
  is_org_admin_or_owner(organization_id)
  OR NOT EXISTS (
    SELECT 1 FROM public.organization_members organization_members_1
    WHERE organization_members_1.organization_id = organization_id
  )
);
