-- Fleet: only the owner changes the branch of an admin or operator, or lets one move between branches
-- (2026-11-20, owner request). An admin the owner allowed on every branch may still move drivers and students
-- around, but cannot hand the all-branches permission to anyone.
do $$
declare d text; a text := 'if not public.is_org_admin_or_owner(p_organization_id) then raise exception ''Not authorized''; end if;';
begin
  select pg_get_functiondef('public.move_to_branch(uuid,text,uuid,uuid,boolean,text)'::regprocedure) into d;
  if position('Only the owner can change the branch of an admin or operator' in d) > 0 then return; end if;
  if position(a in d) = 0 then raise exception 'anchor not found'; end if;
  d := replace(d, a, a || E'\n  if p_subject_type = ''member'' and auth.uid() is not null and not public.is_org_owner(p_organization_id)\n     and (coalesce(p_any, false) or exists (select 1 from public.organization_members t where t.organization_id = p_organization_id\n            and t.user_id = p_subject_id and (t.member_role in (''admin'', ''operator'') or t.any_branch))) then\n    raise exception ''Only the owner can change the branch of an admin or operator'' using errcode = ''42501'';\n  end if;');
  execute d;
end $$;
