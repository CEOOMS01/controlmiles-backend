-- One-step invite (2026-10-27). The accept-invite-account edge function creates the invited
-- person's account already confirmed (the invite link was emailed only to that address, so
-- opening it is the confirmation; no second email). If an account with that email exists but
-- was NEVER confirmed (someone half-registered it, or registered it for another person), it is
-- removed first, so a squatter's password can never end up on the invited person's account.
-- A CONFIRMED account is never touched. Service role only.
-- (Applied to production 2026-10-27 as 'invite_unconfirmed_user_lookup'.)
create or replace function public.fn_invite_unconfirmed_user(p_email text)
returns table(user_id uuid, confirmed boolean)
language sql
stable
security definer
set search_path to 'public'
as $$
  select u.id, (u.email_confirmed_at is not null)
    from auth.users u
   where lower(u.email) = lower(coalesce(p_email, ''))
   limit 1;
$$;
revoke execute on function public.fn_invite_unconfirmed_user(text) from public, anon, authenticated;
