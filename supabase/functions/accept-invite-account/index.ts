// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/accept-invite-account/index.ts
//
// One-step invite (2026-10-27, owner's request: the invitation email and the email
// confirmation must be a single step). The invite link is emailed ONLY to the invited
// address, so someone who holds a valid, pending, unexpired invite token for that
// address controls that mailbox: opening the link and choosing a password is the
// confirmation. This creates that person's account already confirmed, so no second
// (Supabase) confirmation email is needed and the invite can be accepted right away.
//
// Guard rails:
//   * Only for a pending, unexpired invite; the email always comes from the invite row,
//     never from the request.
//   * A CONFIRMED account with that email is never touched (the person signs in with
//     their own password instead).
//   * An UNCONFIRMED account with that email (half-registered, or registered by someone
//     else) is removed first, so a squatter's password can never end up on the account.
//   * Rate limited per IP and per token; the same answer shape for every failure.
//
// No user JWT exists yet (they have no account), so verify_jwt is false; the invite
// token is the credential. The caller (the web invite page) then signs in with the
// password and calls accept_driver_invite.

import { createClient } from 'jsr:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const RATE_LIMIT_MAX = 8;
const RATE_LIMIT_WINDOW_SECONDS = 300;

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return respond({ status: 'error' }, 405);

  try {
    const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);

    let token: string | undefined;
    let password: string | undefined;
    try {
      const body = await req.json();
      token = typeof body?.token === 'string' ? body.token.trim() : undefined;
      password = typeof body?.password === 'string' ? body.password : undefined;
    } catch {
      return respond({ status: 'error' }, 400);
    }
    if (!token || !password) return respond({ status: 'error' }, 400);
    if (password.length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return respond({ status: 'weak_password' }, 400);
    }

    const tokenHash = await sha256Hex(token);
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0].trim()
      ?? req.headers.get('cf-connecting-ip') ?? 'unknown';
    for (const key of [`ip:${clientIp}`, `token:${tokenHash}`]) {
      const { data, error } = await admin.rpc('check_rate_limit', {
        p_fn_name: 'accept-invite-account',
        p_client_key: key,
        p_max_requests: RATE_LIMIT_MAX,
        p_window_seconds: RATE_LIMIT_WINDOW_SECONDS,
      });
      if (!error && data === false) return respond({ status: 'rate_limited' }, 429);
    }

    const { data: invite } = await admin
      .from('driver_invites')
      .select('email')
      .eq('token_hash', tokenHash)
      .eq('status', 'pending')
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();
    if (!invite?.email) return respond({ status: 'invalid_invite' }, 400);
    const email = String(invite.email).trim();

    const { data: existing } = await admin.rpc('fn_invite_unconfirmed_user', { p_email: email }).maybeSingle();
    if (existing?.confirmed) {
      // They already have a real account: they sign in with their own password.
      return respond({ status: 'exists' });
    }
    if (existing?.user_id) {
      const { error: delError } = await admin.auth.admin.deleteUser(existing.user_id as string);
      if (delError) {
        console.error('[accept-invite-account] could not remove the unconfirmed account:', delError);
        return respond({ status: 'error' }, 500);
      }
    }

    const { error: createError } = await admin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });
    if (createError) {
      console.error('[accept-invite-account] createUser failed:', createError);
      return respond({ status: 'error' }, 500);
    }
    return respond({ status: 'created', email });
  } catch (err) {
    console.error('[accept-invite-account] unexpected:', err);
    return respond({ status: 'error' }, 500);
  }
});
