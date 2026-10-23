// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/ds-public-enroll/index.ts
//
// Driving school public enrollment page (/book/<slug>): the one door for
// enrollment requests (audit 2026-10-23, finding 5). The page used to call
// the database function ds_public_enroll straight from the visitor's
// browser with the public key, so a bot only needed that key: no limit per
// visitor, only 30 requests an hour per school, which one bot could use up
// to block real students.
//
// Now the browser calls this function, which
//   1. limits requests per visitor IP (8 an hour; shared with check_rate_limit),
//   2. checks a Cloudflare Turnstile token when TURNSTILE_SECRET is set
//      (when it is not set the captcha is skipped and only the IP limit and
//      the honeypot apply),
//   3. keeps only the known fields, cut to their maximum length, and
//   4. calls ds_public_enroll with the service role, so that function can be
//      closed to anon (migration pending/..._close_ds_public_enroll_to_anon).
// All the real rules (age, guardian, consent, per school limits, per contact
// limits) stay in ds_public_enroll.
//
// verify_jwt is off: visitors have no account. The browser calls it directly
// so the IP seen here is the visitor's.

import { createClient } from 'jsr:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const TURNSTILE_SECRET = Deno.env.get('TURNSTILE_SECRET') ?? '';
const IP_LIMIT_MAX = 8;
const IP_LIMIT_WINDOW_SECONDS = 3600;

const CODES = [
  'NOT_AVAILABLE', 'NAME_REQUIRED', 'BIRTH_DATE', 'TOO_YOUNG', 'EMAIL', 'GUARDIAN_REQUIRED',
  'GUARDIAN_CONSENT', 'CONTACT_REQUIRED', 'CONSENT', 'SMS_PHONE', 'BUSY', 'INVALID',
];

// Text fields and their maximum length; booleans listed apart.
const TEXT_FIELDS: Record<string, number> = {
  first_name: 60, last_name: 60, birth_date: 10, email: 120, phone: 30,
  guardian_name: 120, guardian_email: 120, guardian_phone: 30,
  program_id: 40, branch_id: 40, message: 500, preferred_language: 2,
  consent_by: 10, consent_name: 120, sms_phone: 30,
};
const BOOL_FIELDS = ['consent', 'sms_opt_in'];

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

async function captchaOk(token: string, ip: string): Promise<boolean> {
  if (!token) return false;
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: TURNSTILE_SECRET, response: token, ...(ip !== 'unknown' ? { remoteip: ip } : {}) }),
    });
    const data = await res.json();
    return data?.success === true;
  } catch (err) {
    console.error('[ds-public-enroll] turnstile verification failed:', err);
    return false;
  }
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (req.method !== 'POST') return respond({ error: 'METHOD' }, 405);

  try {
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim()
      ?? req.headers.get('cf-connecting-ip')
      ?? 'unknown';

    const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);

    const { data: allowed, error: limitError } = await admin.rpc('check_rate_limit', {
      p_fn_name: 'ds-public-enroll-ip',
      p_client_key: ip,
      p_max_requests: IP_LIMIT_MAX,
      p_window_seconds: IP_LIMIT_WINDOW_SECONDS,
    });
    if (limitError) {
      // Closed on purpose: this door has no other per visitor protection.
      console.error('[ds-public-enroll] rate limit check failed:', limitError);
      return respond({ error: 'UNAVAILABLE' }, 503);
    }
    if (!allowed) return respond({ error: 'RATE_LIMITED' }, 429);

    let body: Record<string, unknown>;
    try {
      body = await req.json();
    } catch {
      return respond({ error: 'INVALID' }, 400);
    }
    const slug = typeof body.slug === 'string' ? body.slug.toLowerCase() : '';
    const form = body.p && typeof body.p === 'object' ? (body.p as Record<string, unknown>) : null;
    if (!/^[a-z0-9-]{3,40}$/.test(slug) || !form) return respond({ error: 'INVALID' }, 400);

    // Honeypot: a person never fills it. Answer as if it worked.
    if (typeof body.hp === 'string' && body.hp.length > 0) return respond({ ok: true });

    if (TURNSTILE_SECRET) {
      const token = typeof body.captcha === 'string' ? body.captcha : '';
      if (!(await captchaOk(token, ip))) return respond({ error: 'CAPTCHA' }, 400);
    }

    const clean: Record<string, unknown> = {};
    for (const [key, max] of Object.entries(TEXT_FIELDS)) {
      const v = form[key];
      clean[key] = typeof v === 'string' ? v.trim().slice(0, max) : '';
    }
    for (const key of BOOL_FIELDS) clean[key] = form[key] === true;

    const { error } = await admin.rpc('ds_public_enroll', { p_slug: slug, p: clean });
    if (error) {
      const code = CODES.find((c) => error.message.includes(c));
      if (code) return respond({ error: code }, 400);
      console.error('[ds-public-enroll] ds_public_enroll failed:', error);
      return respond({ error: 'UNEXPECTED' }, 500);
    }
    return respond({ ok: true });
  } catch (err) {
    console.error('[ds-public-enroll] unexpected error:', err);
    return respond({ error: 'UNEXPECTED' }, 500);
  }
});
