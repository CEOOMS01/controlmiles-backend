// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/cgc-seal-trip/index.ts
//
// Connects a just-closed trip to CGC Core's governance pipeline
// (https://cgc-cre.vercel.app, see [[project_cgc_core]]): POST
// /governance/decision runs a real multi-module governance pipeline and
// PoD (Proof-of-Decision) cryptographically seals the outcome -- SHA-256
// triplet hash + RSA-PSS signature, chained into CGC Core's own Postgres.
// This closes ControlMiles' own flagged gap: the antifraud engine and its
// hash-chain audit log (audit_service.dart) run entirely client-side --
// nothing server-side proves a trip record wasn't fabricated. This
// function is the server-side hop that adds an independent, non-client
// proof, same pattern LedgiProof already uses for transaction
// classification (supabase/functions/cgc-evaluate in that repo).
//
// Security: session_id comes from the body, but everything else
// (ownership, org_id, total_miles, duration, vehicle_id, the acting
// user's real email) is derived server-side from a SELECT run with the
// CALLER's own JWT (userClient, not the service role) -- Postgres RLS is
// what actually decides whether this caller may see/seal that session
// (owner, or an org admin for a Fleet trip), matching this project's
// existing sessions RLS rather than re-implementing that check here. The
// only client-supplied values forwarded to CGC Core are the antifraud
// tick counters (total_gps_ticks/rejected_gps_ticks/
// min_driving_signature_score) -- diagnostic signal only, not the mileage
// figure itself, which always comes from the verified DB row.
//
// Best-effort by design: sealing must never block or fail trip-close for
// the driver. Any failure here (CGC Core down, not configured, timeout)
// returns a 200 with sealed:false rather than an error -- the caller
// (TrackingController.stopTracking) doesn't await this anyway.

import { createClient } from 'jsr:@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers':
    'authorization, x-client-info, apikey, content-type',
};

const CGC_ENDPOINT = Deno.env.get('CGC_ENDPOINT') ?? '';
// Each app signs in to CGC Core with its own key (2026-10-11): a personal
// trip is a ControlMiles (gig) decision, a fleet trip a ControlMiles Fleet
// one. The shared CGC_API_KEY is only a fallback until both are set.
const CGC_KEYS: Record<string, string> = {
  'controlmiles': Deno.env.get('CGC_API_KEY_CONTROLMILES') ?? '',
  'controlmiles-fleet': Deno.env.get('CGC_API_KEY_CONTROLMILES_FLEET') ?? '',
};
const LEGACY_CGC_API_KEY = Deno.env.get('CGC_API_KEY') ?? '';
const cgcKeyFor = (app: string) => CGC_KEYS[app] || LEGACY_CGC_API_KEY;
// CGC Core sleeps when idle and its first answer took 22 s (measured 2026-11-09);
// with 10 s every seal timed out. The driver never waits for this: see waitUntil.
const CGC_TIMEOUT_MS = 60000;
const CGC_ATTEMPTS = 2;
const CGC_RETRY_DELAY_MS = 15000;

declare const EdgeRuntime: { waitUntil(p: Promise<unknown>): void };

// Runs after the response has gone back to the app. A retry only follows a
// timeout, a network failure or a 5xx from CGC Core.
async function sealAfterResponse(
  // deno-lint-ignore no-explicit-any
  userClient: any,
  sessionId: string,
  form: URLSearchParams,
  cgcApiKey: string,
): Promise<void> {
  for (let attempt = 1; attempt <= CGC_ATTEMPTS; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CGC_TIMEOUT_MS);
    try {
      const cgcRes = await fetch(`${CGC_ENDPOINT}/governance/decision`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${cgcApiKey}`,
        },
        body: form.toString(),
        signal: controller.signal,
      });
      if (!cgcRes.ok) {
        const text = await cgcRes.text();
        console.warn(`[cgc-seal-trip] CGC Core returned ${cgcRes.status}: ${text}`);
        if (cgcRes.status < 500) return;
      } else {
        const data = await cgcRes.json();
        const decisionId: string | undefined = data?.decision_id;
        if (!decisionId) {
          console.warn(`[cgc-seal-trip] CGC Core answered without decision_id: ${JSON.stringify(data).slice(0, 300)}`);
          return;
        }
        // Same userClient -- RLS governs this write too (owner or org admin).
        // Audit 2026-10-10: fn_freeze_closed_session allows the seal once.
        const { error: sealError } = await userClient
          .from('sessions')
          .update({ cgc_decision_id: decisionId, cgc_sealed_at: new Date().toISOString() })
          .eq('id', sessionId);
        if (sealError) {
          console.error(`[cgc-seal-trip] could not store the seal for ${sessionId}: ${sealError.message}`);
        }
        return;
      }
    } catch (err) {
      console.warn(`[cgc-seal-trip] attempt ${attempt} failed for ${sessionId}: ${err}`);
    } finally {
      clearTimeout(timeout);
    }
    if (attempt < CGC_ATTEMPTS) {
      await new Promise((resolve) => setTimeout(resolve, CGC_RETRY_DELAY_MS));
    }
  }
  console.error(`[cgc-seal-trip] trip ${sessionId} not sealed after ${CGC_ATTEMPTS} attempts`);
}

// Security hardening (2026-08-28): same Postgres-backed pattern as
// create-checkout-session's own rate limiter (see its comment for why
// this isn't an in-memory Map) -- a normal driver seals one trip at a
// time, at most a handful per hour; this only stops a compromised token
// from spamming CGC Core through this function.
const RATE_LIMIT_MAX = 15;
const RATE_LIMIT_WINDOW_SECONDS = 60;

async function isRateLimited(clientId: string): Promise<boolean> {
  // SECURITY (2026-09-16): this RPC is called with the SERVICE-ROLE key, not
  // the anon/user key. check_rate_limit is EXECUTE-revoked from anon and
  // authenticated so that nobody holding the public key can fill another
  // user's bucket (a targeted lockout) or bloat edge_function_rate_limits at
  // will. The service-role key never leaves the edge function.
  const rlClient = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );
  const { data, error } = await rlClient.rpc('check_rate_limit', {
    p_fn_name: 'cgc-seal-trip',
    p_client_key: clientId,
    p_max_requests: RATE_LIMIT_MAX,
    p_window_seconds: RATE_LIMIT_WINDOW_SECONDS,
  });
  if (error) {
    console.warn('[cgc-seal-trip] rate limit check failed (failing open):', error);
    return false;
  }
  return !data;
}

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return respond({ sealed: false, reason: 'Missing Authorization header' }, 401);
    }

    let body: {
      session_id?: string;
      total_gps_ticks?: number;
      rejected_gps_ticks?: number;
      min_driving_signature_score?: number;
    };
    try {
      body = await req.json();
    } catch {
      return respond({ sealed: false, reason: 'Invalid JSON body' }, 400);
    }

    if (!body.session_id) {
      return respond({ sealed: false, reason: 'Missing required field: session_id' }, 400);
    }

    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!;

    // User-scoped client -- RLS decides visibility, not this function.
    const userClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: userData, error: userError } = await userClient.auth.getUser();
    if (userError || !userData?.user) {
      return respond({ sealed: false, reason: 'Invalid or expired session' }, 401);
    }

    if (await isRateLimited(userData.user.id)) {
      return respond({ sealed: false, reason: 'rate_limited' }, 429);
    }

    const { data: session, error: sessionError } = await userClient
      .from('sessions')
      .select('id, user_id, organization_id, vehicle_id, total_miles, total_duration_seconds, session_status')
      .eq('id', body.session_id)
      .maybeSingle();

    if (sessionError || !session) {
      // RLS made this look identical to "doesn't exist" whether it's
      // truly missing or just not visible to this caller -- correct,
      // don't leak which.
      return respond({ sealed: false, reason: 'Session not found or not accessible' }, 404);
    }

    if (session.session_status !== 'closed') {
      return respond({ sealed: false, reason: 'Session is not closed yet' }, 400);
    }

    const appSource = session.organization_id ? 'controlmiles-fleet' : 'controlmiles';
    const cgcApiKey = cgcKeyFor(appSource);
    if (!CGC_ENDPOINT || !cgcApiKey) {
      console.warn(`[cgc-seal-trip] CGC_ENDPOINT / CGC key for ${appSource} not set -- trip not sealed`);
      return respond({ sealed: false, reason: 'CGC governance not configured' }, 200);
    }

    // Fleet trip -> the org is the real tenant; Gig trip -> the driver's
    // own user id is the tenant, so one compromised individual account
    // can only ever exhaust its own CGC Core rate-limit/quota bucket,
    // never another driver's.
    const orgId: string = session.organization_id ?? session.user_id;

    const inputData = {
      trip_id: session.id,
      total_miles: session.total_miles,
      duration_seconds: session.total_duration_seconds,
      vehicle_id: session.vehicle_id,
      total_gps_ticks: body.total_gps_ticks ?? null,
      rejected_gps_ticks: body.rejected_gps_ticks ?? null,
      min_driving_signature_score: body.min_driving_signature_score ?? null,
    };

    const form = new URLSearchParams();
    form.set('org_id', orgId);
    form.set('action', 'controlmiles.trip_completed');
    form.set('input_data', JSON.stringify(inputData));
    form.set('user_email', userData.user.email ?? 'unknown@controlmiles');
    form.set('data_domains', JSON.stringify(['mileage_tracking']));
    form.set('app_source', appSource);

    // The trip is already closed: answer now and seal afterwards, so nothing in
    // the app depends on how long CGC Core takes.
    EdgeRuntime.waitUntil(sealAfterResponse(userClient, session.id, form, cgcApiKey));
    return respond({ sealed: false, queued: true });
  } catch (err: any) {
    console.error('[cgc-seal-trip] Unexpected error:', err);
    return respond({ sealed: false, reason: err?.message ?? 'Internal error' }, 200);
  }
});
