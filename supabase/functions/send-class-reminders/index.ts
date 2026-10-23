// Olympus Mont Systems LLC - ControlMiles
// supabase/functions/send-class-reminders/index.ts
//
// Driving school class reminders (2026-10-19, students module phase 1):
// an email to the student and to their parent/guardian before each class,
// within the school's window (ds_settings.reminder_hours, 24 by default).
// ds_due_class_reminders lists what's due (plan feature class_reminders,
// active students, not sent yet); ds_reminders_sent makes it once per
// recipient. Sent through Resend like the other ControlMiles emails.
//
// Freed times (phase 2, 2026-10-20): when a student cancels, the other
// students of the same program (and their guardian when the program says
// so) get one email that the time is open to book from their portal link.
// ds_due_slot_notices skips times already taken again or in the past;
// ds_slot_notices.sent_at makes it once per freed time.
//
// 2026-10-23 (audit finding 9):
//   * the email is written in the student's language (English or Spanish,
//     ds_students.preferred_language; none = English);
//   * the school's name is cleaned before it goes into the From header;
//   * a reminder is CLAIMED in ds_reminders_sent before it is sent (primary
//     key shock-absorbs a second run) and un-claimed if Resend refuses it,
//     so a failed log write can no longer repeat the same email every hour.
//
// Called by pg_cron hourly (job 'class-reminders-hourly'), never by a user:
// verify_jwt off, the X-Sync-Secret header is the gate (IFTA_SYNC_SECRET,
// same as send-fuel-alerts).

import { createClient } from 'jsr:@supabase/supabase-js@2';

const SYNC_SECRET = Deno.env.get('IFTA_SYNC_SECRET') ?? '';
const RESEND_API_KEY = Deno.env.get('RESEND_API_KEY') ?? '';
const SENDER = 'alert@controlmiles.com';

type Due = {
  shift_block_id: string;
  organization_id: string;
  school: string;
  timezone: string;
  block_date: string;
  start_time: string;
  student_first_name: string;
  recipient: string;
  instructor: string | null;
  language: string | null;
};

type Notice = {
  notice_id: string;
  school: string;
  block_date: string;
  start_time: string;
  instructor: string | null;
  recipient: string;
  first_name: string;
  language: string | null;
};

type Lang = 'en' | 'es';
const langOf = (l: string | null): Lang => (l === 'es' ? 'es' : 'en');

// All the wording, per language. {name}, {when}, {instructor}, {first} are
// filled in (already escaped) by fill().
const TEXT: Record<Lang, {
  locale: string; at: string; withWord: string;
  reminderSubject: string; reminderTitle: string; reminderBody: string; reminderNote: string;
  noticeSubject: string; noticeTitle: string; noticeBody: string; noticeNote: string;
  footer: string;
}> = {
  en: {
    locale: 'en-US', at: 'at', withWord: 'with',
    reminderSubject: 'Driving lesson {when}',
    reminderTitle: 'Driving lesson reminder',
    reminderBody: '<strong>{name}</strong> has a driving lesson on <strong>{when}</strong>{instructor}.',
    reminderNote: "Bring the learner's permit. If you need to reschedule, please contact the school.",
    noticeSubject: 'Lesson time open: {when}',
    noticeTitle: 'A lesson time just opened',
    noticeBody: 'A driving lesson on <strong>{when}</strong>{instructor} is free again.',
    noticeNote: "To book it for {first}, open the lesson link the school sent you. First come, first served.",
    footer: 'Sent by ControlMiles for {school}.',
  },
  es: {
    locale: 'es-US', at: 'a las', withWord: 'con',
    reminderSubject: 'Clase de manejo {when}',
    reminderTitle: 'Recordatorio de clase de manejo',
    reminderBody: '<strong>{name}</strong> tiene una clase de manejo el <strong>{when}</strong>{instructor}.',
    reminderNote: 'Lleve el permiso de aprendizaje. Si necesita cambiar la hora, comuníquese con la escuela.',
    noticeSubject: 'Horario de clase disponible: {when}',
    noticeTitle: 'Se liberó un horario de clase',
    noticeBody: 'Una clase de manejo el <strong>{when}</strong>{instructor} quedó libre otra vez.',
    noticeNote: 'Para reservarla para {first}, abra el enlace de clases que le envió la escuela. El primero en reservar se la queda.',
    footer: 'Enviado por ControlMiles para {school}.',
  },
};

function respond(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

const esc = (s: string) => s.replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' })[c]!);

// A school name inside the From header: no characters that can end the name
// or start another address or header.
const fromName = (s: string) => s.replace(/[<>"\r\n,;:\\]/g, '').trim().slice(0, 60) || 'ControlMiles';

function when(d: { block_date: string; start_time: string }, lang: Lang): string {
  const t = TEXT[lang];
  const [h, m] = d.start_time.split(':').map(Number);
  const time = lang === 'en'
    ? `${((h + 11) % 12) + 1}:${String(m).padStart(2, '0')} ${h >= 12 ? 'PM' : 'AM'}`
    : new Date(`${d.block_date}T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00Z`)
        .toLocaleTimeString(t.locale, { hour: 'numeric', minute: '2-digit', timeZone: 'UTC' });
  const day = new Date(`${d.block_date}T12:00:00Z`).toLocaleDateString(t.locale, {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
    timeZone: 'UTC',
  });
  return `${day} ${t.at} ${time}`;
}

function fill(template: string, values: Record<string, string>): string {
  return template.replace(/\{(\w+)\}/g, (_, k) => values[k] ?? '');
}

function page(lang: Lang, school: string, title: string, bodyHtml: string, note: string): string {
  const t = TEXT[lang];
  return `<!DOCTYPE html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>ControlMiles</title></head>
<body style="margin:0; padding:0; background-color:#faf6ee; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#faf6ee; padding:32px 16px;"><tr><td align="center">
<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="max-width:520px; width:100%; background-color:#ffffff; border:1px solid #e3d9c4; border-radius:16px;">
<tr><td style="padding:28px 36px 0 36px; font-size:15px; font-weight:700; color:#2c6c99;">${esc(school)}</td></tr>
<tr><td style="padding:12px 36px 32px 36px;">
<h1 style="margin:0; font-size:20px; color:#211c14;">${title}</h1>
<p style="margin:10px 0 0 0; font-size:15px; line-height:1.5; color:#211c14;">${bodyHtml}</p>
<p style="margin:10px 0 0 0; font-size:13px; line-height:1.5; color:#5c5446;">${note}</p>
</td></tr>
</table>
<p style="font-size:11px; color:#8a8170; margin-top:12px;">${fill(t.footer, { school: esc(school) })}</p>
</td></tr></table></body></html>`;
}

function buildHtml(d: Due): string {
  const lang = langOf(d.language);
  const t = TEXT[lang];
  const body = fill(t.reminderBody, {
    name: esc(d.student_first_name),
    when: esc(when(d, lang)),
    instructor: d.instructor ? ` ${t.withWord} ${esc(d.instructor)}` : '',
  });
  return page(lang, d.school, t.reminderTitle, body, t.reminderNote);
}

function buildNoticeHtml(n: Notice): string {
  const lang = langOf(n.language);
  const t = TEXT[lang];
  const body = fill(t.noticeBody, {
    when: esc(when(n, lang)),
    instructor: n.instructor ? ` ${t.withWord} ${esc(n.instructor)}` : '',
  });
  return page(lang, n.school, t.noticeTitle, body, fill(t.noticeNote, { first: esc(n.first_name) }));
}

async function sendEmail(school: string, to: string, subject: string, html: string): Promise<boolean> {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: `${fromName(school)} via ControlMiles <${SENDER}>`, to: [to], subject, html }),
  });
  if (!res.ok) console.error('[send-class-reminders] Resend refused an email:', res.status, await res.text());
  return res.ok;
}

Deno.serve(async (req: Request) => {
  if (req.method !== 'POST') return respond({ error: 'Method not allowed' }, 405);
  if (!SYNC_SECRET || req.headers.get('X-Sync-Secret') !== SYNC_SECRET) return respond({ error: 'Unauthorized' }, 401);
  if (!RESEND_API_KEY) return respond({ error: 'RESEND_API_KEY not configured' }, 500);

  const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
  const { data, error } = await admin.rpc('ds_due_class_reminders');
  if (error) return respond({ error: error.message }, 500);
  const due = (data ?? []) as Due[];

  let sent = 0;
  let skipped = 0;
  const failed: string[] = [];
  for (const d of due) {
    // Claim first: if this recipient is already logged (or the log cannot be
    // written) nothing is sent, so the same email can never go out twice.
    const { error: claimError } = await admin
      .from('ds_reminders_sent')
      .insert({ shift_block_id: d.shift_block_id, recipient: d.recipient });
    if (claimError) {
      skipped++;
      if (claimError.code !== '23505') console.error('[send-class-reminders] could not log a reminder:', claimError);
      continue;
    }
    const lang = langOf(d.language);
    const ok = await sendEmail(d.school, d.recipient, fill(TEXT[lang].reminderSubject, { when: when(d, lang) }), buildHtml(d));
    if (!ok) {
      // Un-claimed, so the next hourly run tries again.
      await admin.from('ds_reminders_sent').delete().eq('shift_block_id', d.shift_block_id).eq('recipient', d.recipient);
      failed.push(d.shift_block_id);
      continue;
    }
    sent++;
  }

  // Freed times: one email per recipient, then the notice is closed (a
  // failed address isn't retried, so nobody gets the same notice twice).
  const { data: noticeRows, error: noticeError } = await admin.rpc('ds_due_slot_notices');
  if (noticeError) {
    return respond({ due: due.length, sent, skipped, failed: failed.length, notices_error: noticeError.message });
  }
  const notices = (noticeRows ?? []) as Notice[];
  const seen = new Set<string>();
  const done = new Set<string>();
  let noticesSent = 0;
  for (const n of notices) {
    const key = `${n.notice_id}|${n.recipient}`;
    if (seen.has(key)) continue; // a student who is also a guardian
    seen.add(key);
    done.add(n.notice_id);
    const lang = langOf(n.language);
    if (await sendEmail(n.school, n.recipient, fill(TEXT[lang].noticeSubject, { when: when(n, lang) }), buildNoticeHtml(n))) {
      noticesSent++;
    }
  }
  if (done.size > 0) {
    await admin.from('ds_slot_notices').update({ sent_at: new Date().toISOString() }).in('id', [...done]);
  }

  return respond({ due: due.length, sent, skipped, failed: failed.length, notices: done.size, notice_emails: noticesSent });
});
