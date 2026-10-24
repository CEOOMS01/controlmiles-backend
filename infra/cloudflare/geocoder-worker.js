// Olympus Mont Systems LLC - ControlMiles
// infra/cloudflare/geocoder-worker.js
//
// Cloudflare Worker "controlmiles-geocoder": OUR OWN U.S. address geocoder.
// Data: U.S. Census TIGER/Line address ranges (public domain), packed per state
// by tools/geocoder/build_state.py into one file per state in the R2 bucket
// olimsysmaps (key geocode/<ST>.bin). Nothing leaves our infrastructure: no
// third-party geocoder ever sees an address.
//
// Bindings: GEO -> R2 bucket olimsysmaps;  optional secret GEOCODER_KEY.
// Turn OFF "Persist logs" / invocation logs for this Worker in the dashboard.
// A city in the query ("..., Annapolis, MD") narrows the candidates to the ZIPs
// that cover a place of that name (header zipCity, from the Census ZCTA-place file).
// Call (server to server only):  POST /  {"q":"3608 Chestnut Ave, Baltimore, MD","state":"MD"}
//   header  X-CM-Key: <GEOCODER_KEY>
// Answers  {"covered":true,"results":[{"address","lat","lon","zip","county"}]}
//   covered=false when we hold no data for that state (the caller then falls
//   back to another provider).
//
// Accuracy: interpolated along the street segment (same data and method as the
// Census Geocoder: points agreed within a few metres in our test).
//
// Keep ABBR / norm / fnv1a identical to tools/geocoder/build_state.py.

const ABBR = {
  avenue: "ave", street: "st", road: "rd", drive: "dr", boulevard: "blvd", lane: "ln", court: "ct",
  place: "pl", terrace: "ter", parkway: "pkwy", highway: "hwy", circle: "cir", square: "sq",
  north: "n", south: "s", east: "e", west: "w", northeast: "ne", northwest: "nw",
  southeast: "se", southwest: "sw", saint: "st", mount: "mt", fort: "ft", route: "rte",
  trail: "trl", way: "way", alley: "aly", expressway: "expy", freeway: "fwy", turnpike: "tpke",
};
const UNIT_RE = /\b(apt|apartment|unit|ste|suite|fl|floor|rm|room|bldg|building|lot)\b.*$/i;
const OFFSET_M = 4; // how far from the street centre line the point is placed

const norm = (name) =>
  name
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, " ")
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => ABBR[w] || w)
    .join(" ");

function fnv1a(s) {
  let h = 0x811c9dc5;
  for (const b of new TextEncoder().encode(s)) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

// ---- state files (header cached per isolate) --------------------------------
const headers = new Map();
const shardCache = new Map();
let coveredStates = null;

async function covered(env) {
  if (coveredStates) return coveredStates;
  const list = await env.GEO.list({ prefix: "geocode/" });
  coveredStates = list.objects.map((o) => /geocode\/([A-Z]{2})\.bin$/.exec(o.key)?.[1]).filter(Boolean);
  return coveredStates;
}

async function stateHeader(env, st) {
  if (headers.has(st)) return headers.get(st);
  const key = `geocode/${st}.bin`;
  const head = await env.GEO.get(key, { range: { offset: 0, length: 12 } });
  if (!head) return null;
  const buf = new DataView(await head.arrayBuffer());
  const len = buf.getUint32(8, true);
  const hdr = await env.GEO.get(key, { range: { offset: 12, length: len } });
  const meta = JSON.parse(await hdr.text());
  meta.base = 12 + len;
  headers.set(st, meta);
  return meta;
}

async function loadShard(env, st, meta, idx) {
  const ck = `${st}:${idx}`;
  if (shardCache.has(ck)) return shardCache.get(ck);
  const [off, length] = meta.table[idx];
  if (!length) return [];
  const obj = await env.GEO.get(`geocode/${st}.bin`, { range: { offset: meta.base + off, length } });
  const edges = await new Response(obj.body.pipeThrough(new DecompressionStream("gzip"))).json();
  if (shardCache.size > 48) shardCache.delete(shardCache.keys().next().value);
  shardCache.set(ck, edges);
  return edges;
}

// ---- geometry ----------------------------------------------------------------
function decode(g) {
  const pts = [[g[0] / 1e6, g[1] / 1e6]];
  for (let i = 2; i < g.length; i += 2) {
    const p = pts[pts.length - 1];
    pts.push([p[0] + g[i] / 1e6, p[1] + g[i + 1] / 1e6]);
  }
  return pts;
}
const segLen = (a, b) => Math.hypot((b[0] - a[0]) * 111320 * Math.cos((a[1] * Math.PI) / 180), (b[1] - a[1]) * 110540);

// Point at fraction f along the line, moved OFFSET_M to the left or right of it.
function locate(pts, f, left) {
  const segs = [];
  let total = 0;
  for (let i = 0; i < pts.length - 1; i++) {
    const L = segLen(pts[i], pts[i + 1]);
    segs.push([pts[i], pts[i + 1], L]);
    total += L;
  }
  const target = f * (total || 1);
  let acc = 0;
  for (let i = 0; i < segs.length; i++) {
    const [a, b, L] = segs[i];
    if (acc + L >= target || i === segs.length - 1) {
      const t = L === 0 ? 0 : (target - acc) / L;
      const lon = a[0] + (b[0] - a[0]) * t;
      const lat = a[1] + (b[1] - a[1]) * t;
      const c = Math.cos((lat * Math.PI) / 180);
      const dx = (b[0] - a[0]) * c;
      const dy = b[1] - a[1];
      const n = Math.hypot(dx, dy) || 1;
      const sgn = left ? 1 : -1;
      const off = OFFSET_M / 111320;
      return [lat + ((sgn * dx) / n) * off, lon + ((sgn * -dy) / n) * (off / c)];
    }
    acc += L;
  }
  return null;
}

// ---- query -------------------------------------------------------------------
function parse(q) {
  const parts = q.split(",").map((s) => s.trim()).filter(Boolean);
  const m = /^(\d+)[A-Za-z]?\s+(.+)$/.exec(parts[0] || "");
  if (!m) return null;
  const street = m[2].replace(UNIT_RE, "").replace(/#.*$/, "").trim();
  if (!street) return null;
  const rest = parts.slice(1).join(" ");
  const zip = /\b(\d{5})(?:-\d{4})?\b/.exec(rest)?.[1] || null;
  const st = /\b([A-Za-z]{2})\b/.exec(rest.replace(/\b\d{5}(-\d{4})?\b/, ""))?.[1]?.toUpperCase() || null;
  // City: the first part after the street that is not just a state / ZIP.
  const city =
    parts.slice(1).find((x) => !/^[A-Za-z]{2}$/.test(x) && !/^\d{5}(-\d{4})?$/.test(x) && !/^[A-Za-z]{2}\s+\d{5}/.test(x)) || null;
  return { number: Number(m[1]), street, zip, state: st, city: city ? norm(city) : null };
}

function sideMatch(s, number, zip) {
  if (!s) return false;
  const [lo, hi, parity, z] = s;
  if (number < lo || number > hi) return false;
  if (parity === "E" && number % 2) return false;
  if (parity === "O" && number % 2 === 0) return false;
  if (zip && z !== zip) return false;
  return true;
}

async function search(env, st, p) {
  const meta = await stateHeader(env, st);
  if (!meta) return [];
  const key = norm(p.street);
  const edges = await loadShard(env, st, meta, fnv1a(key) % meta.shards);
  const out = [];
  const seen = new Set();
  for (const e of edges) {
    if (e[0] !== key) continue;
    for (const [i, left] of [[3, true], [4, false]]) {
      const s = e[i];
      if (!sideMatch(s, p.number, p.zip)) continue;
      const f = s[1] === s[0] ? 0.5 : (p.number - s[0]) / (s[1] - s[0]);
      const pt = locate(decode(e[5]), f, left);
      if (!pt) continue;
      const id = `${e[1]}|${s[3]}|${e[2]}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({
        address: `${p.number} ${e[1]}${s[3] ? `, ${s[3]}` : ""}, ${st}`,
        lat: Math.round(pt[0] * 1e6) / 1e6,
        lon: Math.round(pt[1] * 1e6) / 1e6,
        zip: s[3] || null,
        county: e[2],
      });
    }
  }
  // With a city, keep the candidates whose ZIP covers a place of that name.
  if (p.city && !p.zip) {
    const inCity = out.filter((r) => ((meta.zipCity || {})[r.zip] || []).some((n) => norm(n) === p.city));
    if (inCity.length) return inCity;
  }
  return out;
}

export default {
  async fetch(request, env) {
    // POST with a JSON body, never GET with the address in the URL: URLs end up
    // in Cloudflare's logs, and an address here may be a child's home.
    if (request.method !== "POST") return json({ error: "method" }, 405);
    // Optional shared key (set the GEOCODER_KEY secret to require it).
    if (env.GEOCODER_KEY && request.headers.get("X-CM-Key") !== env.GEOCODER_KEY) return json({ error: "unauthorized" }, 401);
    let body = {};
    try {
      body = await request.json();
    } catch {
      return json({ error: "bad json" }, 400);
    }
    const q = String(body.q || "").slice(0, 200);
    const p = parse(q);
    if (!p) return json({ covered: true, results: [], note: "not a street address" });
    const have = await covered(env);
    const wanted = String(body.state || p.state || "").toUpperCase();
    const states = wanted ? (have.includes(wanted) ? [wanted] : []) : have;
    if (!states.length) return json({ covered: false, results: [] });
    let results = [];
    for (const st of states) results = results.concat(await search(env, st, p));
    // A matching ZIP first, then the rest; at most 5 candidates.
    results.sort((a, b) => Number(b.zip === p.zip) - Number(a.zip === p.zip));
    return json({ covered: true, results: results.slice(0, 5) });
  },
};
