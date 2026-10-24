// Olympus Mont Systems LLC - ControlMiles
// infra/cloudflare/tiles-worker.js
//
// Cloudflare Worker "controlmiles-tiles" (2026-10-24): serves the map file
// (us.pmtiles, bucket olimsysmaps) to the web map in production, instead of
// the bucket's pub-*.r2.dev address (Cloudflare marks that one "rate-limited,
// not recommended for production": no cache, no Access).
//
// Binding: BUCKET -> the R2 bucket olimsysmaps.
// What it does: answers only HTTP Range requests for us.pmtiles (the PMTiles
// client reads the file in small ranges), caches each range at the edge,
// sends CORS for the sites that may draw the map, and refuses everything else.
// Deployed by hand in the dashboard (Workers & Pages > controlmiles-tiles);
// keep this file as the source of truth.

const KEY = "us.pmtiles";
const MAX_RANGE = 8 * 1024 * 1024;
const ALLOWED = [
  "https://controlmiles.com",
  "https://www.controlmiles.com",
  "http://localhost:3000",
  "http://localhost:3059",
  "http://localhost:3977",
];

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": ALLOWED.includes(origin) ? origin : "https://controlmiles.com",
    "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
    "Access-Control-Allow-Headers": "Range, If-Match, If-None-Match",
    "Access-Control-Expose-Headers": "ETag, Content-Range, Content-Length, Accept-Ranges",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

// "bytes=a-b", "bytes=a-" or "bytes=-n".
function parseRange(header) {
  const m = /^bytes=(\d*)-(\d*)$/.exec(header || "");
  if (!m || (m[1] === "" && m[2] === "")) return null;
  if (m[1] === "") return { suffix: Math.min(Number(m[2]), MAX_RANGE) };
  const offset = Number(m[1]);
  if (m[2] === "") return { offset, length: MAX_RANGE };
  const end = Number(m[2]);
  if (end < offset || end - offset + 1 > MAX_RANGE) return null;
  return { offset, length: end - offset + 1 };
}

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "";
    const cors = corsHeaders(origin);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", { status: 405, headers: cors });
    }
    const url = new URL(request.url);
    if (url.pathname !== "/" + KEY) return new Response("Not found", { status: 404, headers: cors });

    const rangeHeader = request.headers.get("Range");
    const range = parseRange(rangeHeader);
    if (!range) return new Response("A valid Range header is required", { status: 416, headers: cors });

    // Each range is cached as its own entry (the Cache API does not store 206s).
    const cache = caches.default;
    const cacheKey = new Request(url.origin + "/__range/" + KEY + "?r=" + encodeURIComponent(rangeHeader));
    const hit = await cache.match(cacheKey);
    if (hit) {
      const headers = new Headers(hit.headers);
      for (const [k, v] of Object.entries(cors)) headers.set(k, v);
      return new Response(request.method === "HEAD" ? null : hit.body, { status: 206, headers });
    }

    let obj;
    try {
      obj = await env.BUCKET.get(KEY, {
        range: range.suffix !== undefined ? { suffix: range.suffix } : { offset: range.offset, length: range.length },
      });
    } catch (e) {
      return new Response("Range not satisfiable", { status: 416, headers: cors });
    }
    if (!obj) return new Response("Not found", { status: 404, headers: cors });

    const buf = await obj.arrayBuffer();
    const offset = range.suffix !== undefined ? obj.size - buf.byteLength : range.offset;
    const end = offset + buf.byteLength - 1;
    const headers = new Headers({
      "Content-Type": "application/octet-stream",
      "Content-Range": "bytes " + offset + "-" + end + "/" + obj.size,
      "Content-Length": String(buf.byteLength),
      "Accept-Ranges": "bytes",
      ETag: obj.httpEtag,
      "Cache-Control": "public, max-age=86400",
    });
    ctx.waitUntil(cache.put(cacheKey, new Response(buf, { status: 200, headers })));
    for (const [k, v] of Object.entries(cors)) headers.set(k, v);
    return new Response(request.method === "HEAD" ? null : buf, { status: 206, headers });
  },
};
