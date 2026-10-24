#!/usr/bin/env python3
"""
ControlMiles own geocoder: build one state's data file from the U.S. Census
TIGER/Line ADDRFEAT shapefiles (address ranges along street segments).

Why: the Census Geocoder has no published terms, no SLA and no CORS; Nominatim
forbids personal data. TIGER/Line is U.S. Government data (public domain), the
very data the Census Geocoder interpolates from, so a geocoder built on it is
as accurate (tested: same points within a few metres) and no address ever
leaves our own infrastructure.

Usage:  python build_state.py MD 24 [--year 2025] [--out geocode_MD.bin]
        (state abbreviation, state FIPS code)

Besides the street segments, the header carries "zipCity": for each ZIP the
place names that cover it (Census ZCTA-to-place relationship file, also public
domain), so "1 Main St, Annapolis, MD" can be told apart from every other
"1 Main St" in the state.

File layout (read with HTTP range requests by the Worker in
infra/cloudflare/geocoder-worker.js):
    bytes 0-7    magic  b"CMGEO001"
    bytes 8-11   header length H (uint32 little-endian)
    bytes 12-... header JSON (utf-8): {"state","year","shards","table":[[offset,length],...]}
                 plus "zipCity": {zip: [place, ...]}; offsets are relative to the start of the payload area
    payload      N gzip-compressed JSON arrays, one per shard; an edge is
                 [key, fullname, county, [lo,hi,parity,zip] (left side),
                  [lo,hi,parity,zip] (right side), geometry]
                 geometry = [lon0, lat0, dlon1, dlat1, ...] in micro-degrees.

The street normalisation here and in the Worker MUST stay identical
(NORM_TESTS below is checked by both).
"""
import argparse, gzip, io, json, math, os, re, struct, sys, time, urllib.request, zipfile

try:
    import shapefile  # pyshp
except ImportError:
    sys.exit("pip install pyshp")

ABBR = {
    "avenue": "ave", "street": "st", "road": "rd", "drive": "dr", "boulevard": "blvd", "lane": "ln", "court": "ct",
    "place": "pl", "terrace": "ter", "parkway": "pkwy", "highway": "hwy", "circle": "cir", "square": "sq",
    "north": "n", "south": "s", "east": "e", "west": "w", "northeast": "ne", "northwest": "nw",
    "southeast": "se", "southwest": "sw", "saint": "st", "mount": "mt", "fort": "ft", "route": "rte",
    "trail": "trl", "way": "way", "alley": "aly", "expressway": "expy", "freeway": "fwy", "turnpike": "tpke",
}
NORM_TESTS = {
    "North Charles Street": "n charles st",
    "N Charles St": "n charles st",
    "St. Paul Street": "st paul st",
    "Saint Paul St": "st paul st",
    "36th Street": "36th st",
    "Mount Royal Avenue": "mt royal ave",
}


def norm(name: str) -> str:
    t = re.sub(r"[^a-z0-9 ]", " ", name.lower()).split()
    return " ".join(ABBR.get(w, w) for w in t)


def fnv1a(s: str) -> int:
    h = 0x811C9DC5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def hn(s):
    m = re.match(r"\d+", s or "")
    return int(m.group()) if m else None


def side(rec, s):
    lo, hi = hn(rec[s + "FROMHN"]), hn(rec[s + "TOHN"])
    if lo is None or hi is None:
        return None
    if lo > hi:
        lo, hi = hi, lo
    return [lo, hi, rec["PARITY" + s] or "B", rec["ZIP" + s] or ""]


def encode_geometry(points):
    pts = [(round(x * 1e6), round(y * 1e6)) for x, y in points]
    out = [pts[0][0], pts[0][1]]
    for i in range(1, len(pts)):
        out += [pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]]
    return out


PLACE_SUFFIX = re.compile(r"\s+(city and borough|city|town|village|borough|municipality|cdp)$", re.I)


def zip_places(work: str, zips: set) -> dict:
    """ZIP -> place names ordered by how much of the ZIP each place covers."""
    dest = os.path.join(work, "zcta_place.txt")
    fetch("https://www2.census.gov/geo/docs/maps-data/data/rel2020/zcta520/tab20_zcta520_place20_natl.txt", dest)
    acc = {}
    with open(dest, encoding="utf-8-sig") as fh:
        cols = fh.readline().rstrip("\n").split("|")
        iz, ip, ia = cols.index("GEOID_ZCTA5_20"), cols.index("NAMELSAD_PLACE_20"), cols.index("AREALAND_PART")
        for line in fh:
            f = line.rstrip("\n").split("|")
            if len(f) <= ia or f[iz] not in zips or not f[ip]:
                continue
            name = PLACE_SUFFIX.sub("", f[ip]).strip()
            try:
                area = int(f[ia] or 0)
            except ValueError:
                area = 0
            acc.setdefault(f[iz], {})
            acc[f[iz]][name] = acc[f[iz]].get(name, 0) + area
    return {z: [n for n, _ in sorted(v.items(), key=lambda kv: -kv[1])][:6] for z, v in acc.items()}


def fetch(url: str, dest: str):
    """Download with retries; a zip that does not open is thrown away and fetched again."""
    ok = lambda p: os.path.exists(p) and os.path.getsize(p) > 0 and (not p.endswith(".zip") or zipfile.is_zipfile(p))
    if ok(dest):
        return
    for attempt in range(1, 6):
        print("downloading", url, f"(try {attempt})")
        try:
            urllib.request.urlretrieve(url, dest)
        except Exception as e:  # network hiccup: wait and retry
            print("  failed:", e)
        if ok(dest):
            return
        if os.path.exists(dest):
            os.remove(dest)
        time.sleep(3 * attempt)
    raise RuntimeError("could not download " + url)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("abbr")
    ap.add_argument("fips")
    ap.add_argument("--year", default="2025")
    ap.add_argument("--out")
    ap.add_argument("--work", default="tiger_work")
    a = ap.parse_args()
    for k, v in NORM_TESTS.items():
        assert norm(k) == v, (k, norm(k), v)
    os.makedirs(a.work, exist_ok=True)
    base = f"https://www2.census.gov/geo/tiger/TIGER{a.year}/ADDRFEAT/"
    listing = urllib.request.urlopen(base).read().decode("utf-8", "ignore")
    files = sorted(set(re.findall(rf"tl_{a.year}_{a.fips}\d{{3}}_addrfeat\.zip", listing)))
    print(len(files), "county files")
    edges = []
    for f in files:
        # The Census server sometimes rejects one county file ("Request Rejected")
        # for good; address ranges change slowly, so an earlier release will do.
        dest = None
        for y in [a.year, "2024", "2023", "2022"]:
            name = f.replace(f"_{a.year}_", f"_{y}_")
            try:
                fetch(f"https://www2.census.gov/geo/tiger/TIGER{y}/ADDRFEAT/{name}", os.path.join(a.work, name))
                dest, f = os.path.join(a.work, name), name
                if y != a.year:
                    print("  using the", y, "release for", name)
                break
            except RuntimeError:
                continue
        if dest is None:
            raise RuntimeError("no release has " + f)
        county = f.split("_")[2]
        with zipfile.ZipFile(dest) as z:
            stem = f[:-4]
            z.extractall(a.work)
        extracted = [os.path.join(a.work, n) for n in os.listdir(a.work) if n.startswith(stem + ".")]
        rd = shapefile.Reader(os.path.join(a.work, stem))
        for sr in rd.iterShapeRecords():
            rec = sr.record.as_dict()
            left, right = side(rec, "L"), side(rec, "R")
            if not left and not right:
                continue
            if not rec["FULLNAME"] or len(sr.shape.points) < 2:
                continue
            edges.append([norm(rec["FULLNAME"]), rec["FULLNAME"], county, left, right, encode_geometry(sr.shape.points)])
        rd.close()
        for x in extracted:  # keep only the zip; the unpacked shapefile is several times bigger
            os.remove(x)
    print(len(edges), "edges with address ranges")
    n = 16
    while n < len(edges) / 2500:
        n *= 2
    shards = [[] for _ in range(n)]
    for e in edges:
        shards[fnv1a(e[0]) % n].append(e)
    payloads = [gzip.compress(json.dumps(s, separators=(",", ":")).encode("utf-8"), 6) for s in shards]
    table, off = [], 0
    for p in payloads:
        table.append([off, len(p)])
        off += len(p)
    zips = {z for e in edges for sd in (e[3], e[4]) if sd and sd[3] for z in [sd[3]]}
    zc = zip_places(a.work, zips)
    print(len(zips), "ZIPs,", len(zc), "with place names")
    header = json.dumps({"state": a.abbr, "year": a.year, "shards": n, "table": table, "zipCity": zc}, separators=(",", ":")).encode("utf-8")
    out = a.out or f"geocode_{a.abbr}.bin"
    with open(out, "wb") as fh:
        fh.write(b"CMGEO001" + struct.pack("<I", len(header)) + header)
        for p in payloads:
            fh.write(p)
    print(out, round(os.path.getsize(out) / 1e6, 1), "MB,", n, "shards")


if __name__ == "__main__":
    main()
