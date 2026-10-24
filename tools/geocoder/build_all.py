#!/usr/bin/env python3
"""Build the geocoder data file of every U.S. state, DC and Puerto Rico, one
after the other (resumable: a state whose out/geocode_<ST>.bin exists is
skipped). Usage:  python build_all.py [--only MD,VA] [--year 2025]
Takes a few hours and several GB of downloads (kept in tiger_work/)."""
import argparse, os, subprocess, sys, time

STATES = {
    "AL": "01", "AK": "02", "AZ": "04", "AR": "05", "CA": "06", "CO": "08", "CT": "09", "DE": "10", "DC": "11",
    "FL": "12", "GA": "13", "HI": "15", "ID": "16", "IL": "17", "IN": "18", "IA": "19", "KS": "20", "KY": "21",
    "LA": "22", "ME": "23", "MD": "24", "MA": "25", "MI": "26", "MN": "27", "MS": "28", "MO": "29", "MT": "30",
    "NE": "31", "NV": "32", "NH": "33", "NJ": "34", "NM": "35", "NY": "36", "NC": "37", "ND": "38", "OH": "39",
    "OK": "40", "OR": "41", "PA": "42", "RI": "44", "SC": "45", "SD": "46", "TN": "47", "TX": "48", "UT": "49",
    "VT": "50", "VA": "51", "WA": "53", "WV": "54", "WI": "55", "WY": "56", "PR": "72",
}

ap = argparse.ArgumentParser()
ap.add_argument("--only")
ap.add_argument("--year", default="2025")
a = ap.parse_args()
here = os.path.dirname(os.path.abspath(__file__))
out_dir = os.path.join(here, "out")
os.makedirs(out_dir, exist_ok=True)
wanted = a.only.split(",") if a.only else list(STATES)
failed = []
for st in wanted:
    out = os.path.join(out_dir, f"geocode_{st}.bin")
    if os.path.exists(out):
        print(st, "already built", flush=True)
        continue
    t0 = time.time()
    print("==", st, flush=True)
    r = subprocess.run(
        [sys.executable, os.path.join(here, "build_state.py"), st, STATES[st], "--year", a.year, "--out", out, "--work", os.path.join(here, "tiger_work")],
        cwd=here,
    )
    if r.returncode != 0:
        failed.append(st)
        if os.path.exists(out):
            os.remove(out)
    print(st, "done in", round(time.time() - t0), "s", flush=True)
print("failed:", failed or "none", flush=True)
