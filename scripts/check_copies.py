#!/usr/bin/env python3
"""Fails if the copies of _shared/fleet_pricing.ts inside the Edge Function folders differ.

An Edge Function deploys from its own folder, so create-checkout-session/ and
stripe-webhook/ each hold a copy of supabase/functions/_shared/fleet_pricing.ts.
Edit the _shared one, copy it over, and run this before deploying.
"""
import pathlib, sys
root = pathlib.Path(__file__).resolve().parent.parent / "supabase" / "functions"
src = (root / "_shared" / "fleet_pricing.ts").read_bytes().replace(b"\r\n", b"\n")
bad = [d for d in ("create-checkout-session", "stripe-webhook")
       if (root / d / "fleet_pricing.ts").read_bytes().replace(b"\r\n", b"\n") != src]
if bad:
    print("DIFFERENT COPIES in:", ", ".join(bad)); sys.exit(1)
print("copies equal")
