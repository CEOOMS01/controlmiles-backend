"""Builds the Fleet import migration from a COPY-format data dump of the gig project.

Selects ONLY what belongs to Fleet: every organization, its members' accounts (auth.users, identities,
profiles, onboarding) and every row that carries one of those organization ids (plus the two child tables
that have no organization column). Gig personal trips and everything else are left out.
Writes a SQL file (local only: it holds emails and password hashes) and prints counts, no values.
"""
import re
import sys

src, dst = sys.argv[1], sys.argv[2]

blocks = {}  # "schema.table" -> (cols, rows)
cur = None
with open(src, encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if cur is None:
            m = re.match(r'^COPY "([^"]+)"\."([^"]+)" \((.*)\) FROM stdin;$', line)
            if m:
                cols = [c.strip().strip('"') for c in m.group(3).split(",")]
                cur = (m.group(1) + "." + m.group(2), cols, [])
        else:
            if line == r"\.":
                blocks[cur[0]] = (cur[1], cur[2])
                cur = None
            else:
                cur[2].append(line.split("\t"))


def col(tbl, name):
    return blocks[tbl][0].index(name)


def rows_where(tbl, colname, values):
    if tbl not in blocks or colname not in blocks[tbl][0]:
        return []
    i = col(tbl, colname)
    return [r for r in blocks[tbl][1] if r[i] in values]


orgs = {r[col("public.organizations", "id")] for r in blocks["public.organizations"][1]}
members = blocks["public.organization_members"][1]
users = {r[col("public.organization_members", "user_id")] for r in members}

selected = {}  # table -> rows (in COPY text form)
selected["auth.users"] = rows_where("auth.users", "id", users)
selected["auth.identities"] = rows_where("auth.identities", "user_id", users)
selected["public.profiles"] = rows_where("public.profiles", "id", users)
selected["public.user_onboarding"] = rows_where("public.user_onboarding", "user_id", users)
selected["public.organizations"] = rows_where("public.organizations", "id", orgs)

SKIP = {"public.organizations", "public.audit_events"}  # organizations done above; audit stays with gig
for tbl, (cols, rows) in blocks.items():
    if tbl in selected or tbl in SKIP or not tbl.startswith("public.") or "organization_id" not in cols:
        continue
    picked = rows_where(tbl, "organization_id", orgs)
    if picked:
        selected[tbl] = picked

# Child tables without an organization column
ev_ids = {r[col("public.ds_evaluations", "id")] for r in selected.get("public.ds_evaluations", [])}
if ev_ids:
    selected["public.ds_evaluation_scores"] = rows_where("public.ds_evaluation_scores", "evaluation_id", ev_ids)
blk_ids = {r[col("public.shift_blocks", "id")] for r in selected.get("public.shift_blocks", [])}
if blk_ids and "public.ds_reminders_sent" in blocks:
    sent = rows_where("public.ds_reminders_sent", "shift_block_id", blk_ids)
    if sent:
        selected["public.ds_reminders_sent"] = sent

# The owner account was a gig account that also owned these organizations; in Fleet it is a fleet admin.
pi = col("public.profiles", "account_type")
owner_ids = {r[col("public.organization_members", "user_id")] for r in members if r[col("public.organization_members", "member_role")] == "owner"}
idi = col("public.profiles", "id")
for r in selected["public.profiles"]:
    if r[idi] in owner_ids and r[pi] == "gig":
        r[pi] = "fleet_admin"

UNESC = {"\\\\": "\\", "\\n": "\n", "\\t": "\t", "\\r": "\r", "\\b": "\b", "\\f": "\f", "\\v": "\v"}


def lit(v):
    if v == r"\N":
        return "NULL"
    v = re.sub(r"\\[\\ntrbfv]", lambda m: UNESC[m.group(0)], v)
    return "'" + v.replace("'", "''") + "'"


out = [
    "-- Fleet import (2026-11-16): the organizations, accounts and data that belong to Fleet, copied from the",
    "-- old shared project. Verbatim rows; triggers are off for the copy so nothing is renumbered or re-created.",
    "set local session_replication_role = replica;",
]
order = ["auth.users", "auth.identities", "public.profiles", "public.user_onboarding", "public.organizations"]
order += sorted(t for t in selected if t not in order)
for tbl in order:
    rows = selected.get(tbl, [])
    if not rows:
        continue
    cols = blocks[tbl][0]
    schema, name = tbl.split(".")
    out.append(f'insert into "{schema}"."{name}" ({", ".join(chr(34) + c + chr(34) for c in cols)}) values')
    out.append(",\n".join("(" + ", ".join(lit(v) for v in r) + ")" for r in rows) + ";")

out += [
    "-- Classes keep the location of their car or instructor (the column is new in Fleet).",
    "update public.shift_blocks b set branch_id = coalesce((select v.branch_id from public.vehicles v where v.id = b.vehicle_id),",
    "  (select m.branch_id from public.organization_members m where m.organization_id = b.organization_id and m.user_id = b.driver_id and m.is_active limit 1))",
    " where b.branch_id is null;",
]
open(dst, "w", encoding="utf-8").write("\n".join(out) + "\n")

print("organizations:", len(orgs), "| accounts:", len(users))
for t in order:
    if selected.get(t):
        print(f"  {t}: {len(selected[t])}")
print("file bytes:", sum(len(x) for x in out))
