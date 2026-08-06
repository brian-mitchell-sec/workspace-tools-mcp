"""
Analyze the controlled MCP tool-description injection trials.

Reads mcp_data/injection_trials.jsonl (one row per trial: model, condition, complied,
leaked, ...). Reports, per model: injected compliance, injected leak (corrected detector),
baseline compliance, each with Wilson 95% CIs. Prints an auditable table.
"""
from __future__ import annotations
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

DATA = Path(sys.argv[1]) if len(sys.argv) > 1 else \
    Path(__file__).resolve().parent / "data" / "injection_trials.jsonl"


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z*z/n
    center = (p + z*z/(2*n)) / denom
    half = (z * math.sqrt((p*(1-p) + z*z/(4*n)) / n)) / denom
    return (p, max(0.0, center-half), min(1.0, center+half))


def fmt(k, n):
    p, lo, hi = wilson(k, n)
    return f"{k}/{n} ({p*100:.0f}%)  [{lo*100:.0f}-{hi*100:.0f}%]"


def main():
    rows = [json.loads(line) for line in DATA.read_text().splitlines() if line.strip()]
    # group by (model, condition); count only valid trials (complied is a bool)
    agg = defaultdict(lambda: {"n": 0, "complied": 0, "leaked": 0, "mentioned": 0, "err": 0})
    for r in rows:
        key = (r["model"], r["condition"])
        if r.get("complied") is None:  # errored trial
            agg[key]["err"] += 1
            continue
        a = agg[key]
        a["n"] += 1
        a["complied"] += 1 if r["complied"] else 0
        a["leaked"] += 1 if r.get("leaked") else 0
        a["mentioned"] += 1 if r.get("mentioned") else 0

    models = sorted({m for (m, c) in agg})
    print(f"\nData: {DATA}  ({len(rows)} rows total)\n")
    print(f"{'model':28} | {'INJ compliance':24} | {'INJ leak (marker)':24} | {'BASE compliance':24}")
    print("-"*110)
    for m in models:
        inj = agg.get((m, "injected"), {"n": 0, "complied": 0, "leaked": 0, "err": 0})
        base = agg.get((m, "baseline"), {"n": 0, "complied": 0, "leaked": 0, "err": 0})
        print(f"{m:28} | {fmt(inj['complied'], inj['n']):24} | "
              f"{fmt(inj['leaked'], inj['n']):24} | {fmt(base['complied'], base['n']):24}")
    print()
    # detail incl. mentioned-concept (looser, non-leak) + error counts
    print("detail (mentioned_concept = looser non-leak signal; err = errored trials):")
    for m in models:
        for c in ("injected", "baseline"):
            a = agg.get((m, c))
            if not a:
                continue
            print(f"  {m:28} {c:9} n={a['n']:3} complied={a['complied']:3} "
                  f"leaked={a['leaked']:3} mentioned={a['mentioned']:3} err={a['err']}")


if __name__ == "__main__":
    main()
