"""
model_checks.py -- checks on the security model and search-space bounds
=======================================================================
Reproduces the supporting numbers of Chapters 4 and 5 that are not
produced by Modules 0-5 themselves:

  1. MATZOV cross-check : feasible-set sizes and Pareto fronts under the
                          secondary cost model (each tier's threshold is
                          that tier's own MATZOV value).
  2. Instance models    : what a pk-instance-only or ct-instance-only
                          security model would accept (Table 4.2).
  3. Boundary checks    : du = 8 never feasible; minimum feasible dv = 3
                          ciphertext per tier.

Uses only results/lookup_table.json (no SageMath needed).
Run from the repository root:
    python analysis/model_checks.py
"""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "modules"))
os.chdir(_ROOT)

from feasibility import (load_lookup, feasible_set, baseline_threshold,
                         baseline_key, DELTA_CEILING)
from m4_validate import brute_force_front

TIERS = ["Kyber-512", "Kyber-768", "Kyber-1024"]


def front_of(lookup, keys):
    return set(brute_force_front({k: lookup[k] for k in keys}))


def feasible_with(lookup, tier, field):
    thr = lookup[baseline_key(tier)][field]
    return {k for k, v in lookup.items()
            if v[field] >= thr and v["log2_delta"] <= DELTA_CEILING}


def main():
    L = load_lookup("results/lookup_table.json")

    print("1. MATZOV cross-check")
    for t in TIERS:
        a = set(feasible_set(L, t, "security"))
        m = set(feasible_set(L, t, "security_matzov"))
        print(f"   {t:<10}  threshold ADPS16 {baseline_threshold(L, t):7.2f}"
              f" | MATZOV {baseline_threshold(L, t, 'security_matzov'):7.2f}"
              f" | feasible {len(a)} / {len(m)}"
              f" | same feasible set: {a == m}"
              f" | same front: {front_of(L, a) == front_of(L, m)}")
    gaps = [v["security_matzov"] - v["security"] for v in L.values()]
    print(f"   MATZOV - ADPS16 gap over all candidates: "
          f"{min(gaps):.1f} to {max(gaps):.1f} bits")

    print("\n2. Single-instance security models (ADPS16, own threshold)")
    for t in TIERS:
        true = feasible_with(L, t, "security")
        tf = front_of(L, true)
        for field in ("security_pk", "security_ct"):
            acc = feasible_with(L, t, field)
            wrong = acc - true
            f = front_of(L, acc)
            false_pts = f - tf
            min_ct = min(L[k]["ct_bytes"] for k in f)
            eta2 = sorted({k[2] for k in wrong})
            print(f"   {t:<10} {field:<12} wrongly accepted {len(wrong):>2}"
                  f" (eta2 in {eta2}) | false front points {len(false_pts)}/{len(f)}"
                  f" | min ct {min_ct}")
    thr = baseline_threshold(L, "Kyber-512")
    thr_pk = L[baseline_key("Kyber-512")]["security_pk"]
    dis = sum(1 for v in L.values()
              if (v["security_pk"] >= thr_pk) != (v["security"] >= thr))
    print(f"   pk-only vs two-instance, security gate only, Kyber-512: "
          f"{dis} of {len(L)} candidates disagree")

    print("\n3. Boundary checks")
    for t in TIERS:
        F = feasible_set(L, t)
        du8 = sum(1 for k in F if k[3] == 8)
        dv3 = [v["ct_bytes"] for k, v in F.items() if k[4] == 3]
        print(f"   {t:<10} feasible with du=8: {du8} | "
              f"min feasible ct with dv=3: {min(dv3) if dv3 else '-'}")


if __name__ == "__main__":
    main()
