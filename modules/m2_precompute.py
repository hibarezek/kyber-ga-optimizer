"""
Module 2 — Coupled Precomputation (two-instance security, baseline-agnostic)
=============================================================================
For every candidate (k, eta1, eta2, du, dv) this computes and stores the
RAW quantities needed to judge feasibility -- but does NOT bake in a
feasibility decision, because "feasible" depends on which standard
parameter set (Kyber-512 / 768 / 1024) you are comparing against, and
this module is run once, not once per baseline.

Stored per candidate:
  * log2_delta       -- via the pq-crystals REFERENCE implementation
                         (spec-exact), NOT the custom fixed-point model.
  * security         -- min(pk-instance, ct-instance), ADPS16 (primary)
  * security_pk      -- pk-instance alone, ADPS16
  * security_ct      -- ct-instance alone, ADPS16
  * security_matzov  -- min(pk-instance, ct-instance), MATZOV (secondary,
                         independent cross-check model; NOT a gate)
  * sizes            -- pk / sk / ct bytes

Two MLWE instances, same cost model each (spec Section 5.1):
  public-key instance : Xs=CBD(eta1), Xe=CBD(eta1)  (key recovery)
  ciphertext instance : Xs=CBD(eta1), Xe=CBD(eta2)  (message recovery)
Concrete security = min of the two: the scheme is only as strong as its
weaker attack surface.

Feasibility against a SPECIFIC baseline (512/768/1024) is computed by
`modules/feasibility.py`, using these raw values -- not here. This keeps
the (slow, SageMath-dependent) precomputation to a single run, while
letting Modules 3-5 be re-run cheaply against any of the three tiers.

Run in WSL (SageMath + estimator + vendored reference/):
    python modules/m2_precompute.py
"""

import sys
import os
import json
import time
import math
import itertools
from pathlib import Path

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _THIS_DIR)
sys.path.insert(0, os.path.dirname(_THIS_DIR))

N = 256
Q = 3329

PARAM_RANGES = {
    "k":    [2, 3, 4],
    "eta1": [1, 2, 3, 4, 5],
    "eta2": [1, 2, 3],
    "du":   [8, 9, 10, 11, 12],
    "dv":   [3, 4, 5, 6],
}

OUTPUT_PATH = Path("results") / "lookup_table.json"

import modules.reference.reference_delta as reference_delta

from estimator import LWE, ND, RC
from sage.all import RR as SageRR

PRIMARY_MODEL   = RC.ADPS16
SECONDARY_MODEL = RC.MATZOV
DENY = ["arora-gb", "bkw"]


def _instance_security(eta_s, eta_e, k, model):
    """log2 attack cost of one MLWE instance (min over all attacks the
    estimator runs, excluding DENY). Raises if the estimator returns no
    usable result -- callers should NOT silently swallow this (see the
    open MATZOV-direction question in the project's model reference doc:
    catch_exceptions=True elsewhere in this codebase may have hidden a
    real issue -- kept strict here on purpose)."""
    params = LWE.Parameters(
        n=N * k, q=Q,
        Xs=ND.CenteredBinomial(eta_s),
        Xe=ND.CenteredBinomial(eta_e),
        m=(k + 1) * N,
    )
    res = LWE.estimate(params, red_cost_model=model, deny_list=DENY,
                       jobs=1, catch_exceptions=False, quiet=True)
    costs = []
    for v in res.values():
        if isinstance(v, Exception):
            continue
        rop = float(SageRR(v["rop"]))
        if rop > 0 and not math.isinf(rop):
            costs.append(math.log2(rop))
    if not costs:
        raise ValueError(f"No valid rop values for eta_s={eta_s}, eta_e={eta_e}, k={k}")
    return min(costs)


def security_min_of_two(k, eta1, eta2, model):
    pk = _instance_security(eta1, eta1, k, model)
    ct = _instance_security(eta1, eta2, k, model)
    return min(pk, ct), pk, ct


def compute_sizes(k, du, dv):
    return {"pk_bytes": 384 * k + 32,
            "sk_bytes": 768 * k + 96,
            "ct_bytes": 32 * (du * k + dv)}


def run():
    print("=" * 68)
    print("  MODULE 2 -- COUPLED PRECOMPUTATION (baseline-agnostic)")
    print("  delta      : pq-crystals reference (spec-exact)")
    print("  security   : min(pk-instance, ct-instance)")
    print(f"  primary    : ADPS16 (Core-SVP)   secondary: MATZOV")
    print("=" * 68)

    candidates = list(itertools.product(
        PARAM_RANGES["k"], PARAM_RANGES["eta1"], PARAM_RANGES["eta2"],
        PARAM_RANGES["du"], PARAM_RANGES["dv"]))
    total = len(candidates)
    print(f"\n  processing {total} candidates\n")

    sec_cache = {}
    lookup = {}
    t0 = time.time()

    for i, (k, eta1, eta2, du, dv) in enumerate(candidates, 1):
        key = f"{k},{eta1},{eta2},{du},{dv}"

        sk = (k, eta1, eta2)
        if sk not in sec_cache:
            prim, prim_pk, prim_ct = security_min_of_two(k, eta1, eta2, PRIMARY_MODEL)
            seco, _, _             = security_min_of_two(k, eta1, eta2, SECONDARY_MODEL)
            sec_cache[sk] = {
                "security": prim, "security_pk": prim_pk,
                "security_ct": prim_ct, "security_matzov": seco,
            }
        sec = sec_cache[sk]

        log2_delta = reference_delta.reference_log2_delta(k, eta1, eta2, du, dv)
        sizes = compute_sizes(k, du, dv)

        lookup[key] = {
            "k": k, "eta1": eta1, "eta2": eta2, "du": du, "dv": dv,
            "security":        sec["security"],
            "security_pk":     sec["security_pk"],
            "security_ct":     sec["security_ct"],
            "security_matzov": sec["security_matzov"],
            "log2_delta":      log2_delta,
            **sizes,
        }

        if i % 25 == 0 or i == total:
            el = time.time() - t0
            print(f"  [{i:>3}/{total}] cached triples: {len(sec_cache)}/45  | {el:.0f}s")

    meta = {
        "n_candidates": total,
        "delta_source": "pq-crystals reference (Kyber_failure.py)",
        "security_model": "min of two MLWE instances (pk, ct), ADPS16 primary",
        "security_secondary": "MATZOV",
        "samples_m": "(k+1)*n",
        "note": "No feasibility baked in -- baseline-dependent, see modules/feasibility.py",
    }
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump({"meta": meta, "candidates": lookup}, f, indent=2)

    print(f"\n  saved -> {OUTPUT_PATH}")
    print("=" * 68)


if __name__ == "__main__":
    run()
