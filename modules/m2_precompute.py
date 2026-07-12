"""Compute lookup statistics for Kyber parameter candidates."""

import json
import math
import sys
import time
from collections import defaultdict
from pathlib import Path

import mpmath as mp

mp.mp.dps = 100

try:
    from estimator import LWE, ND
    ESTIMATOR_AVAILABLE = True
except ImportError as e:
    print(f"[FATAL] lattice-estimator not found: {e}")
    print("Run inside WSL with SageMath active.")
    sys.exit(1)

N = 256
Q = 3329
LOG2_DELTA_CEILING = -64

PARAM_RANGES = {
    "k":    [2, 3, 4],
    "eta1": [1, 2, 3, 4, 5],
    "eta2": [1, 2, 3],
    "du":   [8, 9, 10, 11, 12],
    "dv":   [3, 4, 5, 6],
}


def compute_sizes(k, du, dv):
    return {
        "pk_bytes": 384 * k + 32,
        "sk_bytes": 768 * k + 96,
        "ct_bytes": 32 * (du * k + dv),
    }

PREC = 512
SCALE = 1 << PREC


def cbd_pmf(eta: int) -> dict:
    """CBD(eta) PMF as scaled integers (numerator over SCALE)."""
    denom = 4 ** eta
    return {x: (math.comb(2 * eta, eta + x) * SCALE) // denom
            for x in range(-eta, eta + 1)}


def product_pmf(pmf_a: dict, pmf_b: dict) -> dict:
    """
    PMF of product A*B, scaled-integer inputs and output.
    Two scaled probs multiply to give SCALE^2 scaling → rescale by >> PREC.
    """
    result = defaultdict(int)
    for a, pa in pmf_a.items():
        for b, pb in pmf_b.items():
            result[a * b] += (pa * pb) >> PREC
    return dict(result)


def compress_ele(x: int, d: int, q: int = Q) -> int:
    t = 1 << d
    y = ((t * x) + (q // 2)) // q
    return y % t


def decompress_ele(y: int, d: int, q: int = Q) -> int:
    half = 1 << (d - 1)
    return (q * y + half) >> d


def compression_error_pmf(d: int, q: int = Q) -> dict:
    counts = defaultdict(int)
    for x in range(q):
        xc = decompress_ele(compress_ele(x, d, q), d, q)
        err = (xc - x) % q
        if err > q // 2:
            err -= q
        counts[err] += 1
    return {e: (c * SCALE) // q for e, c in counts.items()}

FAIL_CAP = Q // 4 + 1


def convolve(pmf_a: dict, pmf_b: dict) -> dict:
    if not pmf_a:
        return dict(pmf_b)
    if not pmf_b:
        return dict(pmf_a)
    result = defaultdict(int)
    for x, px in pmf_a.items():
        for y, py in pmf_b.items():
            s = x + y
            if s > FAIL_CAP:
                s = FAIL_CAP
            elif s < -FAIL_CAP:
                s = -FAIL_CAP
            result[s] += (px * py) >> PREC
    return dict(result)


def convolve_power(pmf: dict, power: int) -> dict:
    """power-fold self-convolution via binary exponentiation (scaled int)."""
    if power == 0:
        return {0: SCALE}
    result = None
    base = dict(pmf)
    p = power
    while p > 0:
        if p & 1:
            result = base if result is None else convolve(result, base)
        p >>= 1
        if p > 0:
            base = convolve(base, base)
    return result


def compute_delta(k: int, eta1: int, eta2: int,
                  du: int, dv: int,
                  n: int = N, q: int = Q) -> float:
    cbd1 = cbd_pmf(eta1)
    cbd2 = cbd_pmf(eta2)
    cu_err = compression_error_pmf(du, q)
    cv_err = compression_error_pmf(dv, q)

    etr  = convolve_power(product_pmf(cbd1, cbd1), k * n)
    ste1 = convolve_power(product_pmf(cbd1, cbd2), k * n)
    e2   = cbd2
    stu  = convolve_power(product_pmf(cbd1, cu_err), k * n)

    total = {0: SCALE}
    for source in (etr, ste1, e2, cv_err, stu):
        total = convolve(total, source)

    threshold = q // 4

    # Sum tail mass (scaled integer), then convert to a probability
    p_fail_scaled = 0
    for x, px in total.items():
        if abs(x) > threshold:
            p_fail_scaled += px

    if p_fail_scaled <= 0:
        return float("-inf")

    # p_fail = p_fail_scaled / SCALE.  delta = 1 - (1 - p_fail)^n
    import mpmath as mp
    mp.mp.dps = 80
    p_fail = mp.mpf(p_fail_scaled) / mp.mpf(SCALE)
    delta  = 1 - (1 - p_fail) ** n
    return float(mp.log(delta, 2))
# ── Security estimation ────────────────────────────────────────────────────
def estimate_security(k: int, eta1: int, eta2: int,
                      n: int = N, q: int = Q) -> float:
    """
    Estimate bit-security via the lattice estimator.
    Cost objects returned by the estimator are dicts — access via v["rop"].
    """
    from sage.all import RR as SageRR

    params = LWE.Parameters(
        n  = n * k,
        q  = q,
        Xs = ND.CenteredBinomial(eta1),
        Xe = ND.CenteredBinomial(eta2),
    )
    result = LWE.estimate(params, jobs=1, catch_exceptions=True, deny_list=["arora-gb","bkw"])

    costs = []
    for attack_name, v in result.items():
        if isinstance(v, Exception):
            continue
        try:
            rop_val = float(SageRR(v["rop"]))
            if rop_val > 0 and not math.isinf(rop_val):
                costs.append(math.log2(rop_val))
        except Exception:
            continue

    if not costs:
        raise ValueError(
            f"No valid rop values for k={k}, eta1={eta1}, eta2={eta2}. "
            f"Keys: {list(result.keys())}"
        )

    return min(costs)


# ── Main ──────────────────────────────────────────────────────────────────
def run():
    # At the top of run(), before the main loop:
    print("  Computing security threshold from Kyber-512 baseline...")
    kyber512_security = estimate_security(k=2, eta1=3, eta2=2)
    security_threshold = kyber512_security
    print(f"  Threshold set to {kyber512_security:.2f} bits "
        f"(Core-SVP hardness of Kyber-512 under our estimator)")

    print("=" * 60)
    print("  MODULE 2 — COUPLED PRECOMPUTATION")
    print("=" * 60)

    import itertools
    candidates = list(itertools.product(
        PARAM_RANGES["k"],
        PARAM_RANGES["eta1"],
        PARAM_RANGES["eta2"],
        PARAM_RANGES["du"],
        PARAM_RANGES["dv"],
    ))

    total      = len(candidates)
    lookup     = {}
    n_feasible = 0
    t_start    = time.time()

    # Cache security by (k, eta1, eta2) — same for all du/dv combinations
    sec_cache = {}

    print(f"\n  Processing {total} candidates...\n")

    for i, (k, eta1, eta2, du, dv) in enumerate(candidates, 1):
        key = f"{k},{eta1},{eta2},{du},{dv}"

        # Security (cached per unique (k, eta1, eta2) triple)
        sec_key = (k, eta1, eta2)
        if sec_key not in sec_cache:
            try:
                sec_cache[sec_key] = estimate_security(k, eta1, eta2)
            except Exception as e:
                print(f"  [WARNING] estimator failed for {sec_key}: {e}")
                sec_cache[sec_key] = 0.0
        security_bits = sec_cache[sec_key]

        # Failure probability
        log2_delta = compute_delta(k, eta1, eta2, du, dv)

        # Sizes
        sizes = compute_sizes(k, du, dv)

        # Feasibility
        g1 = security_bits >= security_threshold
        g2 = log2_delta    <= LOG2_DELTA_CEILING
        feasible = g1 and g2
        if feasible:
            n_feasible += 1

        lookup[key] = {
            "k": k, "eta1": eta1, "eta2": eta2, "du": du, "dv": dv,
            "security_bits": round(security_bits, 2),
            "log2_delta":    round(log2_delta, 4),
            "feasible":      feasible,
            "g1_security":   g1,
            "g2_delta":      g2,
            **sizes,
        }

        # Progress
        if i % 50 == 0 or i == total:
            elapsed = time.time() - t_start
            eta_s   = (elapsed / i) * (total - i)
            print(f"  [{i:>3}/{total}]  feasible so far: {n_feasible}"
                  f"  |  elapsed: {elapsed:.0f}s"
                  f"  |  ETA: {eta_s:.0f}s")

    # Save
    out_path = Path("results") / "lookup_table.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({
            "meta": {
                "n": N, "q": Q,
                "security_threshold": security_threshold,
                "log2_delta_ceiling": LOG2_DELTA_CEILING,
                "total_candidates":   total,
                "feasible_count":     n_feasible,
            },
            "candidates": lookup,
        }, f, indent=2)

    elapsed = time.time() - t_start
    print(f"\n  Total candidates: {total}")
    print(f"  Feasible (pass both gates): {n_feasible}")
    print(f"  Infeasible (eliminated): {total - n_feasible}")
    print(f"  Elapsed: {elapsed:.1f}s")
    print(f"  Saved → {out_path}")
    print("=" * 60)
    print("  MODULE 2 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    run()