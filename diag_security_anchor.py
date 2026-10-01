"""
diag_security_anchor.py — confirm the estimator's ADPS16 matches the
reference (spec Table 4) BEFORE we bake a threshold into Module 2.
=====================================================================

Reference security (from your Kyber.py run = spec Table 4, classical):
    Kyber-512  : primal 118, dual 117   -> min 117
    Kyber-768  : primal 183, dual 181   -> min 181
    Kyber-1024 : primal 256, dual 253   -> min 253

This script runs the estimator the CORRECT way and prints ADPS16 and
MATZOV next to those reference numbers, so we see the gap explicitly.

Correct security modelling (confirmed from the reference Kyber.py/MLWE):
    * public-key instance:  Xs = Xe = CBD(eta1)   (ks == ke in the ref)
    * samples available  :  m = (k+1)*n           (spec 5.1.1)
    * exclude arora-gb, bkw (spec rules them out)

Run in WSL (SageMath + estimator):
    python diag_security_anchor.py
"""

import math
from estimator import LWE, ND, RC
from sage.all import RR

N, Q = 256, 3329
DENY = ["arora-gb", "bkw"]

REFERENCE = {   # classical, from the spec's own script (Table 4)
    "Kyber-512":  (2, 3, 117),
    "Kyber-768":  (3, 2, 181),
    "Kyber-1024": (4, 2, 253),
}

MODELS = {"ADPS16": RC.ADPS16, "MATZOV": RC.MATZOV}


def security(k, eta1, model, m_mode):
    """Public-key instance security under a given cost model."""
    if m_mode == "(k+1)n":
        m = (k + 1) * N
    elif m_mode == "kn":
        m = k * N
    else:
        m = float("inf")
    params = LWE.Parameters(
        n=N * k, q=Q,
        Xs=ND.CenteredBinomial(eta1),
        Xe=ND.CenteredBinomial(eta1),   # pk instance: Xs == Xe
        m=m,
    )
    res = LWE.estimate(params, red_cost_model=model, deny_list=DENY,
                       jobs=1, catch_exceptions=True, quiet=True)
    costs = {}
    for name, v in res.items():
        if isinstance(v, Exception):
            continue
        try:
            rop = float(RR(v["rop"]))
            if rop > 0 and not math.isinf(rop):
                costs[name] = math.log2(rop)
        except Exception:
            continue
    return min(costs.values()), min(costs, key=costs.get)


print("=" * 70)
print("  SECURITY ANCHOR CHECK — estimator vs reference (spec Table 4)")
print("=" * 70)

for m_mode in ["(k+1)n", "kn", "inf"]:
    print(f"\n  ── samples m = {m_mode} ──")
    print(f"  {'config':<12}{'reference':>11}{'ADPS16':>18}{'MATZOV':>18}")
    print("  " + "-" * 58)
    for name, (k, eta1, ref) in REFERENCE.items():
        row = f"  {name:<12}{ref:>11}"
        for mlabel, model in MODELS.items():
            b, atk = security(k, eta1, model, m_mode)
            row += f"{b:>12.1f} ({atk[:4]})"
        print(row)

print("\n" + "=" * 70)
print("  What to look for:")
print("  * ADPS16 should land within ~3 bits of the reference classical")
print("    column (that is the spec's own Core-SVP model).")
print("  * m mode should barely matter (estimator optimizes internally).")
print("  * MATZOV will be higher (newer, different cost model) — that is")
print("    the point of having it as the independent second model.")
print("  Once ADPS16 ~ reference is confirmed, the security anchor is")
print("  trustworthy and we bake the ADPS16 threshold into Module 2.")
print("=" * 70)
