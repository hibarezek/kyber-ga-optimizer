"""
diag_security.py — is security(P4) == security(Kyber-512) real, or an artifact?
==============================================================================

The dominance claim rests on an EQUALITY:

    P4        = (k=2, eta1=2, eta2=2, du=10, dv=4)   ct=768  delta=2^-246
    Kyber-512 = (k=2, eta1=3, eta2=2, du=10, dv=4)   ct=768  delta=2^-142

Both report 132.84 bits. But these are DIFFERENT LWE instances:
    Kyber-512 -> Xs=CBD(3), Xe=CBD(2)
    P4        -> Xs=CBD(2), Xe=CBD(2)

A wider secret should be harder. So why identical? Two hypotheses:

  H1. The binding attack in min(costs) does not depend on Xs, so eta1
      never moves the reported number.
  H2. They genuinely differ, but round(security_bits, 2) hides it.

This script tests both: it prints EVERY attack's cost at FULL precision,
for both configurations, under several reduction cost models.

Context (Kyber spec v3.0, "Changes to the core Kyber design"):
    round-2 Kyber512 = (2, 2, 2, 10, 3) = 736 B   <- this is our P3
    round-3 Kyber512 = (2, 3, 2, 10, 4) = 768 B
The team raised eta1 from 2 to 3 because of "requests to increase the
Core-SVP hardness of this parameter set". If eta1 is security-relevant to
them and inert in our estimator, we need to know why.

Run in WSL with SageMath + estimator active:
    python diag_security.py
"""

import math

from estimator import LWE, ND, RC
from sage.all import RR as SageRR

N, Q = 256, 3329

CONFIGS = {
    "Kyber-512 (round-3)": dict(k=2, eta1=3, eta2=2),
    "P4  (eta1=2)":        dict(k=2, eta1=2, eta2=2),
}

# Cost models to compare. ADPS16 is the Core-SVP model the Kyber spec uses
# (its Table 4 reports 118 classical / 107 quantum for Kyber-512).
COST_MODELS = {
    "MATZOV (current default)": RC.MATZOV,
    "ADPS16 (Core-SVP, spec)":  RC.ADPS16,
    "BDGL16":                   RC.BDGL16,
    "CheNgu12":                 RC.CheNgu12,
}

DENY = ["arora-gb", "bkw"]


def ct_instance(k, eta1, eta2):
    """Ciphertext MLWE instance: u = A^T r + e1, r~CBD(eta1), e1~CBD(eta2)."""
    return LWE.Parameters(n=N * k, q=Q,
                          Xs=ND.CenteredBinomial(eta1),
                          Xe=ND.CenteredBinomial(eta2))


def pk_instance(k, eta1):
    """Public-key MLWE instance: t = As + e, both s,e ~ CBD(eta1)."""
    return LWE.Parameters(n=N * k, q=Q,
                          Xs=ND.CenteredBinomial(eta1),
                          Xe=ND.CenteredBinomial(eta1))


def costs_by_attack(params, red_cost_model):
    """Return {attack_name: log2(rop)} at full precision."""
    res = LWE.estimate(params, red_cost_model=red_cost_model,
                       deny_list=DENY, jobs=1,
                       catch_exceptions=True, quiet=True)
    out = {}
    for name, v in res.items():
        if isinstance(v, Exception):
            continue
        try:
            rop = float(SageRR(v["rop"]))
            if rop > 0 and not math.isinf(rop):
                out[name] = math.log2(rop)
        except Exception:
            continue
    return out


def main():
    for model_name, model in COST_MODELS.items():
        print("=" * 74)
        print(f"  COST MODEL: {model_name}")
        print("=" * 74)

        per_config = {}
        for label, cfg in CONFIGS.items():
            ct = costs_by_attack(ct_instance(**cfg), model)
            pk = costs_by_attack(pk_instance(cfg["k"], cfg["eta1"]), model)
            per_config[label] = (ct, pk)

        attacks = sorted(set().union(*[c.keys() for c, _ in per_config.values()]))

        # ── ciphertext instance (what Module 2 currently estimates) ──
        print("\n  CIPHERTEXT instance  [Xs=CBD(eta1), Xe=CBD(eta2)]"
              "  <- the only one Module 2 computes")
        print(f"    {'attack':<16}" + "".join(f"{l:>24}" for l in CONFIGS))
        print("    " + "-" * (16 + 24 * len(CONFIGS)))
        for a in attacks:
            row = f"    {a:<16}"
            for label in CONFIGS:
                v = per_config[label][0].get(a)
                row += f"{v:>24.6f}" if v is not None else f"{'-':>24}"
            print(row)

        mins_ct = {l: (min(c.values()) if c else float('nan'))
                   for l, (c, _) in per_config.items()}
        binder  = {l: (min(c, key=c.get) if c else "-")
                   for l, (c, _) in per_config.items()}
        print("    " + "-" * (16 + 24 * len(CONFIGS)))
        print(f"    {'MIN':<16}" + "".join(f"{mins_ct[l]:>24.6f}" for l in CONFIGS))
        print(f"    {'binding attack':<16}" + "".join(f"{binder[l]:>24}" for l in CONFIGS))

        # ── public-key instance (currently NEVER estimated) ──
        print("\n  PUBLIC-KEY instance  [Xs=Xe=CBD(eta1)]"
              "  <- Module 2 never computes this")
        mins_pk = {l: (min(p.values()) if p else float('nan'))
                   for l, (_, p) in per_config.items()}
        print(f"    {'MIN':<16}" + "".join(f"{mins_pk[l]:>24.6f}" for l in CONFIGS))

        # ── verdict ──
        print("\n  VERDICT")
        labels = list(CONFIGS)
        d_ct = mins_ct[labels[0]] - mins_ct[labels[1]]
        print(f"    ct-instance gap (Kyber-512 - P4): {d_ct:+.6f} bits")
        print(f"    -> rounds to 2dp as: {round(mins_ct[labels[0]],2)} vs "
              f"{round(mins_ct[labels[1]],2)}"
              f"   {'IDENTICAL (rounding hides nothing / or nothing to hide)' if round(mins_ct[labels[0]],2)==round(mins_ct[labels[1]],2) else 'DIFFERENT'}")
        if abs(d_ct) < 1e-9:
            print("    -> EXACTLY equal: eta1 is INERT under this model.")
            print("       H1 CONFIRMED: the binding attack ignores Xs.")
            print("       The 'equivalent security' claim is an artifact.")
        else:
            print(f"    -> They differ by {abs(d_ct):.6f} bits."
                  f"  {'Kyber-512 stronger' if d_ct > 0 else 'P4 stronger'}")
            if abs(d_ct) < 0.005:
                print("       H2: real but hidden by round(.,2) in m2_precompute.py:255.")

        true_min = {l: min(mins_ct[l], mins_pk[l]) for l in labels}
        print(f"\n    min(pk, ct) — the CORRECT security:")
        for l in labels:
            print(f"      {l:<24} {true_min[l]:.6f}"
                  f"   (ct={mins_ct[l]:.4f}, pk={mins_pk[l]:.4f})")
        d_true = true_min[labels[0]] - true_min[labels[1]]
        print(f"    correct gap (Kyber-512 - P4): {d_true:+.6f} bits")
        if d_true > 0.005:
            print("    *** Kyber-512 is MEASURABLY STRONGER than P4.")
            print("        The dominance claim does NOT hold under this model.")
        print()

    print("=" * 74)
    print("  Spec cross-check: ADPS16 should give ~118 classical Core-SVP")
    print("  for Kyber-512 (spec Table 4). If it does, the security pipeline")
    print("  is validated against the specification for the first time.")
    print("=" * 74)


if __name__ == "__main__":
    main()
