"""
Module 1 — Parameter Space Definition
======================================
Defines and enumerates the complete valid parameter space for
CRYSTALS-Kyber optimization.

Fixed constants (NTT constraints, non-negotiable):
  n = 256   polynomial degree
  q = 3329  modulus (= 13·256 + 1, smallest NTT-friendly prime for n=256)

Free parameters and search bounds:
  k    ∈ {2, 3, 4}            module rank
  η1   ∈ {1, 2, 3, 4, 5}     key-generation noise
  η2   ∈ {1, 2, 3}           encryption noise
  du   ∈ {8, 9, 10, 11, 12}  u-compression bits (of 12)
  dv   ∈ {3, 4, 5, 6}        v-compression bits (of 12)

Total combinations: 3 × 5 × 3 × 5 × 4 = 900
"""

import itertools
import json
from pathlib import Path

# ── Fixed constants ────────────────────────────────────────────────────────
N = 256
Q = 3329

# ── Parameter ranges ───────────────────────────────────────────────────────
PARAM_RANGES = {
    "k":    [2, 3, 4],
    "eta1": [1, 2, 3, 4, 5],
    "eta2": [1, 2, 3],
    "du":   [8, 9, 10, 11, 12],
    "dv":   [3, 4, 5, 6],
}

# Why these bounds — referenced in Section 3.3 of the thesis
PARAM_JUSTIFICATION = {
    "k":    ("k=1 is far below every tier's security threshold (39-44 bits); "
             "k>=5 exceeds NIST Level V with no practical benefit."),
    "eta1": ("eta1=0 removes the noise (instance solvable by linear algebra); "
             "larger eta1 only increases delta."),
    "eta2": ("eta2=0 removes the noise; larger eta2 only increases delta."),
    "du":   ("du=12 is (near) lossless for q=3329. No du=8 configuration is "
             "feasible at any tier, so du<8 cannot be feasible either."),
    "dv":   ("dv>6 only enlarges the ciphertext. The smallest feasible dv=3 "
             "ciphertext minus the at most 64 bytes saved by dv<3 never beats "
             "the smallest ciphertext found at any tier."),
}


# ── Size formulas (exact, FIPS 203) ───────────────────────────────────────
def compute_sizes(k: int, du: int, dv: int) -> dict:
    """Compute public key, secret key, and ciphertext sizes in bytes."""
    return {
        "pk_bytes": 384 * k + 32,
        "sk_bytes": 768 * k + 96,
        "ct_bytes": 32 * (du * k + dv),
    }


# ── Enumeration ───────────────────────────────────────────────────────────
def enumerate_space() -> list[dict]:
    """
    Generate all 900 valid parameter combinations.
    Returns a list of dicts with parameters + analytically computed sizes.
    """
    candidates = []
    for k, eta1, eta2, du, dv in itertools.product(
        PARAM_RANGES["k"],
        PARAM_RANGES["eta1"],
        PARAM_RANGES["eta2"],
        PARAM_RANGES["du"],
        PARAM_RANGES["dv"],
    ):
        entry = {"k": k, "eta1": eta1, "eta2": eta2, "du": du, "dv": dv}
        entry.update(compute_sizes(k, du, dv))
        candidates.append(entry)
    return candidates


# ── Summary statistics ────────────────────────────────────────────────────
def summarise(candidates: list[dict]) -> dict:
    cts = [c["ct_bytes"] for c in candidates]
    pks = [c["pk_bytes"] for c in candidates]
    sks = [c["sk_bytes"] for c in candidates]
    kyber512_ct = compute_sizes(2, 10, 4)["ct_bytes"]   # = 768

    smaller_than_kyber512 = sum(
        1 for c in candidates if c["ct_bytes"] < kyber512_ct
    )
    return {
        "total":                    len(candidates),
        "ct_min_bytes":             min(cts),
        "ct_max_bytes":             max(cts),
        "ct_kyber512_bytes":        kyber512_ct,
        "candidates_smaller_than_kyber512": smaller_than_kyber512,
        "pk_min_bytes":             min(pks),
        "pk_max_bytes":             max(pks),
        "sk_min_bytes":             min(sks),
        "sk_max_bytes":             max(sks),
    }


# ── Main ──────────────────────────────────────────────────────────────────
def run() -> list[dict]:
    print("=" * 60)
    print("  MODULE 1 — PARAMETER SPACE DEFINITION")
    print("=" * 60)

    print(f"\n  Fixed:  n = {N},  q = {Q}")
    print("\n  Free parameters and bounds:")
    for name, values in PARAM_RANGES.items():
        print(f"    {name:<5}  {values}")

    candidates = enumerate_space()
    stats      = summarise(candidates)

    print(f"\n  Total combinations enumerated:  {stats['total']}")
    print(f"  Ciphertext range:               "
          f"{stats['ct_min_bytes']}–{stats['ct_max_bytes']} bytes")
    print(f"  Kyber-512 ciphertext:           "
          f"{stats['ct_kyber512_bytes']} bytes  (reference point)")
    print(f"  Candidates smaller than Kyber-512 ct:  "
          f"{stats['candidates_smaller_than_kyber512']}")
    print(f"  Public key range:               "
          f"{stats['pk_min_bytes']}–{stats['pk_max_bytes']} bytes")
    print(f"  Secret key range:               "
          f"{stats['sk_min_bytes']}–{stats['sk_max_bytes']} bytes")

    # Persist to results/
    out_path = Path("results") / "parameter_space.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({
            "meta": {
                "n": N,
                "q": Q,
                "param_ranges": PARAM_RANGES,
                "justification": PARAM_JUSTIFICATION,
            },
            "stats":      stats,
            "candidates": candidates,
        }, f, indent=2)

    print(f"\n  Saved → {out_path}")
    print("=" * 60)
    print("  MODULE 1 COMPLETE")
    print("=" * 60)

    return candidates


if __name__ == "__main__":
    run()