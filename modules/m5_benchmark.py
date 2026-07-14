"""
Module 5 — Benchmarking and Correctness Verification
=====================================================
Benchmarks every Pareto-optimal configuration (Module 3/4) against the
Kyber-512 baseline by instantiating each in kyber-py and measuring:

  1. SIZES        — public key, secret key, ciphertext (bytes), measured
                    from real keygen/encaps and cross-checked against
                    the analytic formulas.
  2. LATENCY      — keygen, encaps, decaps timing (mean ± std) over many
                    repetitions.
  3. MEMORY       — peak memory of a keygen+encaps+decaps cycle
                    (tracemalloc).
  4. CORRECTNESS  — Monte Carlo: N encaps/decaps cycles, counting shared-
                    secret mismatches. Confirms the implementation behaves
                    correctly; consistent with the theoretical delta.

Runs on Windows (uv) — requires only kyber-py, no SageMath.

Usage:
    uv run python modules/m5_benchmark.py
"""

import json
import time
import tracemalloc
import statistics
import sys
from pathlib import Path

from kyber_py.kyber.kyber import Kyber

FRONT_PATH  = Path("results") / "nsga2_front.json"
LOOKUP_PATH = Path("results") / "lookup_table.json"
OUTPUT_PATH = Path("results") / "benchmark.json"

# Benchmark settings
LATENCY_RUNS      = 1000    # timing repetitions per operation
MONTE_CARLO_RUNS  = 10000   # encaps/decaps cycles for correctness

# Kyber-512 baseline (standard parameters)
KYBER512_PARAMS = {"k": 2, "eta_1": 3, "eta_2": 2, "du": 10, "dv": 4}


# ── Build kyber-py parameter dict from a front config ──────────────────────
def to_kyber_params(cfg: dict) -> dict:
    """Map our (eta1, eta2) naming to kyber-py's (eta_1, eta_2)."""
    return {
        "k":     cfg["k"],
        "eta_1": cfg["eta1"],
        "eta_2": cfg["eta2"],
        "du":    cfg["du"],
        "dv":    cfg["dv"],
    }


# ── Size measurement ───────────────────────────────────────────────────────
def measure_sizes(kyber) -> dict:
    pk, sk = kyber.keygen()
    key, ct = kyber.encaps(pk)
    return {
        "pk_bytes": len(pk),
        "sk_bytes": len(sk),
        "ct_bytes": len(ct),
    }


# ── Latency measurement ────────────────────────────────────────────────────
def measure_latency(kyber, runs: int) -> dict:
    """Time keygen, encaps, decaps separately; return mean/std in ms."""
    # Keygen
    keygen_times = []
    keys = []
    for _ in range(runs):
        t0 = time.perf_counter()
        pk, sk = kyber.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)
        keys.append((pk, sk))

    # Encaps (reuse generated keys round-robin)
    encaps_times = []
    caps = []
    for i in range(runs):
        pk, _ = keys[i % len(keys)]
        t0 = time.perf_counter()
        key, ct = kyber.encaps(pk)
        encaps_times.append((time.perf_counter() - t0) * 1000)
        caps.append((key, ct))

    # Decaps
    decaps_times = []
    for i in range(runs):
        _, sk = keys[i % len(keys)]
        _, ct = caps[i % len(caps)]
        t0 = time.perf_counter()
        kyber.decaps(sk, ct)
        decaps_times.append((time.perf_counter() - t0) * 1000)

    def stats(xs):
        return {
            "mean_ms": statistics.mean(xs),
            "std_ms":  statistics.pstdev(xs),
        }

    return {
        "keygen": stats(keygen_times),
        "encaps": stats(encaps_times),
        "decaps": stats(decaps_times),
    }


# ── Memory measurement ─────────────────────────────────────────────────────
def measure_memory(kyber) -> dict:
    """Peak memory of one full keygen+encaps+decaps cycle."""
    tracemalloc.start()
    pk, sk = kyber.keygen()
    key, ct = kyber.encaps(pk)
    kyber.decaps(sk, ct)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"peak_kb": peak / 1024}


# ── Correctness (Monte Carlo) ──────────────────────────────────────────────
def measure_correctness(kyber, runs: int) -> dict:
    """Run N encaps/decaps cycles, count shared-secret mismatches."""
    failures = 0
    for _ in range(runs):
        pk, sk = kyber.keygen()
        key_bob, ct = kyber.encaps(pk)
        key_alice = kyber.decaps(sk, ct)
        if key_alice != key_bob:
            failures += 1
    return {
        "runs":     runs,
        "failures": failures,
    }


# ── Benchmark one configuration ────────────────────────────────────────────
def benchmark_config(name: str, cfg: dict, expected_sizes: dict = None):
    print(f"\n▸ {name}  "
          f"(k={cfg['k']}, η1={cfg['eta1']}, η2={cfg['eta2']}, "
          f"du={cfg['du']}, dv={cfg['dv']})")

    params = to_kyber_params(cfg)
    try:
        kyber = Kyber(params)
    except Exception as e:
        print(f"    [ERROR] could not instantiate: {e}")
        return None

    # Sizes
    sizes = measure_sizes(kyber)
    size_note = ""
    if expected_sizes:
        ok = (sizes["ct_bytes"] == expected_sizes.get("ct_bytes"))
        size_note = "  ✓ matches formula" if ok else "  ✗ formula mismatch"
    print(f"    sizes:  pk={sizes['pk_bytes']}B  "
          f"sk={sizes['sk_bytes']}B  ct={sizes['ct_bytes']}B{size_note}")

    # Latency
    lat = measure_latency(kyber, LATENCY_RUNS)
    print(f"    latency (ms):  "
          f"keygen {lat['keygen']['mean_ms']:.3f}±{lat['keygen']['std_ms']:.3f}  "
          f"encaps {lat['encaps']['mean_ms']:.3f}±{lat['encaps']['std_ms']:.3f}  "
          f"decaps {lat['decaps']['mean_ms']:.3f}±{lat['decaps']['std_ms']:.3f}")

    # Memory
    mem = measure_memory(kyber)
    print(f"    memory:  peak {mem['peak_kb']:.1f} KB")

    # Correctness
    corr = measure_correctness(kyber, MONTE_CARLO_RUNS)
    print(f"    correctness:  {corr['failures']} failures "
          f"in {corr['runs']} cycles")

    return {
        "name":        name,
        "config":      cfg,
        "sizes":       sizes,
        "latency":     lat,
        "memory":      mem,
        "correctness": corr,
    }


# ── Main ───────────────────────────────────────────────────────────────────
def run():
    print("=" * 60)
    print("  MODULE 5 — BENCHMARKING")
    print(f"  Latency runs: {LATENCY_RUNS}  |  "
          f"Monte Carlo runs: {MONTE_CARLO_RUNS}")
    print("=" * 60)

    if not FRONT_PATH.exists():
        print(f"[FATAL] {FRONT_PATH} not found. Run Module 3 first.")
        sys.exit(1)

    with open(FRONT_PATH) as f:
        front_data = json.load(f)
    front = front_data["front"]

    results = []

    # Baseline first
    baseline_cfg = {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4}
    base_res = benchmark_config("Kyber-512 (baseline)", baseline_cfg,
                                {"ct_bytes": 768})
    if base_res:
        results.append(base_res)

    # Each Pareto configuration
    for i, cfg in enumerate(front, 1):
        name = f"P{i}"
        res = benchmark_config(name, cfg, {"ct_bytes": cfg["ct_bytes"]})
        if res:
            results.append(res)

    # Comparison table (ciphertext + latency vs baseline)
    print("\n" + "=" * 60)
    print("  SUMMARY — vs Kyber-512 baseline")
    print("=" * 60)
    base_ct = results[0]["sizes"]["ct_bytes"]
    base_dec = results[0]["latency"]["decaps"]["mean_ms"]

    print(f"  {'config':<20} {'ct(B)':>6} {'Δct':>7} "
          f"{'decaps(ms)':>11} {'fails':>6}")
    print("  " + "-" * 54)
    for r in results:
        ct     = r["sizes"]["ct_bytes"]
        dct    = ct - base_ct
        dct_s  = f"{dct:+d}" if dct != 0 else "—"
        dec    = r["latency"]["decaps"]["mean_ms"]
        fails  = r["correctness"]["failures"]
        print(f"  {r['name']:<20} {ct:>6} {dct_s:>7} "
              f"{dec:>11.3f} {fails:>6}")

    # Persist
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump({
            "settings": {
                "latency_runs":     LATENCY_RUNS,
                "monte_carlo_runs": MONTE_CARLO_RUNS,
            },
            "results": results,
        }, f, indent=2)

    print(f"\n  Saved → {OUTPUT_PATH}")
    print("=" * 60)
    print("  MODULE 5 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    run()