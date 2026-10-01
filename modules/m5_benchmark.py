"""
Module 5 — Benchmarking and Correctness Verification
=====================================================
Benchmarks every Pareto-optimal configuration for a given baseline tier
against that tier's standard Kyber parameters, instantiating each in
kyber-py and measuring sizes, latency, memory, and Monte-Carlo
correctness.

Front configurations are labelled P1..Pn in order of ciphertext size
for each tier; the baseline's own configuration appears in the front
(and is benchmarked again under its P-label).

Note: kyber-py 1.2.0 decodes du=12 ciphertexts incorrectly (values are
reduced mod q instead of mod 4096), so du=12 configurations fail every
Monte Carlo cycle. Their sizes, latency and memory remain valid.

Usage:
    python modules/m5_benchmark.py Kyber-512
    python modules/m5_benchmark.py Kyber-768
    python modules/m5_benchmark.py Kyber-1024
"""

import json
import os
import statistics
import sys
import time
import tracemalloc
from pathlib import Path

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _THIS_DIR)

from kyber_py.kyber.kyber import Kyber

LATENCY_RUNS     = 1000
MONTE_CARLO_RUNS = 2000

STANDARD_CONFIGS = {
    "Kyber-512":  {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
    "Kyber-768":  {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
    "Kyber-1024": {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}


def to_kyber_params(cfg: dict) -> dict:
    return {"k": cfg["k"], "eta_1": cfg["eta1"], "eta_2": cfg["eta2"],
            "du": cfg["du"], "dv": cfg["dv"]}


def measure_sizes(kyber) -> dict:
    pk, sk = kyber.keygen()
    key, ct = kyber.encaps(pk)
    return {"pk_bytes": len(pk), "sk_bytes": len(sk), "ct_bytes": len(ct)}


def measure_latency(kyber, runs: int) -> dict:
    keygen_times, keys = [], []
    for _ in range(runs):
        t0 = time.perf_counter()
        pk, sk = kyber.keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)
        keys.append((pk, sk))

    encaps_times, caps = [], []
    for i in range(runs):
        pk, _ = keys[i % len(keys)]
        t0 = time.perf_counter()
        key, ct = kyber.encaps(pk)
        encaps_times.append((time.perf_counter() - t0) * 1000)
        caps.append((key, ct))

    decaps_times = []
    for i in range(runs):
        _, sk = keys[i % len(keys)]
        _, ct = caps[i % len(caps)]
        t0 = time.perf_counter()
        kyber.decaps(sk, ct)
        decaps_times.append((time.perf_counter() - t0) * 1000)

    def stats(xs):
        return {"mean_ms": statistics.mean(xs), "std_ms": statistics.pstdev(xs)}

    return {"keygen": stats(keygen_times), "encaps": stats(encaps_times),
            "decaps": stats(decaps_times)}


def measure_memory(kyber) -> dict:
    tracemalloc.start()
    pk, sk = kyber.keygen()
    key, ct = kyber.encaps(pk)
    kyber.decaps(sk, ct)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"peak_kb": peak / 1024}


def measure_correctness(kyber, runs: int) -> dict:
    failures = 0
    for _ in range(runs):
        pk, sk = kyber.keygen()
        key_bob, ct = kyber.encaps(pk)
        key_alice = kyber.decaps(sk, ct)
        if key_alice != key_bob:
            failures += 1
    return {"runs": runs, "failures": failures}


def benchmark_config(name: str, cfg: dict, expected_ct: int = None):
    print(f"\n> {name}  (k={cfg['k']}, eta1={cfg['eta1']}, eta2={cfg['eta2']}, "
          f"du={cfg['du']}, dv={cfg['dv']})")
    params = to_kyber_params(cfg)
    kyber = Kyber(params)

    sizes = measure_sizes(kyber)
    note = ""
    if expected_ct is not None:
        note = "  OK matches formula" if sizes["ct_bytes"] == expected_ct else "  XX MISMATCH"
    print(f"    sizes:  pk={sizes['pk_bytes']}B sk={sizes['sk_bytes']}B ct={sizes['ct_bytes']}B{note}")

    lat = measure_latency(kyber, LATENCY_RUNS)
    print(f"    latency (ms): keygen {lat['keygen']['mean_ms']:.3f}+-{lat['keygen']['std_ms']:.3f}  "
          f"encaps {lat['encaps']['mean_ms']:.3f}+-{lat['encaps']['std_ms']:.3f}  "
          f"decaps {lat['decaps']['mean_ms']:.3f}+-{lat['decaps']['std_ms']:.3f}")

    mem = measure_memory(kyber)
    print(f"    memory: peak {mem['peak_kb']:.1f} KB")

    corr = measure_correctness(kyber, MONTE_CARLO_RUNS)
    print(f"    correctness: {corr['failures']} failures in {corr['runs']} cycles")

    return {"name": name, "config": cfg, "sizes": sizes, "latency": lat,
            "memory": mem, "correctness": corr}


def run(baseline_name: str):
    print("=" * 60)
    print(f"  MODULE 5 -- BENCHMARKING  [{baseline_name}]")
    print(f"  Latency runs: {LATENCY_RUNS}  |  Monte Carlo runs: {MONTE_CARLO_RUNS}")
    print("=" * 60)

    front_path = Path("results") / f"nsga2_front_{baseline_name.replace('-', '').lower()}.json"
    with open(front_path) as f:
        front_data = json.load(f)
    front = front_data["front"]

    results = []
    baseline_cfg = STANDARD_CONFIGS[baseline_name]
    base_ct = 32 * (baseline_cfg["du"] * baseline_cfg["k"] + baseline_cfg["dv"])
    results.append(benchmark_config(f"{baseline_name} (baseline)", baseline_cfg, base_ct))

    for i, cfg in enumerate(front, 1):
        name = f"P{i}"
        res = benchmark_config(name, cfg, cfg["ct_bytes"])
        results.append(res)

    print("\n" + "=" * 60)
    print(f"  SUMMARY -- vs {baseline_name} baseline")
    print("=" * 60)
    base_ct = results[0]["sizes"]["ct_bytes"]
    print(f"  {'config':<24} {'ct(B)':>6} {'dct':>7} {'decaps(ms)':>11} {'fails':>6}")
    print("  " + "-" * 58)
    for r in results:
        ct = r["sizes"]["ct_bytes"]
        dct = ct - base_ct
        dct_s = f"{dct:+d}" if dct != 0 else "-"
        dec = r["latency"]["decaps"]["mean_ms"]
        fails = r["correctness"]["failures"]
        print(f"  {r['name']:<24} {ct:>6} {dct_s:>7} {dec:>11.3f} {fails:>6}")

    out_path = Path("results") / f"benchmark_{baseline_name.replace('-', '').lower()}.json"
    with open(out_path, "w") as f:
        json.dump({"baseline": baseline_name,
                    "settings": {"latency_runs": LATENCY_RUNS, "monte_carlo_runs": MONTE_CARLO_RUNS},
                    "results": results}, f, indent=2)
    print(f"\n  Saved -> {out_path}")
    print("=" * 60)


if __name__ == "__main__":
    baseline = sys.argv[1] if len(sys.argv) > 1 else "Kyber-512"
    run(baseline)
