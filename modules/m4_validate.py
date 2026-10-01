"""
Module 4 — Ground-Truth Validation and Convergence Efficiency
==============================================================
Validates the NSGA-II Pareto front (Module 3) against the exhaustive
brute-force front, for a given baseline tier. Also quantifies how many
unique feasible candidates NSGA-II evaluates before covering the true
front, versus the size of the full feasible space (the scaling
argument for why NSGA-II is used at all, despite brute force being
tractable on THIS specific space).

Usage:
    python modules/m4_validate.py Kyber-512
    python modules/m4_validate.py Kyber-768
    python modules/m4_validate.py Kyber-1024
"""

import json
import random
import sys
import os
from pathlib import Path

import numpy as np

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _THIS_DIR)
sys.path.insert(0, os.path.dirname(_THIS_DIR))

from feasibility import load_lookup, feasible_set, baseline_threshold
import m3_nsga2 as m3

LOOKUP_PATH = Path("results") / "lookup_table.json"


def dominates(a, b):
    return (a[0] <= b[0] and a[1] <= b[1]) and (a[0] < b[0] or a[1] < b[1])


def brute_force_front(feasible_lookup):
    items = [(tup, (float(e["ct_bytes"]), float(e["log2_delta"])))
              for tup, e in feasible_lookup.items()]
    front = []
    for tup_i, obj_i in items:
        if not any(dominates(obj_j, obj_i) for tup_j, obj_j in items if tup_j != tup_i):
            front.append(tup_i)
    front.sort(key=lambda t: feasible_lookup[t]["ct_bytes"])
    return front


def objective_vector(feasible_lookup, tup):
    e = feasible_lookup[tup]
    return (float(e["ct_bytes"]), float(e["log2_delta"]))


def compute_coverage(true_front, nsga_front):
    true_set = set(true_front)
    nsga_set = set(nsga_front)
    recovered = true_set & nsga_set
    return len(recovered) / len(true_set), recovered


def compute_igd(feasible_lookup, true_front, nsga_front):
    if not nsga_front:
        return float("inf")
    true_objs = np.array([objective_vector(feasible_lookup, t) for t in true_front])
    nsga_objs = np.array([objective_vector(feasible_lookup, t) for t in nsga_front])
    mins = true_objs.min(axis=0)
    maxs = true_objs.max(axis=0)
    span = np.where(maxs - mins == 0, 1.0, maxs - mins)
    tn = (true_objs - mins) / span
    nn = (nsga_objs - mins) / span
    dists = [np.sqrt(((nn - p) ** 2).sum(axis=1)).min() for p in tn]
    return float(np.mean(dists))


def convergence_experiment(feasible_lookup, true_front, seed=0):
    random.seed(seed)
    np.random.seed(seed)
    toolbox = m3.setup_toolbox(feasible_lookup)
    true_set = set(true_front)

    evaluated_unique = set()
    discovered_front = set()
    gen_full_cover = None
    evals_full_cover = None

    def record_eval(ind):
        tup = tuple(ind)
        if tup in feasible_lookup:
            evaluated_unique.add(tup)
            if tup in true_set:
                discovered_front.add(tup)

    pop = toolbox.population(n=m3.POP_SIZE)
    for ind in pop:
        ind.fitness.values = toolbox.evaluate(ind)
        record_eval(ind)
    pop = toolbox.select(pop, m3.POP_SIZE)

    from deap import tools as deap_tools
    for gen in range(m3.N_GENERATIONS):
        offspring = deap_tools.selTournamentDCD(pop, m3.POP_SIZE)
        offspring = [toolbox.clone(ind) for ind in offspring]
        for c1, c2 in zip(offspring[::2], offspring[1::2]):
            if random.random() < m3.CX_PROB:
                toolbox.mate(c1, c2)
                del c1.fitness.values
                del c2.fitness.values
            toolbox.mutate(c1)
            toolbox.mutate(c2)
            del c1.fitness.values
            del c2.fitness.values
        invalid = [ind for ind in offspring if not ind.fitness.valid]
        for ind in invalid:
            ind.fitness.values = toolbox.evaluate(ind)
            record_eval(ind)
        pop = toolbox.select(pop + offspring, m3.POP_SIZE)
        if gen_full_cover is None and discovered_front == true_set:
            gen_full_cover = gen + 1
            evals_full_cover = len(evaluated_unique)

    return {
        "generation_full_coverage": gen_full_cover,
        "unique_evals_full_coverage": evals_full_cover,
        "total_unique_evaluated": len(evaluated_unique),
    }


def run(baseline_name: str):
    print("=" * 60)
    print(f"  MODULE 4 -- GROUND-TRUTH VALIDATION  [{baseline_name}]")
    print("=" * 60)

    lookup = load_lookup(str(LOOKUP_PATH))
    feasible_lookup = feasible_set(lookup, baseline_name)

    front_path = Path("results") / f"nsga2_front_{baseline_name.replace('-', '').lower()}.json"
    with open(front_path) as f:
        nsga_raw = json.load(f)
    nsga_front = [(p["k"], p["eta1"], p["eta2"], p["du"], p["dv"]) for p in nsga_raw["front"]]

    true_front = brute_force_front(feasible_lookup)
    n_feasible = len(feasible_lookup)
    print(f"\n  Feasible candidates:      {n_feasible}")
    print(f"  Brute-force Pareto front: {len(true_front)} configurations")
    print(f"  NSGA-II Pareto front:     {len(nsga_front)} configurations")

    coverage, recovered = compute_coverage(true_front, nsga_front)
    igd = compute_igd(feasible_lookup, true_front, nsga_front)
    missed = set(true_front) - set(nsga_front)
    extra = set(nsga_front) - set(true_front)

    print(f"\n  Coverage: {coverage*100:.1f}%  ({len(recovered)}/{len(true_front)})")
    print(f"  IGD:      {igd:.6f}  (0.0 = exact recovery)")
    if not missed and not extra:
        print("  -> NSGA-II front is IDENTICAL to the ground truth.")
    else:
        print(f"  MISSED: {sorted(missed)}")
        print(f"  EXTRA:  {sorted(extra)}")

    conv = convergence_experiment(feasible_lookup, true_front, seed=0)
    if conv["generation_full_coverage"] is not None:
        frac = conv["unique_evals_full_coverage"] / n_feasible * 100
        print(f"\n  Full true front discovered by generation {conv['generation_full_coverage']}")
        print(f"  Unique feasible evaluated at that point: "
              f"{conv['unique_evals_full_coverage']} of {n_feasible} ({frac:.1f}%)")

    out = {
        "baseline": baseline_name,
        "n_feasible": n_feasible,
        "true_front_size": len(true_front),
        "nsga_front_size": len(nsga_front),
        "coverage": coverage,
        "igd": igd,
        "identical": (not missed and not extra),
        "convergence": conv,
        "true_front": [
            {"k": t[0], "eta1": t[1], "eta2": t[2], "du": t[3], "dv": t[4],
             "ct_bytes": feasible_lookup[t]["ct_bytes"],
             "log2_delta": feasible_lookup[t]["log2_delta"]}
            for t in true_front
        ],
    }
    out_path = Path("results") / f"validation_{baseline_name.replace('-', '').lower()}.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  Saved -> {out_path}")
    print("=" * 60)
    return out


if __name__ == "__main__":
    baseline = sys.argv[1] if len(sys.argv) > 1 else "Kyber-512"
    run(baseline)
