"""
Module 3 — NSGA-II Multi-objective Search
==========================================
Searches the feasible parameter space (relative to a chosen baseline:
Kyber-512, Kyber-768, or Kyber-1024) for the Pareto-optimal front
trading off:

    f1 = ciphertext size (bytes)   -> minimise (IoT bandwidth)
    f2 = log2(delta)               -> minimise (reliability margin)

Feasibility (both hard constraints) is computed from Module 2's raw
values via modules/feasibility.py, parametrised by baseline -- so this
module can be re-run cheaply against all three tiers without re-running
the (slow, SageMath-dependent) Module 2.

Usage:
    python modules/m3_nsga2.py Kyber-512
    python modules/m3_nsga2.py Kyber-768
    python modules/m3_nsga2.py Kyber-1024
"""

import json
import random
import sys
import os
from pathlib import Path

import numpy as np
from deap import base, creator, tools

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _THIS_DIR)
sys.path.insert(0, os.path.dirname(_THIS_DIR))

from feasibility import load_lookup, feasible_set, baseline_threshold

LOOKUP_PATH = Path("results") / "lookup_table.json"

PARAM_RANGES = {
    "k":    [2, 3, 4],
    "eta1": [1, 2, 3, 4, 5],
    "eta2": [1, 2, 3],
    "du":   [8, 9, 10, 11, 12],
    "dv":   [3, 4, 5, 6],
}
GENE_NAMES = ["k", "eta1", "eta2", "du", "dv"]

POP_SIZE      = 52
N_GENERATIONS = 100
N_RUNS        = 30
CX_PROB       = 0.70
MUT_PROB      = 0.10

INFEASIBLE = (1e9, 1e9)


def evaluate(individual, feasible_lookup):
    tup = tuple(individual)
    entry = feasible_lookup.get(tup)
    if entry is None:
        return INFEASIBLE
    return (float(entry["ct_bytes"]), float(entry["log2_delta"]))


def make_individual():
    return [random.choice(PARAM_RANGES[name]) for name in GENE_NAMES]


def mutate_individual(individual, indpb):
    for i, name in enumerate(GENE_NAMES):
        if random.random() < indpb:
            individual[i] = random.choice(PARAM_RANGES[name])
    return (individual,)


def cx_one_point(ind1, ind2):
    if len(ind1) < 2:
        return ind1, ind2
    point = random.randint(1, len(ind1) - 1)
    ind1[point:], ind2[point:] = ind2[point:], ind1[point:]
    return ind1, ind2


def setup_toolbox(feasible_lookup):
    if not hasattr(creator, "FitnessMulti"):
        creator.create("FitnessMulti", base.Fitness, weights=(-1.0, -1.0))
    if not hasattr(creator, "Individual"):
        creator.create("Individual", list, fitness=creator.FitnessMulti)

    toolbox = base.Toolbox()
    toolbox.register("individual", tools.initIterate, creator.Individual, make_individual)
    toolbox.register("population", tools.initRepeat, list, toolbox.individual)
    toolbox.register("evaluate", evaluate, feasible_lookup=feasible_lookup)
    toolbox.register("mate", cx_one_point)
    toolbox.register("mutate", mutate_individual, indpb=MUT_PROB)
    toolbox.register("select", tools.selNSGA2)
    return toolbox


def run_nsga2(toolbox, seed):
    random.seed(seed)
    np.random.seed(seed)

    pop = toolbox.population(n=POP_SIZE)
    for ind in pop:
        ind.fitness.values = toolbox.evaluate(ind)
    pop = toolbox.select(pop, POP_SIZE)

    for gen in range(N_GENERATIONS):
        offspring = tools.selTournamentDCD(pop, POP_SIZE)
        offspring = [toolbox.clone(ind) for ind in offspring]

        for c1, c2 in zip(offspring[::2], offspring[1::2]):
            if random.random() < CX_PROB:
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

        pop = toolbox.select(pop + offspring, POP_SIZE)

    feasible = [ind for ind in pop if ind.fitness.values != INFEASIBLE]
    seen = {}
    for ind in feasible:
        seen[tuple(ind)] = ind
    unique = list(seen.values())
    if not unique:
        return []
    front = tools.sortNondominated(unique, len(unique), first_front_only=True)[0]
    return front


def dominates(a, b):
    return (a[0] <= b[0] and a[1] <= b[1]) and (a[0] < b[0] or a[1] < b[1])


def combine_fronts(all_solutions):
    unique = {}
    for genes, obj in all_solutions:
        unique[genes] = obj
    items = list(unique.items())
    front = []
    for genes_i, obj_i in items:
        if not any(dominates(obj_j, obj_i) for genes_j, obj_j in items if genes_j != genes_i):
            front.append((genes_i, obj_i))
    front.sort(key=lambda x: (x[1][0], x[1][1]))
    return front


def run(baseline_name: str):
    print("=" * 60)
    print(f"  MODULE 3 -- NSGA-II MULTI-OBJECTIVE SEARCH  [{baseline_name}]")
    print("=" * 60)

    lookup = load_lookup(str(LOOKUP_PATH))
    thr = baseline_threshold(lookup, baseline_name)
    feasible_lookup = feasible_set(lookup, baseline_name)
    print(f"  Loaded {len(lookup)} candidates | security threshold = {thr:.2f} bits "
          f"| delta ceiling = 2^-128 | feasible = {len(feasible_lookup)}")

    toolbox = setup_toolbox(feasible_lookup)
    print(f"\n  Running {N_RUNS} independent NSGA-II runs "
          f"(pop={POP_SIZE}, gens={N_GENERATIONS}, cx={CX_PROB}, mut={MUT_PROB})\n")

    all_solutions = []
    per_run_sizes = []
    for r in range(N_RUNS):
        front = run_nsga2(toolbox, seed=r)
        for ind in front:
            all_solutions.append((tuple(ind), ind.fitness.values))
        per_run_sizes.append(len(front))
        print(f"  Run {r + 1:>2}/{N_RUNS}:  front size = {len(front):>2}")

    combined = combine_fronts(all_solutions)

    print(f"\n  Per-run front sizes: min={min(per_run_sizes)}, max={max(per_run_sizes)}, "
          f"mean={np.mean(per_run_sizes):.1f}")
    print(f"  Combined Pareto front: {len(combined)} configurations\n")

    print("  Combined Pareto front (sorted by ciphertext):")
    print(f"  {'k':>2} {'eta1':>4} {'eta2':>4} {'du':>3} {'dv':>3}  "
          f"{'ct(B)':>6} {'log2d':>9} {'sec':>8} {'sec_matzov':>10}")
    print("  " + "-" * 62)
    for genes, obj in combined:
        entry = feasible_lookup[genes]
        print(f"  {genes[0]:>2} {genes[1]:>4} {genes[2]:>4} {genes[3]:>3} {genes[4]:>3}  "
              f"{int(obj[0]):>6} {obj[1]:>9.2f} {entry['security']:>8.2f} "
              f"{entry['security_matzov']:>10.2f}")

    out = {
        "meta": {
            "baseline": baseline_name,
            "security_threshold": thr,
            "n_feasible": len(feasible_lookup),
            "n_runs": N_RUNS, "pop_size": POP_SIZE, "generations": N_GENERATIONS,
            "per_run_front_sizes": per_run_sizes,
            "combined_front_size": len(combined),
        },
        "front": [
            {
                "k": g[0], "eta1": g[1], "eta2": g[2], "du": g[3], "dv": g[4],
                "ct_bytes":       int(obj[0]),
                "log2_delta":     obj[1],
                "security":       feasible_lookup[g]["security"],
                "security_matzov": feasible_lookup[g]["security_matzov"],
                "pk_bytes":       feasible_lookup[g]["pk_bytes"],
                "sk_bytes":       feasible_lookup[g]["sk_bytes"],
            }
            for g, obj in combined
        ],
    }
    out_path = Path("results") / f"nsga2_front_{baseline_name.replace('-', '').lower()}.json"
    out_path.parent.mkdir(exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"\n  Saved -> {out_path}")
    print("=" * 60)
    return out


if __name__ == "__main__":
    baseline = sys.argv[1] if len(sys.argv) > 1 else "Kyber-512"
    run(baseline)
