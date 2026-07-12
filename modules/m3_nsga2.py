"""
Module 3 — NSGA-II Multi-objective Search
==========================================
Searches the pre-computed feasible parameter space for the Pareto-optimal
front trading off two objectives:

    f1 = ciphertext size (bytes)   → minimise (IoT bandwidth)
    f2 = log2(delta)               → minimise (reliability margin;
                                       more negative = safer)

Hard constraints (already applied in Module 2, encoded in the lookup table):
    g1 : security_bits >= threshold (132.84, Kyber-512 Core-SVP hardness)
    g2 : log2_delta    <= -64

All objective values are read from results/lookup_table.json in O(1) time —
no estimator or failure-probability computation happens during the search.

NSGA-II is applied here to demonstrate that an evolutionary search recovers
the true Pareto front without exhaustive enumeration. Because the feasible
space is small (406 candidates), the true front can also be computed by
brute force (Module 4), which validates the NSGA-II result.

Runs on Windows (uv) — requires only `deap`, no SageMath.

Usage:
    uv run python modules/m3_nsga2.py
"""

import json
import random
import sys
from pathlib import Path

import numpy as np
from deap import base, creator, tools

# ── Configuration ──────────────────────────────────────────────────────────
LOOKUP_PATH = Path("results") / "lookup_table.json"
OUTPUT_PATH = Path("results") / "nsga2_front.json"

# Parameter ranges (must match Module 1 / Module 2)
PARAM_RANGES = {
    "k":    [2, 3, 4],
    "eta1": [1, 2, 3, 4, 5],
    "eta2": [1, 2, 3],
    "du":   [8, 9, 10, 11, 12],
    "dv":   [3, 4, 5, 6],
}
GENE_NAMES = ["k", "eta1", "eta2", "du", "dv"]

# NSGA-II hyperparameters
POP_SIZE      = 52
N_GENERATIONS = 100
N_RUNS        = 30
CX_PROB       = 0.70   # crossover probability
MUT_PROB      = 0.10   # per-gene mutation probability
TOURNAMENT_K  = 3      # (NSGA-II uses selNSGA2; tournament used for variation)

# Penalty objective vector for infeasible / invalid individuals.
# Both objectives are minimised, so large positive values are "worst".
INFEASIBLE = (1e9, 1e9)


# ── Lookup table ───────────────────────────────────────────────────────────
def load_lookup() -> dict:
    """Load the Module 2 lookup table, keyed by (k,eta1,eta2,du,dv) tuple."""
    if not LOOKUP_PATH.exists():
        print(f"[FATAL] {LOOKUP_PATH} not found. Run Module 2 first.")
        sys.exit(1)

    with open(LOOKUP_PATH) as f:
        data = json.load(f)

    lookup = {}
    for key, entry in data["candidates"].items():
        tup = tuple(int(x) for x in key.split(","))
        lookup[tup] = entry

    meta = data["meta"]
    print(f"  Loaded {len(lookup)} candidates from lookup table")
    print(f"  Security threshold: {meta['security_threshold']:.2f} bits")
    print(f"  Delta ceiling:      2^{meta['log2_delta_ceiling']}")
    print(f"  Feasible candidates: {meta['feasible_count']}")
    return lookup


# ── Objective evaluation ───────────────────────────────────────────────────
def evaluate(individual, lookup):
    """
    Return the two-objective fitness of an individual.
    Reads directly from the lookup table. Infeasible or out-of-table
    individuals receive the INFEASIBLE penalty.
    """
    tup = tuple(individual)
    entry = lookup.get(tup)
    if entry is None or not entry["feasible"]:
        return INFEASIBLE
    return (float(entry["ct_bytes"]), float(entry["log2_delta"]))


# ── Genetic operators ──────────────────────────────────────────────────────
def make_individual():
    """Create a random individual within the valid parameter ranges."""
    return [random.choice(PARAM_RANGES[name]) for name in GENE_NAMES]


def mutate_individual(individual, indpb):
    """
    Per-gene uniform mutation: with probability indpb, replace a gene
    with a random valid value for that gene's position.
    """
    for i, name in enumerate(GENE_NAMES):
        if random.random() < indpb:
            individual[i] = random.choice(PARAM_RANGES[name])
    return (individual,)


def cx_one_point(ind1, ind2):
    """Single-point crossover on the 5-gene chromosome."""
    if len(ind1) < 2:
        return ind1, ind2
    point = random.randint(1, len(ind1) - 1)
    ind1[point:], ind2[point:] = ind2[point:], ind1[point:]
    return ind1, ind2


# ── DEAP setup ─────────────────────────────────────────────────────────────
def setup_toolbox(lookup):
    # Two objectives, both minimised
    if not hasattr(creator, "FitnessMulti"):
        creator.create("FitnessMulti", base.Fitness, weights=(-1.0, -1.0))
    if not hasattr(creator, "Individual"):
        creator.create("Individual", list, fitness=creator.FitnessMulti)

    toolbox = base.Toolbox()
    toolbox.register("individual", tools.initIterate,
                     creator.Individual, make_individual)
    toolbox.register("population", tools.initRepeat,
                     list, toolbox.individual)
    toolbox.register("evaluate", evaluate, lookup=lookup)
    toolbox.register("mate", cx_one_point)
    toolbox.register("mutate", mutate_individual, indpb=MUT_PROB)
    toolbox.register("select", tools.selNSGA2)
    return toolbox


# ── Single NSGA-II run ─────────────────────────────────────────────────────
def run_nsga2(toolbox, seed):
    """Execute one NSGA-II run; return the final non-dominated front."""
    random.seed(seed)
    np.random.seed(seed)

    pop = toolbox.population(n=POP_SIZE)

    # Evaluate initial population
    for ind in pop:
        ind.fitness.values = toolbox.evaluate(ind)

    # Assign crowding distance via initial NSGA-II selection
    pop = toolbox.select(pop, POP_SIZE)

    for gen in range(N_GENERATIONS):
        # Variation: tournament-DCD selection, then crossover + mutation
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

        # Re-evaluate invalidated offspring
        invalid = [ind for ind in offspring if not ind.fitness.valid]
        for ind in invalid:
            ind.fitness.values = toolbox.evaluate(ind)

        # Environmental selection: pick best POP_SIZE from parents+offspring
        pop = toolbox.select(pop + offspring, POP_SIZE)

    # Extract the true non-dominated feasible front, deduplicated by genotype.
    # The final population can contain duplicate genotypes and penalty
    # individuals; filter both so the reported front size is meaningful.
    feasible = [ind for ind in pop
                if ind.fitness.values != INFEASIBLE]

    # Deduplicate by genotype, keeping one representative each
    seen = {}
    for ind in feasible:
        seen[tuple(ind)] = ind
    unique = list(seen.values())

    if not unique:
        return []

    # True non-dominated subset among the unique feasible individuals
    front = tools.sortNondominated(unique, len(unique),
                                   first_front_only=True)[0]
    return front


# ── Aggregation across runs ────────────────────────────────────────────────
def dominates(a, b):
    """True if objective vector a dominates b (both minimised)."""
    return (a[0] <= b[0] and a[1] <= b[1]) and (a[0] < b[0] or a[1] < b[1])


def combine_fronts(all_solutions):
    """
    Given a set of (genes_tuple, obj_tuple) solutions from all runs,
    return the combined non-dominated front, deduplicated.
    """
    unique = {}
    for genes, obj in all_solutions:
        unique[genes] = obj   # dedupe by genotype

    items = list(unique.items())
    front = []
    for genes_i, obj_i in items:
        if not any(dominates(obj_j, obj_i)
                   for genes_j, obj_j in items if genes_j != genes_i):
            front.append((genes_i, obj_i))

    # Sort by ciphertext ascending for readability
    front.sort(key=lambda x: (x[1][0], x[1][1]))
    return front


# ── Main ───────────────────────────────────────────────────────────────────
def run():
    print("=" * 60)
    print("  MODULE 3 — NSGA-II MULTI-OBJECTIVE SEARCH")
    print("=" * 60)

    lookup  = load_lookup()
    toolbox = setup_toolbox(lookup)

    print(f"\n  Running {N_RUNS} independent NSGA-II runs")
    print(f"  (pop={POP_SIZE}, gens={N_GENERATIONS}, "
          f"cx={CX_PROB}, mut={MUT_PROB})\n")

    all_solutions = []
    per_run_sizes = []

    for r in range(N_RUNS):
        front = run_nsga2(toolbox, seed=r)
        for ind in front:
            all_solutions.append((tuple(ind), ind.fitness.values))
        per_run_sizes.append(len(front))
        print(f"  Run {r + 1:>2}/{N_RUNS}:  "
              f"front size = {len(front):>2}")

    # Combine all runs into one non-dominated front
    combined = combine_fronts(all_solutions)

    print(f"\n  Per-run front sizes: "
          f"min={min(per_run_sizes)}, "
          f"max={max(per_run_sizes)}, "
          f"mean={np.mean(per_run_sizes):.1f}")
    print(f"  Combined Pareto front: {len(combined)} configurations\n")

    # Display the combined front
    print("  Combined Pareto front (sorted by ciphertext):")
    print(f"  {'k':>2} {'η1':>3} {'η2':>3} {'du':>3} {'dv':>3}  "
          f"{'ct(B)':>6} {'log2δ':>9} {'sec':>7}")
    print("  " + "-" * 52)
    for genes, obj in combined:
        k, eta1, eta2, du, dv = genes
        entry = lookup[genes]
        print(f"  {k:>2} {eta1:>3} {eta2:>3} {du:>3} {dv:>3}  "
              f"{int(obj[0]):>6} {obj[1]:>9.2f} "
              f"{entry['security_bits']:>7.2f}")

    # Persist
    out = {
        "meta": {
            "n_runs":        N_RUNS,
            "pop_size":      POP_SIZE,
            "generations":   N_GENERATIONS,
            "cx_prob":       CX_PROB,
            "mut_prob":      MUT_PROB,
            "per_run_front_sizes": per_run_sizes,
            "combined_front_size": len(combined),
        },
        "front": [
            {
                "k": g[0], "eta1": g[1], "eta2": g[2], "du": g[3], "dv": g[4],
                "ct_bytes":      int(obj[0]),
                "log2_delta":    obj[1],
                "security_bits": lookup[g]["security_bits"],
                "pk_bytes":      lookup[g]["pk_bytes"],
                "sk_bytes":      lookup[g]["sk_bytes"],
            }
            for g, obj in combined
        ],
    }
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(out, f, indent=2)

    print(f"\n  Saved → {OUTPUT_PATH}")
    print("=" * 60)
    print("  MODULE 3 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    run()