"""
Module 4 — Ground-Truth Validation and Convergence Efficiency
==============================================================
Validates the NSGA-II Pareto front (Module 3) against the exhaustive
brute-force front computed directly over the feasible space, and
quantifies how efficiently NSGA-II converges relative to exhaustive
enumeration.

Produces three pieces of evidence:

  1. CORRECTNESS
     - Coverage: fraction of the true Pareto front recovered by NSGA-II
     - IGD (Inverted Generational Distance): mean distance from each
       true-front point to the nearest NSGA-II point
     Both confirm NSGA-II recovered the verified ground truth.

  2. CONVERGENCE EFFICIENCY
     - Number of UNIQUE feasible candidates NSGA-II evaluates before
       it has discovered the entire true front, versus the size of the
       full feasible space. This is the scaling argument: NSGA-II locks
       onto the front after exploring only a fraction of the space.

  3. EXTRAPOLATION
     - What the observed exploration fraction implies for schemes whose
       parameter spaces are far larger, or whose per-candidate
       evaluation is expensive (as security/delta estimation is), where
       exhaustive enumeration becomes intractable.

Runs on Windows (uv) — reads the lookup table and NSGA-II front only.

Usage:
    uv run python modules/m4_validate.py
"""

import json
import random
import sys
from pathlib import Path

import numpy as np

# Reuse Module 3's search internals for the convergence experiment
sys.path.insert(0, str(Path(__file__).resolve().parent))
import m3_nsga2 as m3

LOOKUP_PATH = Path("results") / "lookup_table.json"
FRONT_PATH  = Path("results") / "nsga2_front.json"
OUTPUT_PATH = Path("results") / "validation.json"


# ── Load data ──────────────────────────────────────────────────────────────
def load_data():
    with open(LOOKUP_PATH) as f:
        lookup_raw = json.load(f)
    with open(FRONT_PATH) as f:
        nsga_raw = json.load(f)

    lookup = {}
    for key, entry in lookup_raw["candidates"].items():
        tup = tuple(int(x) for x in key.split(","))
        lookup[tup] = entry

    nsga_front = [
        (p["k"], p["eta1"], p["eta2"], p["du"], p["dv"])
        for p in nsga_raw["front"]
    ]
    return lookup, nsga_front


# ── Brute-force true Pareto front ──────────────────────────────────────────
def dominates(a, b):
    """True if objective vector a dominates b (both minimised)."""
    return (a[0] <= b[0] and a[1] <= b[1]) and (a[0] < b[0] or a[1] < b[1])


def brute_force_front(lookup):
    """
    Exhaustively compute the true Pareto front over all feasible
    candidates. Objectives: (ciphertext bytes, log2 delta), both minimised.
    """
    feasible = [
        (tup, (float(e["ct_bytes"]), float(e["log2_delta"])))
        for tup, e in lookup.items()
        if e["feasible"]
    ]

    front = []
    for tup_i, obj_i in feasible:
        if not any(dominates(obj_j, obj_i)
                   for tup_j, obj_j in feasible if tup_j != tup_i):
            front.append(tup_i)

    front.sort(key=lambda t: lookup[t]["ct_bytes"])
    return front, len(feasible)


# ── Correctness metrics ────────────────────────────────────────────────────
def objective_vector(lookup, tup):
    e = lookup[tup]
    return (float(e["ct_bytes"]), float(e["log2_delta"]))


def compute_coverage(true_front, nsga_front):
    """Fraction of true-front configurations that NSGA-II also found."""
    true_set = set(true_front)
    nsga_set = set(nsga_front)
    recovered = true_set & nsga_set
    return len(recovered) / len(true_set), recovered


def compute_igd(lookup, true_front, nsga_front):
    """
    Inverted Generational Distance: mean Euclidean distance (in
    normalised objective space) from each true-front point to the
    nearest NSGA-II point. 0.0 = perfect recovery.
    """
    if not nsga_front:
        return float("inf")

    true_objs = np.array([objective_vector(lookup, t) for t in true_front])
    nsga_objs = np.array([objective_vector(lookup, t) for t in nsga_front])

    # Normalise each objective to [0, 1] using the true front's range
    mins = true_objs.min(axis=0)
    maxs = true_objs.max(axis=0)
    span = np.where(maxs - mins == 0, 1.0, maxs - mins)

    tn = (true_objs - mins) / span
    nn = (nsga_objs - mins) / span

    dists = []
    for p in tn:
        d = np.sqrt(((nn - p) ** 2).sum(axis=1)).min()
        dists.append(d)
    return float(np.mean(dists))


# ── Convergence efficiency experiment ──────────────────────────────────────
def convergence_experiment(lookup, true_front, seed=0):
    """
    Run a single instrumented NSGA-II and record, generation by
    generation, how many UNIQUE feasible candidates have been evaluated
    and how much of the true front has been discovered. Returns the
    generation and unique-eval count at which the full true front is
    first covered.
    """
    random.seed(seed)
    np.random.seed(seed)

    toolbox = m3.setup_toolbox(lookup)
    true_set = set(true_front)

    evaluated_unique = set()
    discovered_front = set()
    history = []
    gen_full_cover = None
    evals_full_cover = None

    def record_eval(ind):
        tup = tuple(ind)
        entry = lookup.get(tup)
        if entry is not None and entry["feasible"]:
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

        history.append({
            "generation":      gen + 1,
            "unique_feasible_evaluated": len(evaluated_unique),
            "true_front_discovered":     len(discovered_front),
        })

        if gen_full_cover is None and discovered_front == true_set:
            gen_full_cover   = gen + 1
            evals_full_cover = len(evaluated_unique)

    return {
        "generation_full_coverage": gen_full_cover,
        "unique_evals_full_coverage": evals_full_cover,
        "total_unique_evaluated": len(evaluated_unique),
        "history": history,
    }


# ── Main ───────────────────────────────────────────────────────────────────
def run():
    print("=" * 60)
    print("  MODULE 4 — GROUND-TRUTH VALIDATION")
    print("=" * 60)

    lookup, nsga_front = load_data()

    # 1. Brute-force true front
    true_front, n_feasible = brute_force_front(lookup)
    print(f"\n  Feasible candidates:        {n_feasible}")
    print(f"  Brute-force Pareto front:   {len(true_front)} configurations")
    print(f"  NSGA-II Pareto front:       {len(nsga_front)} configurations")

    print("\n  True (brute-force) Pareto front:")
    print(f"  {'k':>2} {'η1':>3} {'η2':>3} {'du':>3} {'dv':>3}  "
          f"{'ct(B)':>6} {'log2δ':>9}")
    print("  " + "-" * 44)
    for t in true_front:
        e = lookup[t]
        print(f"  {t[0]:>2} {t[1]:>3} {t[2]:>3} {t[3]:>3} {t[4]:>3}  "
              f"{e['ct_bytes']:>6} {e['log2_delta']:>9.2f}")

    # 2. Correctness metrics
    coverage, recovered = compute_coverage(true_front, nsga_front)
    igd = compute_igd(lookup, true_front, nsga_front)
    missed = set(true_front) - set(nsga_front)
    extra  = set(nsga_front) - set(true_front)

    print("\n  " + "=" * 44)
    print("  CORRECTNESS")
    print("  " + "-" * 44)
    print(f"  Coverage:  {coverage * 100:.1f}%  "
          f"({len(recovered)}/{len(true_front)} true-front points recovered)")
    print(f"  IGD:       {igd:.6f}  (0.0 = exact recovery)")
    if missed:
        print(f"  MISSED by NSGA-II: {sorted(missed)}")
    if extra:
        print(f"  EXTRA in NSGA-II (not on true front): {sorted(extra)}")
    if not missed and not extra:
        print("  → NSGA-II front is IDENTICAL to the ground truth.")

    # 3. Convergence efficiency
    print("\n  " + "=" * 44)
    print("  CONVERGENCE EFFICIENCY")
    print("  " + "-" * 44)
    conv = convergence_experiment(lookup, true_front, seed=0)
    gfc  = conv["generation_full_coverage"]
    efc  = conv["unique_evals_full_coverage"]

    if gfc is not None:
        frac = efc / n_feasible * 100
        print(f"  Full true front discovered by generation {gfc}")
        print(f"  Unique feasible candidates evaluated at that point: "
              f"{efc} of {n_feasible} ({frac:.1f}% of feasible space)")
        print(f"  Total unique feasible evaluated over full run: "
              f"{conv['total_unique_evaluated']} of {n_feasible}")
    else:
        print("  Full coverage not reached within the generation budget "
              "(single-run instrumented experiment).")

    # 4. Extrapolation statement
    print("\n  " + "=" * 44)
    print("  SCALING IMPLICATION")
    print("  " + "-" * 44)
    if gfc is not None:
        print("  On this space, NSGA-II recovered the complete front after")
        print(f"  exploring ~{frac:.0f}% of feasible candidates. Brute force")
        print(f"  requires evaluating 100% ({n_feasible} candidates). The")
        print("  evolutionary search therefore scales favourably to larger")
        print("  parameter spaces or schemes where per-candidate evaluation")
        print("  (security + failure estimation) is expensive and exhaustive")
        print("  enumeration becomes intractable.")
    # Persist
    out = {
        "n_feasible":         n_feasible,
        "true_front_size":    len(true_front),
        "nsga_front_size":    len(nsga_front),
        "coverage":           coverage,
        "igd":                igd,
        "missed":             sorted(str(m) for m in missed),
        "extra":              sorted(str(x) for x in extra),
        "identical":          (not missed and not extra),
        "convergence":        conv,
        "true_front": [
            {"k": t[0], "eta1": t[1], "eta2": t[2], "du": t[3], "dv": t[4],
             "ct_bytes": lookup[t]["ct_bytes"],
             "log2_delta": lookup[t]["log2_delta"]}
            for t in true_front
        ],
    }
    OUTPUT_PATH.parent.mkdir(exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(out, f, indent=2)

    print(f"\n  Saved → {OUTPUT_PATH}")
    print("=" * 60)
    print("  MODULE 4 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    run()