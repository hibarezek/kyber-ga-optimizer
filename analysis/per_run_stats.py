"""
per_run_stats.py -- per-run quality of NSGA-II (thesis Table 5.5)
==================================================================
Re-runs the 30 NSGA-II runs of Module 3 (seeds 0-29) for each tier and
compares every single run's front with the exhaustive Pareto front:

  * coverage  : share of the true front recovered by the run (%)
  * IGD       : inverted generational distance (Module 4 definition)
  * HV ratio  : hypervolume of the run's front / hypervolume of the true
                front (%). Objectives normalised to [0, 1] over the
                tier's feasible set; reference point (1.1, 1.1).

Run from the repository root:
    python analysis/per_run_stats.py
"""

import os
import sys
import statistics as st

import numpy as np

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "modules"))
os.chdir(_ROOT)

from feasibility import load_lookup, feasible_set
import m3_nsga2 as m3
import m4_validate as m4

TIERS = ["Kyber-512", "Kyber-768", "Kyber-1024"]
REF = (1.1, 1.1)


def hypervolume(points, ref=REF):
    """2-D hypervolume for minimisation."""
    h, prev_f2 = 0.0, ref[1]
    for f1, f2 in sorted(points):
        if f2 < prev_f2:
            h += (ref[0] - f1) * (prev_f2 - f2)
            prev_f2 = f2
    return h


def main():
    L = load_lookup("results/lookup_table.json")
    for tier in TIERS:
        F = feasible_set(L, tier)
        toolbox = m3.setup_toolbox(F)
        true = m4.brute_force_front(F)

        objs = np.array([m4.objective_vector(F, t) for t in F])
        lo, hi = objs.min(0), objs.max(0)
        span = np.where(hi - lo == 0, 1, hi - lo)
        norm = lambda t: tuple((np.array(m4.objective_vector(F, t)) - lo) / span)
        hv_true = hypervolume([norm(t) for t in true])

        cov, igd, hvr, full = [], [], [], 0
        for seed in range(m3.N_RUNS):
            front = [tuple(ind) for ind in m3.run_nsga2(toolbox, seed=seed)]
            c, _ = m4.compute_coverage(true, front)
            cov.append(100 * c)
            full += c == 1.0
            igd.append(m4.compute_igd(F, true, front))
            hvr.append(100 * hypervolume([norm(t) for t in front]) / hv_true)

        print(f"{tier}: feasible {len(F)}, true front {len(true)}")
        print(f"  coverage  mean {st.mean(cov):5.1f} sd {st.pstdev(cov):5.1f}"
              f" min {min(cov):5.1f}   runs at 100%: {full}/{m3.N_RUNS}")
        print(f"  IGD       mean {st.mean(igd):.3f} max {max(igd):.3f}")
        print(f"  HV ratio  mean {st.mean(hvr):5.1f} min {min(hvr):5.1f}")


if __name__ == "__main__":
    main()
