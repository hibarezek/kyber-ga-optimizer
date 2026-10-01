"""
feasibility.py — baseline-dependent feasibility, computed on the fly
======================================================================
Module 2 stores raw (security, security_matzov, log2_delta) per
candidate -- values that don't depend on which standard parameter set
you're comparing against. Feasibility DOES depend on that choice, so
it lives here instead of being baked into the lookup table.

Usage:
    lookup = load_lookup("results/lookup_table.json")
    thr = baseline_threshold(lookup, "Kyber-512")
    feas = {k: is_feasible(v, thr) for k, v in lookup.items()}
"""

import json

# Study-level reliability constraint (thesis Chapter 3): delta <= 2^-128,
# motivated by the 2^64 decapsulation queries of the NIST PQC call.
DELTA_CEILING = -128

BASELINES = {
    "Kyber-512":  (2, 3, 2, 10, 4),
    "Kyber-768":  (3, 2, 2, 10, 4),
    "Kyber-1024": (4, 2, 2, 11, 5),
}


def load_lookup(path="results/lookup_table.json") -> dict:
    with open(path) as f:
        data = json.load(f)
    lookup = {}
    for key, entry in data["candidates"].items():
        tup = tuple(int(x) for x in key.split(","))
        lookup[tup] = entry
    return lookup


def baseline_key(name: str) -> tuple:
    return BASELINES[name]


def baseline_threshold(lookup: dict, name: str, sec_field: str = "security") -> float:
    """security threshold = the baseline's OWN min(pk,ct) under the given model"""
    return lookup[baseline_key(name)][sec_field]


def is_feasible(entry: dict, threshold: float, sec_field: str = "security") -> bool:
    """g1: at least the baseline's security; g2: delta at or below the ceiling."""
    g1 = entry[sec_field] >= threshold
    g2 = entry["log2_delta"] <= DELTA_CEILING
    return g1 and g2


def feasible_set(lookup: dict, baseline_name: str, sec_field: str = "security") -> dict:
    """Return {tuple_key: entry} for every feasible candidate against this baseline."""
    thr = baseline_threshold(lookup, baseline_name, sec_field)
    return {k: v for k, v in lookup.items() if is_feasible(v, thr, sec_field)}
