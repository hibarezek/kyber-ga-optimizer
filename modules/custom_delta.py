"""
custom_delta.py — fast custom decryption-failure estimator
============================================================
This is OUR OWN implementation (fixed-point scaled-integer convolution),
independent of the vendored pq-crystals reference. It exists as an
engineering artifact and a Module 0 cross-check, NOT as the source of
truth for the lookup table — that role belongs to
`modules/reference/reference_delta.py` (spec-exact).

History: earlier attempts at this computation (raw floats -> FFT
convolution, Python Fraction, mpmath at high precision) either
underflowed or were too slow to run across a large candidate space.
This fixed-point / scaled-integer approach with binary-exponentiation
convolution was the working solution, reproducing the reference to
within a small, consistent gap (see Module 0's comparison).

This file has NO dependency on m2_precompute.py, and m2_precompute.py
has no dependency on this file — they are independent by design.
"""

import math
from collections import defaultdict

N = 256
Q = 3329
PREC = 512
SCALE = 1 << PREC
FAIL_CAP = Q // 4 + 1


def cbd_pmf(eta: int) -> dict:
    """CBD(eta) PMF as scaled integers (numerator over SCALE)."""
    denom = 4 ** eta
    return {x: (math.comb(2 * eta, eta + x) * SCALE) // denom
            for x in range(-eta, eta + 1)}


def product_pmf(pmf_a: dict, pmf_b: dict) -> dict:
    """PMF of product A*B, scaled-integer inputs and output."""
    result = defaultdict(int)
    for a, pa in pmf_a.items():
        for b, pb in pmf_b.items():
            result[a * b] += (pa * pb) >> PREC
    return dict(result)


def compress_ele(x: int, d: int, q: int = Q) -> int:
    t = 1 << d
    y = ((t * x) + (q // 2)) // q
    return y % t


def decompress_ele(y: int, d: int, q: int = Q) -> int:
    half = 1 << (d - 1)
    return (q * y + half) >> d


def compression_error_pmf(d: int, q: int = Q) -> dict:
    counts = defaultdict(int)
    for x in range(q):
        xc = decompress_ele(compress_ele(x, d, q), d, q)
        err = (xc - x) % q
        if err > q // 2:
            err -= q
        counts[err] += 1
    return {e: (c * SCALE) // q for e, c in counts.items()}


def convolve(pmf_a: dict, pmf_b: dict) -> dict:
    if not pmf_a:
        return dict(pmf_b)
    if not pmf_b:
        return dict(pmf_a)
    result = defaultdict(int)
    for x, px in pmf_a.items():
        for y, py in pmf_b.items():
            s = x + y
            if s > FAIL_CAP:
                s = FAIL_CAP
            elif s < -FAIL_CAP:
                s = -FAIL_CAP
            result[s] += (px * py) >> PREC
    return dict(result)


def convolve_power(pmf: dict, power: int) -> dict:
    """power-fold self-convolution via binary exponentiation (scaled int)."""
    if power == 0:
        return {0: SCALE}
    result = None
    base = dict(pmf)
    p = power
    while p > 0:
        if p & 1:
            result = base if result is None else convolve(result, base)
        p >>= 1
        if p > 0:
            base = convolve(base, base)
    return result


def compute_delta(k: int, eta1: int, eta2: int,
                  du: int, dv: int,
                  n: int = N, q: int = Q) -> float:
    """
    Our own fast estimate of log2(decryption failure probability).
    Independent implementation from the vendored reference -- used as
    a Module 0 cross-check, not as the pipeline's source of truth.
    """
    cbd1 = cbd_pmf(eta1)
    cbd2 = cbd_pmf(eta2)
    cu_err = compression_error_pmf(du, q)
    cv_err = compression_error_pmf(dv, q)

    etr  = convolve_power(product_pmf(cbd1, cbd1), k * n)
    ste1 = convolve_power(product_pmf(cbd1, cbd2), k * n)
    e2   = cbd2
    stu  = convolve_power(product_pmf(cbd1, cu_err), k * n)

    total = {0: SCALE}
    for source in (etr, ste1, e2, cv_err, stu):
        total = convolve(total, source)

    threshold = q // 4
    p_fail_scaled = 0
    for x, px in total.items():
        if abs(x) > threshold:
            p_fail_scaled += px

    if p_fail_scaled <= 0:
        return float(-PREC)

    import mpmath as mp
    mp.mp.dps = 80
    p_fail = mp.mpf(p_fail_scaled) / mp.mpf(SCALE)
    delta = 1 - (1 - p_fail) ** n
    return float(mp.log(delta, 2))
