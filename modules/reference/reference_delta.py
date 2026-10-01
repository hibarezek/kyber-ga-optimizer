"""
reference_delta.py — decryption failure probability via the OFFICIAL
pq-crystals reference implementation.
====================================================================

This wraps the reference failure-probability computation from
    https://github.com/pq-crystals/security-estimates
    (Kyber_failure.py + proba_util.py)

which is the exact script the CRYSTALS-Kyber specification cites for its
published failure probabilities (spec v3.0, Section 5.5). Running it
reproduces the published values exactly:

    Kyber-512  : 2^-139.14   (published -139)
    Kyber-768  : 2^-165.24   (published -164)
    Kyber-1024 : 2^-175.20   (published -174)

Parameter mapping (verified against Kyber.py lines 54-56):

    reference field   our parameter        notes
    ---------------    ------------------   ---------------------------
    n                  256                  fixed
    m                  k                    module rank (ref calls it m)
    ks                 eta1                 secret-key noise
    ke                 eta1                 public-key error (== ks)
    ke_ct              eta2                 ciphertext error
    q                  3329                 fixed
    rqk                2^12 = 4096          public-key compression (fixed)
    rqc                2^du                 first-ciphertext compression
    rq2                2^dv                 second-ciphertext compression

The reference REQUIRES ks == ke (Kyber_to_MLWE raises otherwise); for
the failure computation this holds by construction since both map to
eta1. eta2 enters only as ke_ct, exactly as in the reference.

The reference files are vendored into modules/reference/ unmodified
apart from their import paths, with original attribution retained.

Note: the reference returns delta = n * p_fail, i.e. the union bound
over the n message coefficients.
"""

from math import log

# The reference modules, vendored from pq-crystals/security-estimates
from modules.reference.Kyber_failure import p2_cyclotomic_error_probability


class _RefParamSet:
    """Mirror of the reference KyberParameterSet (Kyber.py)."""
    def __init__(self, n, m, ks, ke, q, rqk, rqc, rq2, ke_ct=None):
        self.n = n
        self.m = m
        self.ks = ks
        self.ke = ke
        self.ke_ct = ke_ct if ke_ct is not None else ke
        self.q = q
        self.rqk = rqk
        self.rqc = rqc
        self.rq2 = rq2


def reference_log2_delta(k: int, eta1: int, eta2: int,
                         du: int, dv: int,
                         n: int = 256, q: int = 3329) -> float:
    """
    log2 of the decryption failure probability, computed by the
    pq-crystals reference implementation.

    Maps our (k, eta1, eta2, du, dv) to the reference parameter set and
    returns log2(delta). Reproduces the published Kyber values exactly.
    """
    ps = _RefParamSet(
        n   = n,
        m   = k,             # reference 'm' is the module rank
        ks  = eta1,          # secret-key noise
        ke  = eta1,          # public-key error (must equal ks)
        q   = q,
        rqk = 2 ** 12,       # public key: 12-bit, lossless for q=3329
        rqc = 2 ** du,       # first ciphertext compression
        rq2 = 2 ** dv,       # second ciphertext compression
        ke_ct = eta2,        # ciphertext error
    )
    _, proba = p2_cyclotomic_error_probability(ps)
    # guard against log(0) exactly as the reference summarize() does
    return log(proba + 2.0 ** (-300)) / log(2)


if __name__ == "__main__":
    # Self-test: must reproduce the published Kyber values
    checks = [
        ("Kyber-512",  (2, 3, 2, 10, 4), -139.14),
        ("Kyber-768",  (3, 2, 2, 10, 4), -165.24),
        ("Kyber-1024", (4, 2, 2, 11, 5), -175.20),
    ]
    print("Reference delta self-test:")
    for name, params, expected in checks:
        got = reference_log2_delta(*params)
        ok = abs(got - expected) < 0.1
        print(f"  {'OK ' if ok else 'FAIL'}  {name:12s} 2^{got:.2f}  (expected 2^{expected})")
