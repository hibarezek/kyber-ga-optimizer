"""
kyberpy_du12_bug.py -- minimal reproduction of the kyber-py du = 12 bug
=======================================================================
kyber-py 1.2.0, PolynomialRing.decode(): for d == 12 the decoded 12-bit
values are reduced modulo q = 3329 instead of 2^12 = 4096. This is
correct for public keys (12-bit, uncompressed, values < q) but wrong for
ciphertexts compressed with du = 12, whose values range over 0..4095.

The script compresses a random polynomial with d = 12, encodes it,
decodes it and compares the result with the compressed values.
Run from the repository root:
    python analysis/kyberpy_du12_bug.py
"""

import random

from kyber_py.polynomials.polynomials import PolynomialRing

random.seed(0)
R = PolynomialRing()
D = 12

for d in (10, 11, D):
    poly = R([random.randrange(3329) for _ in range(256)]).compress(d)
    before = list(poly.coeffs)
    after = R.decode(poly.encode(d), d).coeffs
    wrong = [(a, b) for a, b in zip(before, after) if a != b]
    shifts = sorted({b - a for a, b in wrong})
    print(f"d = {d:>2}: {len(wrong):>3} of 256 coefficients changed by the "
          f"encode/decode round trip" + (f" (shift {shifts})" if wrong else ""))
