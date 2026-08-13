#!/usr/bin/env python3
"""Algebra/range regression tests for the migrated SOCI-plus protocol flow."""
import random

N = (1 << 521) - 1  # large odd modulus; operands stay far inside the range
MID = N // 2
rng = random.Random(7)


def scmp_view(x, y):
    """Return (encrypted-bit plaintext, CSP-visible randomized difference)."""
    r3 = rng.randrange(1, 1 << 128)
    r = rng.randrange(1, r3 + 1)
    r4 = MID - r
    pi = rng.randrange(2)
    if pi == 0:
        d = (r3 * (x - y) + r3 + r4) % N
    else:
        d = (r3 * (y - x) + r4) % N
    u0 = 0 if d > MID else 1
    return (u0 if pi == 0 else 1 - u0), d


def smul_view(x, y):
    r1 = rng.randrange(1 << 127, 1 << 128)
    r2 = rng.randrange(1 << 127, 1 << 128)
    packing_base = 1 << 130
    visible_x, visible_y = x + r1, y + r2
    packed = visible_x * packing_base + visible_y
    # CSP follows SOCI-plus: one decryption, then quotient/remainder unpacking.
    visible_x, visible_y = divmod(packed, packing_base)
    product = visible_x * visible_y - r2 * x - r1 * y - r1 * r2
    return product, packed, visible_x, visible_y


def sdiv(x, y, bits):
    quotient = 0
    remainder = x
    for step in reversed(range(bits)):
        shifted = y << step
        less, _ = scmp_view(remainder, shifted)
        take = 1 - less
        quotient += take << step
        subtraction, _, _, _ = smul_view(take, shifted)
        remainder -= subtraction
    return quotient, remainder


for x in range(-100, 101):
    for y in range(-100, 101):
        bit, visible = scmp_view(x, y)
        assert bit == int(x < y)
        # For non-trivial pairs CSP must not receive either original operand.
        if x != y:
            assert visible not in (x % N, y % N)

for _ in range(1000):
    x, y = rng.randrange(-100000, 100001), rng.randrange(-100000, 100001)
    product, packed, visible_x, visible_y = smul_view(x, y)
    assert product == x * y
    assert visible_x != x and visible_y != y
    assert packed != x and packed != y

for x in range(0, 512):
    for y in range(1, 65):
        quotient, remainder = sdiv(x, y, 10)
        assert (quotient, remainder) == divmod(x, y)

print("SOCI-plus protocol algebra tests passed")
