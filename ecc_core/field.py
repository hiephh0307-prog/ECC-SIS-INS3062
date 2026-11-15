"""Finite field arithmetic over prime fields F_p."""

from __future__ import annotations


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (gcd, x, y) such that a*x + b*y == gcd."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inv(a: int, p: int) -> int:
    """Compute multiplicative inverse of a modulo prime p using Extended Euclidean Algorithm."""
    a_mod = a % p
    if a_mod == 0:
        raise ZeroDivisionError("Cannot compute modular inverse of 0.")
    gcd, x, _ = extended_gcd(a_mod, p)
    if gcd != 1:
        raise ValueError(f"{a} has no modular inverse modulo {p} (gcd={gcd}).")
    return x % p


def legendre_symbol(a: int, p: int) -> int:
    """Compute Legendre symbol (a / p) for odd prime p: returns 0, 1, or p - 1 (-1)."""
    ls = pow(a % p, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def mod_sqrt(a: int, p: int) -> int | None:
    """Compute square root of a modulo prime p using Tonelli-Shanks algorithm.

    Returns r such that r^2 == a (mod p), or None if a is a quadratic non-residue.
    """
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if legendre_symbol(a, p) != 1:
        return None

    # Fast path when p == 3 (mod 4)
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Factor p - 1 = q * 2^s with q odd
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    # Find a quadratic non-residue z
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    while t != 1:
        # Find least i (0 < i < m) such that t^(2^i) == 1 (mod p)
        t2i = t
        i = 0
        for idx in range(1, m):
            t2i = (t2i * t2i) % p
            if t2i == 1:
                i = idx
                break
        if i == 0:
            return None
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p

    return r
