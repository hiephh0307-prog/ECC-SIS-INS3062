"""Pure-Python RSA implementation for apples-to-apples benchmarking against pure-Python ECC."""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass

from ecc_core.field import mod_inv

_SMALL_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
)


def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        # Ensure exact bit length and odd
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int
    bit_size: int

    @property
    def byte_size(self) -> int:
        return (self.bit_size + 7) // 8

    def encrypt_int(self, m: int) -> int:
        if not (0 <= m < self.n):
            raise ValueError("Plaintext integer out of range [0, n).")
        return pow(m, self.e, self.n)

    def verify(self, message: bytes, signature: bytes) -> bool:
        digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
        s_int = int.from_bytes(signature, "big")
        if s_int >= self.n:
            return False
        recovered = pow(s_int, self.e, self.n)
        return recovered == (digest % self.n)


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    bit_size: int

    def decrypt_int(self, c: int) -> int:
        return pow(c, self.d, self.n)

    def sign(self, message: bytes) -> bytes:
        digest = int.from_bytes(hashlib.sha256(message).digest(), "big") % self.n
        sig_int = pow(digest, self.d, self.n)
        return sig_int.to_bytes((self.bit_size + 7) // 8, "big")


def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """Generate an RSA keypair of the requested bit size."""
    if bits < 512 or bits % 2 != 0:
        raise ValueError("RSA bit size must be an even integer >= 512.")
    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(half)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            n = p * q
            if n.bit_length() == bits:
                d = mod_inv(e, phi)
                return (
                    RSAPublicKey(n=n, e=e, bit_size=bits),
                    RSAPrivateKey(n=n, e=e, d=d, p=p, q=q, bit_size=bits),
                )
