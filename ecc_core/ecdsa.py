"""ECDSA (Elliptic Curve Digital Signature Algorithm) with RFC 6979 deterministic nonces."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .curves import EllipticCurve, Point
from .field import mod_inv


@dataclass(frozen=True)
class ECDSASignature:
    """ECDSA signature (r, s) with P1363 and ASN.1 DER serialization."""

    r: int
    s: int
    order_byte_size: int = 32

    def to_p1363(self) -> bytes:
        """Encode as IEEE P1363 fixed-length (r || s), compatible with WebCrypto."""
        return self.r.to_bytes(self.order_byte_size, "big") + self.s.to_bytes(self.order_byte_size, "big")

    def to_hex(self) -> str:
        return self.to_p1363().hex()

    @classmethod
    def from_p1363(cls, sig_bytes: bytes, order_byte_size: int = 32) -> ECDSASignature:
        if len(sig_bytes) != 2 * order_byte_size:
            raise ValueError(
                f"Invalid P1363 signature length: expected {2 * order_byte_size}, got {len(sig_bytes)}."
            )
        r = int.from_bytes(sig_bytes[:order_byte_size], "big")
        s = int.from_bytes(sig_bytes[order_byte_size:], "big")
        return cls(r=r, s=s, order_byte_size=order_byte_size)

    @staticmethod
    def _encode_der_int(val: int) -> bytes:
        b = val.to_bytes((val.bit_length() + 7) // 8 or 1, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b

    def to_der(self) -> bytes:
        """Encode signature in ASN.1 DER format."""
        r_enc = self._encode_der_int(self.r)
        s_enc = self._encode_der_int(self.s)
        body = r_enc + s_enc
        return b"\x30" + bytes([len(body)]) + body


def _bits2int(data: bytes, qlen: int) -> int:
    v = int.from_bytes(data, "big")
    blen = len(data) * 8
    if blen > qlen:
        v >>= blen - qlen
    return v


def _int2octets(val: int, rlen: int) -> bytes:
    return val.to_bytes(rlen, "big")


def _bits2octets(data: bytes, n: int, qlen: int, rlen: int) -> bytes:
    z1 = _bits2int(data, qlen)
    z2 = z1 % n
    return _int2octets(z2, rlen)


def hash_message_to_int(message: bytes, curve: EllipticCurve) -> tuple[bytes, int]:
    """Hash message with SHA-256 and truncate/reduce to curve order bit length."""
    digest = hashlib.sha256(message).digest()
    z = _bits2int(digest, curve.n.bit_length())
    return digest, z


def rfc6979_generate_k(private_key: int, digest: bytes, curve: EllipticCurve, extra_attempt: int = 0) -> int:
    """Deterministic nonce generation per RFC 6979 (HMAC-SHA256)."""
    n = curve.n
    qlen = n.bit_length()
    rlen = (qlen + 7) // 8
    hlen = 32  # SHA-256

    x_oct = _int2octets(private_key, rlen)
    h1_oct = _bits2octets(digest, n, qlen, rlen)

    v = b"\x01" * hlen
    k_mac = b"\x00" * hlen

    k_mac = hmac.new(k_mac, v + b"\x00" + x_oct + h1_oct, hashlib.sha256).digest()
    v = hmac.new(k_mac, v, hashlib.sha256).digest()
    k_mac = hmac.new(k_mac, v + b"\x01" + x_oct + h1_oct, hashlib.sha256).digest()
    v = hmac.new(k_mac, v, hashlib.sha256).digest()

    skipped = 0
    while True:
        t = bytearray()
        while len(t) * 8 < qlen:
            v = hmac.new(k_mac, v, hashlib.sha256).digest()
            t.extend(v)
        k_cand = _bits2int(bytes(t), qlen)
        if 1 <= k_cand < n:
            if skipped == extra_attempt:
                return k_cand
            skipped += 1
        k_mac = hmac.new(k_mac, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k_mac, v, hashlib.sha256).digest()


def sign(
    private_key: int,
    message: bytes,
    curve: EllipticCurve,
    low_s: bool = True,
    nonce_override: int | None = None,
) -> ECDSASignature:
    """Sign message with ECDSA (SHA-256 + RFC 6979 deterministic k).

    nonce_override is strictly for educational testing (e.g., demonstrating nonce-reuse attacks).
    """
    n = curve.n
    if not (1 <= private_key < n):
        raise ValueError("Private key out of range [1, n - 1].")

    digest, z = hash_message_to_int(message, curve)
    attempt = 0
    while True:
        k = nonce_override if nonce_override is not None else rfc6979_generate_k(private_key, digest, curve, attempt)
        if not (1 <= k < n):
            if nonce_override is not None:
                raise ValueError("Invalid nonce_override.")
            attempt += 1
            continue

        R = k * curve.G
        if R.is_infinity or R.x is None:
            if nonce_override is not None:
                raise ValueError("Nonce resulted in point at infinity.")
            attempt += 1
            continue

        r = R.x % n
        if r == 0:
            if nonce_override is not None:
                raise ValueError("Nonce resulted in r == 0.")
            attempt += 1
            continue

        k_inv = mod_inv(k, n)
        s = (k_inv * (z + r * private_key)) % n
        if s == 0:
            if nonce_override is not None:
                raise ValueError("Nonce resulted in s == 0.")
            attempt += 1
            continue

        if low_s and s > n // 2:
            s = n - s

        return ECDSASignature(r=r, s=s, order_byte_size=curve.order_byte_size)


def verify(public_key: Point, message: bytes, signature: ECDSASignature) -> bool:
    """Verify an ECDSA signature against a public key Point and message bytes."""
    curve = public_key.curve
    n = curve.n
    r, s = signature.r, signature.s

    if public_key.is_infinity or not curve.is_on_curve_coords(public_key.x, public_key.y):
        return False
    if not (1 <= r < n and 1 <= s < n):
        return False

    _, z = hash_message_to_int(message, curve)
    w = mod_inv(s, n)
    u1 = (z * w) % n
    u2 = (r * w) % n

    P = (u1 * curve.G).add_affine(u2 * public_key)
    if P.is_infinity or P.x is None:
        return False
    return (P.x % n) == r


def recover_private_key_from_reused_nonce(
    curve: EllipticCurve,
    msg1: bytes,
    sig1: ECDSASignature,
    msg2: bytes,
    sig2: ECDSASignature,
) -> int:
    """Educational attack: recover ECDSA private key when two distinct messages share nonce k.

    Since r1 == r2 (same k*G), we have:
      s1 - s2 = k^-1 * (z1 - z2) mod n  =>  k = (z1 - z2) * (s1 - s2)^-1 mod n
      d = (s1 * k - z1) * r^-1 mod n
    """
    n = curve.n
    if sig1.r != sig2.r:
        raise ValueError("Signatures do not share the same r (nonce was not reused).")
    _, z1 = hash_message_to_int(msg1, curve)
    _, z2 = hash_message_to_int(msg2, curve)

    # Test sign combinations in case low-s normalization flipped sig1.s or sig2.s.
    # Checking (k * G).x % n == sig1.r uniquely identifies the true nonce +/-k.
    r_inv = mod_inv(sig1.r, n)
    for s1_cand in (sig1.s, (-sig1.s) % n):
        for s2_cand in (sig2.s, (-sig2.s) % n):
            s_diff = (s1_cand - s2_cand) % n
            if s_diff == 0:
                continue
            k = ((z1 - z2) * mod_inv(s_diff, n)) % n
            R = k * curve.G
            if R.is_infinity or R.x is None or (R.x % n) != sig1.r:
                continue
            d = ((s1_cand * k - z1) * r_inv) % n
            if 1 <= d < n:
                return d
    raise ValueError("Could not recover private key from the provided signatures.")
