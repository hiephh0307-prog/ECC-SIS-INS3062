"""ECDH (Elliptic Curve Diffie-Hellman) and RFC 5869 HKDF-SHA256 key derivation."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from .curves import EllipticCurve, Point, get_curve


@dataclass(frozen=True)
class ECCKeyPair:
    """ECC private/public keypair on a specific EllipticCurve."""

    curve: EllipticCurve
    private_key: int
    public_key: Point

    def private_bytes(self) -> bytes:
        return self.private_key.to_bytes(self.curve.order_byte_size, "big")

    def private_hex(self) -> str:
        return self.private_bytes().hex()

    def public_hex(self, compressed: bool = False) -> str:
        return self.public_key.to_hex(compressed=compressed)

    def to_dict(self, include_private: bool = False) -> dict:
        data = {
            "curve": self.curve.name,
            "public_key": self.public_hex(compressed=False),
            "public_key_compressed": self.public_hex(compressed=True),
        }
        if include_private:
            data["private_key"] = self.private_hex()
        return data


def generate_keypair(curve: EllipticCurve | str = "secp256r1") -> ECCKeyPair:
    """Generate a cryptographically secure ECC keypair using secrets."""
    c = get_curve(curve) if isinstance(curve, str) else curve
    # Private key d in [1, n - 1]
    d = secrets.randbelow(c.n - 1) + 1
    Q = d * c.G
    return ECCKeyPair(curve=c, private_key=d, public_key=Q)


def keypair_from_private_hex(private_hex: str, curve: EllipticCurve | str = "secp256r1") -> ECCKeyPair:
    """Reconstruct an ECCKeyPair from a hex-encoded private scalar."""
    c = get_curve(curve) if isinstance(curve, str) else curve
    d = int(private_hex, 16)
    if not (1 <= d < c.n):
        raise ValueError("Private key scalar must satisfy 1 <= d < n.")
    return ECCKeyPair(curve=c, private_key=d, public_key=d * c.G)


def validate_public_key(public_key: Point) -> None:
    """Perform NIST SP 800-56A public key validation."""
    if public_key.is_infinity:
        raise ValueError("Public key cannot be point at infinity.")
    if not public_key.curve.is_on_curve_coords(public_key.x, public_key.y):
        raise ValueError("Public key is not on the curve.")
    # Subgroup check: n * Q == O (for cofactor h == 1, on-curve implies in subgroup, but verify)
    if (public_key.curve.n * public_key) != public_key.curve.infinity:
        raise ValueError("Public key does not belong to the prime-order subgroup.")


def ecdh_shared_secret(private_key: int, peer_public_key: Point) -> bytes:
    """Compute raw ECDH shared secret Z (big-endian x-coordinate of d * Q_peer).

    Matches NIST SP 800-56A and WebCrypto ECDH deriveBits output.
    """
    curve = peer_public_key.curve
    if not (1 <= private_key < curve.n):
        raise ValueError("Private key out of valid range [1, n - 1].")
    if peer_public_key.is_infinity or not curve.is_on_curve_coords(peer_public_key.x, peer_public_key.y):
        raise ValueError("Invalid peer public key.")

    shared_point = private_key * peer_public_key
    if shared_point.is_infinity or shared_point.x is None:
        raise ValueError("Invalid ECDH shared point (point at infinity).")
    return shared_point.x.to_bytes(curve.coord_byte_size, "big")


def hkdf_sha256_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract using HMAC-SHA256."""
    actual_salt = salt if salt else b"\x00" * 32
    return hmac.new(actual_salt, ikm, hashlib.sha256).digest()


def hkdf_sha256_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand using HMAC-SHA256."""
    hash_len = 32
    if length < 0 or length > 255 * hash_len:
        raise ValueError("HKDF output length must be between 0 and 255 * 32 bytes.")
    n_blocks = (length + hash_len - 1) // hash_len
    okm = bytearray()
    t = b""
    for counter in range(1, n_blocks + 1):
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
    return bytes(okm[:length])


def hkdf_sha256(ikm: bytes, length: int = 32, salt: bytes = b"", info: bytes = b"") -> bytes:
    """Derive symmetric key material using RFC 5869 HKDF-SHA256."""
    prk = hkdf_sha256_extract(salt, ikm)
    return hkdf_sha256_expand(prk, info, length)
