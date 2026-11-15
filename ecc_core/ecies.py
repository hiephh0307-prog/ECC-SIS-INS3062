"""ECIES (Elliptic Curve Integrated Encryption Scheme) & Authenticated E2EE Envelope."""

from __future__ import annotations

from dataclasses import dataclass

from .cipher import aes256_gcm_decrypt, aes256_gcm_encrypt
from .curves import Point
from .ecdh import ecdh_shared_secret, generate_keypair, hkdf_sha256
from .ecdsa import ECDSASignature, sign as ecdsa_sign, verify as ecdsa_verify

ECIES_HKDF_INFO = b"ECC-SIS-v1|AES-256-GCM"
SIG_DOMAIN_PREFIX = b"ECC-SIS-SIG-v1|"


@dataclass(frozen=True)
class ECIESEncryptedPacket:
    """Standard ECIES encrypted payload (ephemeral pubkey + nonce + AES-GCM ciphertext||tag)."""

    curve_name: str
    ephemeral_public_key: bytes  # SEC1 uncompressed (0x04 || x || y)
    nonce: bytes  # 12 bytes
    ciphertext: bytes  # ciphertext || 16-byte GCM tag

    def to_dict(self) -> dict[str, str]:
        return {
            "curve": self.curve_name,
            "ephemeral_public_key": self.ephemeral_public_key.hex(),
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
        }


def ecies_encrypt(
    recipient_public_key: Point,
    plaintext: bytes,
    aad: bytes = b"",
) -> ECIESEncryptedPacket:
    """Encrypt plaintext for recipient_public_key using Ephemeral ECDH + HKDF-SHA256 + AES-256-GCM."""
    curve = recipient_public_key.curve
    eph = generate_keypair(curve)
    eph_pub_bytes = eph.public_key.to_bytes(compressed=False)

    shared_secret = ecdh_shared_secret(eph.private_key, recipient_public_key)
    aes_key = hkdf_sha256(
        ikm=shared_secret,
        length=32,
        salt=eph_pub_bytes,
        info=ECIES_HKDF_INFO,
    )
    nonce, ciphertext = aes256_gcm_encrypt(aes_key, plaintext, aad=aad)
    return ECIESEncryptedPacket(
        curve_name=curve.name,
        ephemeral_public_key=eph_pub_bytes,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def ecies_decrypt(
    recipient_private_key: int,
    packet: ECIESEncryptedPacket,
    recipient_curve_point: Point,
    aad: bytes = b"",
) -> bytes:
    """Decrypt an ECIESEncryptedPacket using the recipient's private key."""
    curve = recipient_curve_point.curve
    eph_pub = curve.decode_point(packet.ephemeral_public_key)
    shared_secret = ecdh_shared_secret(recipient_private_key, eph_pub)
    aes_key = hkdf_sha256(
        ikm=shared_secret,
        length=32,
        salt=packet.ephemeral_public_key,
        info=ECIES_HKDF_INFO,
    )
    return aes256_gcm_decrypt(aes_key, packet.nonce, packet.ciphertext, aad=aad)


def build_signature_payload(
    ephemeral_public_key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    """Canonical byte string signed by ECDSA to authenticate an E2EE envelope."""
    return SIG_DOMAIN_PREFIX + ephemeral_public_key + nonce + ciphertext + aad


def sign_encrypted_packet(
    sender_private_key: int,
    packet: ECIESEncryptedPacket,
    sender_public_key: Point,
    aad: bytes = b"",
) -> ECDSASignature:
    """Sign an ECIESEncryptedPacket with sender's ECDSA private key."""
    payload = build_signature_payload(
        packet.ephemeral_public_key,
        packet.nonce,
        packet.ciphertext,
        aad,
    )
    return ecdsa_sign(sender_private_key, payload, sender_public_key.curve)


def verify_encrypted_packet_signature(
    sender_public_key: Point,
    packet: ECIESEncryptedPacket,
    signature: ECDSASignature,
    aad: bytes = b"",
) -> bool:
    """Verify sender's ECDSA signature on an ECIESEncryptedPacket."""
    payload = build_signature_payload(
        packet.ephemeral_public_key,
        packet.nonce,
        packet.ciphertext,
        aad,
    )
    return ecdsa_verify(sender_public_key, payload, signature)
