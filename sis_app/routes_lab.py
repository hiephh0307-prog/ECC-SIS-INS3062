"""API routes for the interactive ECC Algorithm Study Lab & ECC vs RSA Benchmarks."""

from __future__ import annotations

import secrets
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from benchmarks.runner import run_full_benchmark, run_quick_benchmark
from ecc_core import (
    TOY_P97,
    InvalidTagError,
    Point,
    ecdh_shared_secret,
    ecies_decrypt,
    ecies_encrypt,
    generate_keypair,
    get_curve,
    hkdf_sha256,
    recover_private_key_from_reused_nonce,
    sign as ecdsa_sign,
    verify as ecdsa_verify,
)

router = APIRouter(prefix="/api", tags=["ECC Lab & Benchmarks"])


class PointOpsRequest(BaseModel):
    px: int = Field(default=2, ge=0, lt=97)
    py: int = Field(default=4, ge=0, lt=97)
    qx: int = Field(default=1, ge=0, lt=97)
    qy: int = Field(default=43, ge=0, lt=97)
    k: int = Field(default=7, ge=1, le=200)


class CurveSelectRequest(BaseModel):
    curve: Literal["secp256r1", "secp256k1", "secp384r1", "toy_p97"] = "secp256r1"


class ECDSADemoRequest(BaseModel):
    curve: Literal["secp256r1", "secp256k1", "secp384r1"] = "secp256r1"
    message: str = Field(default="Transfer $1000 to Bob", min_length=1, max_length=2000)
    tampered_message: str | None = None
    demonstrate_nonce_reuse: bool = False


class ECIESDemoRequest(BaseModel):
    curve: Literal["secp256r1", "secp256k1", "secp384r1"] = "secp256r1"
    plaintext: str = Field(default="Confidential Medical Record #42", min_length=1, max_length=4000)
    aad: str = Field(default="dept=cardiology;classification=secret", max_length=500)
    simulate_tamper: bool = False


@router.get("/lab/toy-curve")
def get_toy_curve_points() -> dict:
    """Return all points on toy_p97: y^2 = x^3 + 3x + 2 (mod 97) for visualization."""
    pts = TOY_P97.enumerate_points()
    finite_pts = [[pt.x, pt.y] for pt in pts if not pt.is_infinity]
    return {
        "curve": TOY_P97.name,
        "equation": f"y^2 ≡ x^3 + {TOY_P97.a}x + {TOY_P97.b} (mod {TOY_P97.p})",
        "p": TOY_P97.p,
        "a": TOY_P97.a,
        "b": TOY_P97.b,
        "order": TOY_P97.n,
        "generator": [TOY_P97.gx, TOY_P97.gy],
        "points": finite_pts,
    }


@router.post("/lab/point-ops")
def compute_toy_point_ops(req: PointOpsRequest) -> dict:
    """Perform P + Q, 2P, and k*P with step-by-step Double-and-Add trace on toy_p97."""
    try:
        P = Point(TOY_P97, req.px, req.py, validate=True)
        Q = Point(TOY_P97, req.qx, req.qy, validate=True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    sum_pq = P.add_affine(Q)
    doubled_p = P.double_affine()
    k_p, trace = P.scalar_mul_with_trace(req.k)

    def _fmt(pt: Point) -> list[int] | str:
        return "Infinity" if pt.is_infinity else [pt.x, pt.y]  # type: ignore[list-item]

    return {
        "P": _fmt(P),
        "Q": _fmt(Q),
        "P_plus_Q": _fmt(sum_pq),
        "two_P": _fmt(doubled_p),
        "k": req.k,
        "k_binary": bin(req.k)[2:],
        "k_times_P": _fmt(k_p),
        "trace": trace,
    }


@router.post("/lab/ecdh-demo")
def run_ecdh_demo(req: CurveSelectRequest) -> dict:
    """Demonstrate full ECDH handshake + HKDF-SHA256 key derivation."""
    curve = get_curve(req.curve)
    alice = generate_keypair(curve)
    bob = generate_keypair(curve)

    secret_a = ecdh_shared_secret(alice.private_key, bob.public_key)
    secret_b = ecdh_shared_secret(bob.private_key, alice.public_key)
    assert secret_a == secret_b

    aes_key_a = hkdf_sha256(secret_a, length=32, info=b"ECC-SIS-ECDH-DEMO")
    aes_key_b = hkdf_sha256(secret_b, length=32, info=b"ECC-SIS-ECDH-DEMO")

    return {
        "curve": curve.name,
        "alice": {
            "private_key_hex": alice.private_hex(),
            "public_key_hex": alice.public_hex(compressed=False),
            "public_key_compressed_hex": alice.public_hex(compressed=True),
        },
        "bob": {
            "private_key_hex": bob.private_hex(),
            "public_key_hex": bob.public_hex(compressed=False),
            "public_key_compressed_hex": bob.public_hex(compressed=True),
        },
        "shared_secret_alice_hex": secret_a.hex(),
        "shared_secret_bob_hex": secret_b.hex(),
        "shared_secrets_match": secret_a == secret_b,
        "derived_aes256_key_hex": aes_key_a.hex(),
        "aes_keys_match": aes_key_a == aes_key_b,
    }


@router.post("/lab/ecdsa-demo")
def run_ecdsa_demo(req: ECDSADemoRequest) -> dict:
    """Demonstrate RFC 6979 ECDSA sign/verify and optional nonce-reuse key recovery attack."""
    curve = get_curve(req.curve)
    signer = generate_keypair(curve)
    msg_bytes = req.message.encode("utf-8")

    sig1 = ecdsa_sign(signer.private_key, msg_bytes, curve)
    sig2 = ecdsa_sign(signer.private_key, msg_bytes, curve)  # deterministic RFC 6979
    valid_original = ecdsa_verify(signer.public_key, msg_bytes, sig1)

    tampered = req.tampered_message if req.tampered_message is not None else (req.message + " [TAMPERED]")
    valid_tampered = ecdsa_verify(signer.public_key, tampered.encode("utf-8"), sig1)

    result: dict = {
        "curve": curve.name,
        "public_key_hex": signer.public_hex(),
        "message": req.message,
        "signature_p1363_hex": sig1.to_hex(),
        "signature_der_hex": sig1.to_der().hex(),
        "r_hex": hex(sig1.r),
        "s_hex": hex(sig1.s),
        "rfc6979_deterministic_match": sig1.to_hex() == sig2.to_hex(),
        "valid_original": valid_original,
        "tampered_message": tampered,
        "valid_tampered": valid_tampered,
    }

    if req.demonstrate_nonce_reuse:
        reused_k = secrets.randbelow(curve.n - 1) + 1
        m1 = msg_bytes
        m2 = (req.message + " (second tx)").encode("utf-8")
        bad_sig1 = ecdsa_sign(signer.private_key, m1, curve, nonce_override=reused_k)
        bad_sig2 = ecdsa_sign(signer.private_key, m2, curve, nonce_override=reused_k)
        recovered_d = recover_private_key_from_reused_nonce(curve, m1, bad_sig1, m2, bad_sig2)
        result["nonce_reuse_attack"] = {
            "shared_r_hex": hex(bad_sig1.r),
            "actual_private_key_hex": signer.private_hex(),
            "recovered_private_key_hex": recovered_d.to_bytes(curve.order_byte_size, "big").hex(),
            "private_key_compromised": recovered_d == signer.private_key,
        }

    return result


@router.post("/lab/ecies-demo")
def run_ecies_demo(req: ECIESDemoRequest) -> dict:
    """Demonstrate ECIES (Ephemeral ECDH + HKDF-SHA256 + AES-256-GCM)."""
    curve = get_curve(req.curve)
    recipient = generate_keypair(curve)
    aad_bytes = req.aad.encode("utf-8")
    packet = ecies_encrypt(recipient.public_key, req.plaintext.encode("utf-8"), aad=aad_bytes)

    if req.simulate_tamper:
        ct = bytearray(packet.ciphertext)
        ct[0] ^= 0xFF
        from ecc_core import ECIESEncryptedPacket

        tampered_pkt = ECIESEncryptedPacket(
            curve_name=packet.curve_name,
            ephemeral_public_key=packet.ephemeral_public_key,
            nonce=packet.nonce,
            ciphertext=bytes(ct),
        )
        try:
            ecies_decrypt(recipient.private_key, tampered_pkt, recipient.public_key, aad=aad_bytes)
            tamper_rejected = False
            decrypt_status = "Unexpectedly decrypted!"
        except InvalidTagError as exc:
            tamper_rejected = True
            decrypt_status = f"Rejected: {exc}"

        return {
            "curve": curve.name,
            "recipient_public_key_hex": recipient.public_hex(),
            "packet": tampered_pkt.to_dict(),
            "tamper_simulated": True,
            "tamper_rejected": tamper_rejected,
            "status": decrypt_status,
        }

    recovered = ecies_decrypt(recipient.private_key, packet, recipient.public_key, aad=aad_bytes)
    return {
        "curve": curve.name,
        "recipient_public_key_hex": recipient.public_hex(),
        "packet": packet.to_dict(),
        "tamper_simulated": False,
        "decrypted_plaintext": recovered.decode("utf-8"),
        "roundtrip_match": recovered.decode("utf-8") == req.plaintext,
    }


@router.get("/benchmarks/run")
def run_benchmarks(mode: Literal["quick", "full"] = "quick") -> dict:
    """Run live ECC vs RSA benchmarks."""
    return run_full_benchmark() if mode == "full" else run_quick_benchmark()
