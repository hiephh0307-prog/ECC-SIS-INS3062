"""Benchmark runner comparing ECC (secp256r1, secp256k1, secp384r1) against pure-Python RSA."""

from __future__ import annotations

import secrets
import time
from typing import Any

from ecc_core import (
    SECP256K1,
    SECP256R1,
    SECP384R1,
    ecdh_shared_secret,
    generate_keypair,
    sign as ecdsa_sign,
    verify as ecdsa_verify,
)
from .rsa_pure import generate_rsa_keypair

SECURITY_EQUIVALENCE_TABLE = [
    {
        "security_bits": 80,
        "ecc_bits": 160,
        "rsa_bits": 1024,
        "ecc_pubkey_bytes": 21,
        "rsa_pubkey_bytes": 128,
        "ecc_sig_bytes": 40,
        "rsa_sig_bytes": 128,
        "ratio_key": round(1024 / 160, 2),
    },
    {
        "security_bits": 112,
        "ecc_bits": 224,
        "rsa_bits": 2048,
        "ecc_pubkey_bytes": 29,
        "rsa_pubkey_bytes": 256,
        "ecc_sig_bytes": 56,
        "rsa_sig_bytes": 256,
        "ratio_key": round(2048 / 224, 2),
    },
    {
        "security_bits": 128,
        "ecc_bits": 256,
        "rsa_bits": 3072,
        "ecc_pubkey_bytes": 33,  # compressed SEC1
        "rsa_pubkey_bytes": 384,
        "ecc_sig_bytes": 64,
        "rsa_sig_bytes": 384,
        "ratio_key": round(3072 / 256, 2),
    },
    {
        "security_bits": 192,
        "ecc_bits": 384,
        "rsa_bits": 7680,
        "ecc_pubkey_bytes": 49,  # compressed SEC1
        "rsa_pubkey_bytes": 960,
        "ecc_sig_bytes": 96,
        "rsa_sig_bytes": 960,
        "ratio_key": round(7680 / 384, 2),
    },
    {
        "security_bits": 256,
        "ecc_bits": 521,
        "rsa_bits": 15360,
        "ecc_pubkey_bytes": 67,
        "rsa_pubkey_bytes": 1920,
        "ecc_sig_bytes": 132,
        "rsa_sig_bytes": 1920,
        "ratio_key": round(15360 / 521, 2),
    },
]


def _benchmark_ecc_curve(curve: Any, iterations: int = 5) -> dict[str, Any]:
    msg = b"ECC Secure Information System Benchmark Payload 2026"

    # Keygen
    t0 = time.perf_counter()
    alice = None
    bob = None
    for _ in range(iterations):
        alice = generate_keypair(curve)
        bob = generate_keypair(curve)
    keygen_ms = ((time.perf_counter() - t0) / (2 * iterations)) * 1000.0
    assert alice is not None and bob is not None

    # Sign
    t0 = time.perf_counter()
    sig = None
    for _ in range(iterations):
        sig = ecdsa_sign(alice.private_key, msg, curve)
    sign_ms = ((time.perf_counter() - t0) / iterations) * 1000.0
    assert sig is not None

    # Verify
    t0 = time.perf_counter()
    for _ in range(iterations):
        ok = ecdsa_verify(alice.public_key, msg, sig)
        if not ok:
            raise AssertionError("ECDSA verification failed during benchmark.")
    verify_ms = ((time.perf_counter() - t0) / iterations) * 1000.0

    # ECDH
    t0 = time.perf_counter()
    for _ in range(iterations):
        ecdh_shared_secret(alice.private_key, bob.public_key)
    ecdh_ms = ((time.perf_counter() - t0) / iterations) * 1000.0

    return {
        "algorithm": f"ECC ({curve.name})",
        "family": "ECC",
        "key_bits": curve.bit_size,
        "security_bits": curve.bit_size // 2,
        "public_key_bytes_compressed": len(alice.public_key.to_bytes(compressed=True)),
        "public_key_bytes_uncompressed": len(alice.public_key.to_bytes(compressed=False)),
        "signature_bytes": len(sig.to_p1363()),
        "keygen_ms": round(keygen_ms, 3),
        "sign_ms": round(sign_ms, 3),
        "verify_ms": round(verify_ms, 3),
        "key_exchange_or_enc_ms": round(ecdh_ms, 3),
    }


def _benchmark_rsa(bits: int, keygen_iters: int = 2, op_iters: int = 5) -> dict[str, Any]:
    msg = b"ECC Secure Information System Benchmark Payload 2026"

    t0 = time.perf_counter()
    pub, priv = None, None
    for _ in range(keygen_iters):
        pub, priv = generate_rsa_keypair(bits)
    keygen_ms = ((time.perf_counter() - t0) / keygen_iters) * 1000.0
    assert pub is not None and priv is not None

    t0 = time.perf_counter()
    sig = b""
    for _ in range(op_iters):
        sig = priv.sign(msg)
    sign_ms = ((time.perf_counter() - t0) / op_iters) * 1000.0

    t0 = time.perf_counter()
    for _ in range(op_iters):
        if not pub.verify(msg, sig):
            raise AssertionError("RSA verification failed during benchmark.")
    verify_ms = ((time.perf_counter() - t0) / op_iters) * 1000.0

    secret_int = secrets.randbits(256)
    t0 = time.perf_counter()
    for _ in range(op_iters):
        ct = pub.encrypt_int(secret_int)
        pt = priv.decrypt_int(ct)
        if pt != secret_int:
            raise AssertionError("RSA encrypt/decrypt mismatch.")
    enc_dec_ms = ((time.perf_counter() - t0) / op_iters) * 1000.0

    security_map = {1024: 80, 2048: 112, 3072: 128}
    return {
        "algorithm": f"RSA-{bits}",
        "family": "RSA",
        "key_bits": bits,
        "security_bits": security_map.get(bits, bits // 16),
        "public_key_bytes_compressed": pub.byte_size,
        "public_key_bytes_uncompressed": pub.byte_size,
        "signature_bytes": len(sig),
        "keygen_ms": round(keygen_ms, 3),
        "sign_ms": round(sign_ms, 3),
        "verify_ms": round(verify_ms, 3),
        "key_exchange_or_enc_ms": round(enc_dec_ms, 3),
    }


def benchmark_affine_vs_jacobian(iterations: int = 5) -> dict[str, Any]:
    """Compare scalar multiplication performance: Affine vs Jacobian projective coordinates."""
    k = secrets.randbelow(SECP256R1.n - 1) + 1
    G = SECP256R1.G

    t0 = time.perf_counter()
    p_aff = None
    for _ in range(iterations):
        p_aff = G.scalar_mul_affine(k)
    affine_ms = ((time.perf_counter() - t0) / iterations) * 1000.0

    t0 = time.perf_counter()
    p_jac = None
    for _ in range(iterations):
        p_jac = G.scalar_mul_jacobian(k)
    jacobian_ms = ((time.perf_counter() - t0) / iterations) * 1000.0

    assert p_aff == p_jac
    return {
        "curve": SECP256R1.name,
        "iterations": iterations,
        "affine_ms": round(affine_ms, 3),
        "jacobian_ms": round(jacobian_ms, 3),
        "speedup": round(affine_ms / jacobian_ms, 2) if jacobian_ms > 0 else 0.0,
    }


def run_quick_benchmark() -> dict[str, Any]:
    """Fast benchmark suitable for interactive Web UI execution (~1-2 seconds)."""
    results = [
        _benchmark_ecc_curve(SECP256R1, iterations=3),
        _benchmark_ecc_curve(SECP256K1, iterations=3),
        _benchmark_ecc_curve(SECP384R1, iterations=2),
        _benchmark_rsa(1024, keygen_iters=1, op_iters=3),
        _benchmark_rsa(2048, keygen_iters=1, op_iters=3),
    ]
    coord_cmp = benchmark_affine_vs_jacobian(iterations=3)
    return {
        "mode": "quick",
        "results": results,
        "coordinate_comparison": coord_cmp,
        "security_equivalence": SECURITY_EQUIVALENCE_TABLE,
    }


def run_full_benchmark() -> dict[str, Any]:
    """Comprehensive benchmark including RSA-3072 (128-bit security parity with ECC-256)."""
    results = [
        _benchmark_ecc_curve(SECP256R1, iterations=5),
        _benchmark_ecc_curve(SECP256K1, iterations=5),
        _benchmark_ecc_curve(SECP384R1, iterations=3),
        _benchmark_rsa(1024, keygen_iters=2, op_iters=5),
        _benchmark_rsa(2048, keygen_iters=2, op_iters=5),
        _benchmark_rsa(3072, keygen_iters=1, op_iters=3),
    ]
    coord_cmp = benchmark_affine_vs_jacobian(iterations=5)
    return {
        "mode": "full",
        "results": results,
        "coordinate_comparison": coord_cmp,
        "security_equivalence": SECURITY_EQUIVALENCE_TABLE,
    }


if __name__ == "__main__":
    import json

    report = run_full_benchmark()
    print(json.dumps(report, indent=2))
