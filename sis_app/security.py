"""ECDSA authentication, public key validation, and session token helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time

from fastapi import Header, HTTPException, status

from ecc_core import ECDSASignature, get_curve, validate_public_key
from ecc_core import verify as ecdsa_verify

_EPHEMERAL_SECRET = os.environ.get("SIS_SESSION_SECRET") or secrets.token_hex(32)
AUTH_CHALLENGE_PREFIX = b"ECC-SIS-AUTH|"
SESSION_TTL_SECONDS = 3600 * 12


def validate_hex_public_key(public_key_hex: str, curve_name: str = "secp256r1"):
    """Decode and cryptographically validate a hex-encoded SEC1 ECC public key."""
    curve = get_curve(curve_name)
    try:
        raw = bytes.fromhex(public_key_hex)
        point = curve.decode_point(raw)
        validate_public_key(point)
        return point
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid ECC public key: {exc}",
        ) from exc


def build_auth_challenge_message(username: str, nonce_hex: str) -> bytes:
    """Canonical challenge payload signed by the user's ECDSA private key."""
    return AUTH_CHALLENGE_PREFIX + username.encode("utf-8") + b"|" + bytes.fromhex(nonce_hex)


def verify_ecdsa_signature_hex(
    public_key_hex: str,
    message: bytes,
    signature_hex: str,
    curve_name: str = "secp256r1",
) -> bool:
    """Verify a P1363 hex-encoded ECDSA signature using pure-Python ecc_core."""
    curve = get_curve(curve_name)
    try:
        pub_point = curve.decode_point(bytes.fromhex(public_key_hex))
        sig = ECDSASignature.from_p1363(
            bytes.fromhex(signature_hex),
            order_byte_size=curve.order_byte_size,
        )
        return ecdsa_verify(pub_point, message, sig)
    except Exception:
        return False


def issue_session_token(username: str) -> str:
    """Create an HMAC-SHA256 signed bearer token."""
    exp = int(time.time()) + SESSION_TTL_SECONDS
    payload = f"{username}|{exp}".encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    sig = hmac.new(_EPHEMERAL_SECRET.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_session_token(token: str) -> str:
    """Verify bearer token and return authenticated username."""
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed session token.") from exc

    expected_sig = hmac.new(
        _EPHEMERAL_SECRET.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session token signature.")

    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        username, exp_str = decoded.split("|", 1)
        exp = int(exp_str)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session payload.") from exc

    if time.time() > exp:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session token expired.")
    return username


def get_current_user(authorization: str | None = Header(default=None)) -> str:
    """FastAPI dependency extracting and verifying the Bearer session token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization Bearer token.",
        )
    token = authorization[len("Bearer ") :].strip()
    return verify_session_token(token)
