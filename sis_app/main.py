"""FastAPI backend for ECC-SIS (Secure Information System + ECC Study Lab)."""

from __future__ import annotations

import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ecc_core import build_signature_payload

from .database import append_audit_log, get_conn, init_db, utc_now_iso, verify_audit_chain
from .routes_lab import router as lab_router
from .security import (
    build_auth_challenge_message,
    get_current_user,
    issue_session_token,
    validate_hex_public_key,
    verify_ecdsa_signature_hex,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="ECC-SIS: Elliptic Curve Cryptography for a Secure Information System",
    version="1.0.0",
    description="End-to-End Encrypted Messaging & File System + Interactive ECC Study & Benchmark Suite",
    lifespan=lifespan,
)

app.include_router(lab_router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ----------------------------------------------------------------------
# Pydantic Schemas
# ----------------------------------------------------------------------
class RegisterRequest(BaseModel):
    username: str = Field(min_length=2, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    display_name: str = Field(min_length=1, max_length=64)
    curve: Literal["secp256r1"] = "secp256r1"
    public_key_hex: str = Field(min_length=66, max_length=132)


class ChallengeRequest(BaseModel):
    username: str = Field(min_length=2, max_length=32)


class VerifyChallengeRequest(BaseModel):
    challenge_id: str
    username: str
    signature_hex: str


class SendEncryptedMessageRequest(BaseModel):
    recipient: str = Field(min_length=2, max_length=32)
    msg_type: Literal["text", "file"] = "text"
    filename: str = Field(default="", max_length=255)
    mime_type: str = Field(default="text/plain", max_length=120)
    file_size: int = Field(default=0, ge=0, le=10 * 1024 * 1024)
    curve: Literal["secp256r1"] = "secp256r1"
    ephemeral_pubkey_hex: str = Field(min_length=66, max_length=132)
    nonce_hex: str = Field(min_length=24, max_length=24)
    ciphertext_hex: str = Field(min_length=32)
    signature_hex: str = Field(min_length=128, max_length=128)
    aad_text: str = Field(min_length=1, max_length=1000)


# ----------------------------------------------------------------------
# Root UI & Health
# ----------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def serve_index() -> FileResponse:
    return FileResponse(
        str(STATIC_DIR / "index.html"),
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "ECC-SIS", "curve": "secp256r1"}


# ----------------------------------------------------------------------
# Identity & ECDSA Challenge-Response Authentication
# ----------------------------------------------------------------------
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register_user(req: RegisterRequest) -> dict:
    validate_hex_public_key(req.public_key_hex, req.curve)
    now = utc_now_iso()
    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (req.username,)).fetchone()
        if existing:
            if req.username in ("alice", "bob"):
                # Seamless re-sync for demo personas across browser refreshes / sessions
                conn.execute(
                    "UPDATE users SET display_name = ?, public_key_hex = ? WHERE username = ?",
                    (req.display_name, req.public_key_hex.lower(), req.username),
                )
                append_audit_log(
                    conn,
                    actor=req.username,
                    action="USER_KEY_UPDATED",
                    details=f"Updated ECC identity ({req.curve}), pubkey={req.public_key_hex[:18]}...",
                )
            else:
                raise HTTPException(status_code=409, detail=f"Username '{req.username}' is already registered.")
        else:
            conn.execute(
                """
                INSERT INTO users (username, display_name, curve, public_key_hex, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (req.username, req.display_name, req.curve, req.public_key_hex.lower(), now),
            )
            append_audit_log(
                conn,
                actor=req.username,
                action="USER_REGISTERED",
                details=f"Registered ECC identity ({req.curve}), pubkey={req.public_key_hex[:18]}...",
            )
    return {
        "username": req.username,
        "display_name": req.display_name,
        "curve": req.curve,
        "public_key_hex": req.public_key_hex.lower(),
        "created_at": now,
    }


@app.post("/api/auth/challenge")
def request_challenge(req: ChallengeRequest) -> dict:
    with get_conn() as conn:
        user = conn.execute("SELECT username, curve FROM users WHERE username = ?", (req.username,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail=f"User '{req.username}' not found.")

        challenge_id = secrets.token_hex(16)
        nonce_hex = secrets.token_hex(32)
        expires_at = time.time() + 120.0
        conn.execute(
            """
            INSERT INTO auth_challenges (challenge_id, username, nonce_hex, expires_at, used)
            VALUES (?, ?, ?, ?, 0)
            """,
            (challenge_id, req.username, nonce_hex, expires_at),
        )
    return {
        "challenge_id": challenge_id,
        "username": req.username,
        "nonce_hex": nonce_hex,
        "expires_in_seconds": 120,
    }


@app.post("/api/auth/verify")
def verify_challenge(req: VerifyChallengeRequest) -> dict:
    with get_conn() as conn:
        ch = conn.execute(
            "SELECT * FROM auth_challenges WHERE challenge_id = ? AND username = ?",
            (req.challenge_id, req.username),
        ).fetchone()
        if not ch:
            raise HTTPException(status_code=404, detail="Auth challenge not found.")
        if ch["used"]:
            raise HTTPException(status_code=400, detail="Auth challenge already consumed (replay blocked).")
        if time.time() > ch["expires_at"]:
            raise HTTPException(status_code=400, detail="Auth challenge expired.")

        user = conn.execute("SELECT * FROM users WHERE username = ?", (req.username,)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        message = build_auth_challenge_message(req.username, ch["nonce_hex"])
        valid = verify_ecdsa_signature_hex(
            user["public_key_hex"],
            message,
            req.signature_hex,
            curve_name=user["curve"],
        )
        if not valid:
            append_audit_log(
                conn,
                actor=req.username,
                action="AUTH_FAILED",
                details=f"Invalid ECDSA challenge signature for challenge_id={req.challenge_id}",
            )
            raise HTTPException(status_code=401, detail="ECDSA signature verification failed.")

        conn.execute("UPDATE auth_challenges SET used = 1 WHERE challenge_id = ?", (req.challenge_id,))
        append_audit_log(
            conn,
            actor=req.username,
            action="AUTH_SUCCESS",
            details=f"Authenticated via ECDSA challenge-response ({user['curve']})",
        )

    token = issue_session_token(req.username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": req.username,
        "display_name": user["display_name"],
        "curve": user["curve"],
        "public_key_hex": user["public_key_hex"],
    }


@app.get("/api/users")
def list_users() -> dict:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT username, display_name, curve, public_key_hex, created_at FROM users ORDER BY id ASC"
        ).fetchall()
    return {"users": [dict(r) for r in rows]}


# ----------------------------------------------------------------------
# End-to-End Encrypted Messaging & File Exchange
# ----------------------------------------------------------------------
@app.post("/api/messages", status_code=status.HTTP_201_CREATED)
def send_encrypted_message(req: SendEncryptedMessageRequest, current_user: str = Depends(get_current_user)) -> dict:
    validate_hex_public_key(req.ephemeral_pubkey_hex, req.curve)

    with get_conn() as conn:
        sender_row = conn.execute("SELECT * FROM users WHERE username = ?", (current_user,)).fetchone()
        recipient_row = conn.execute("SELECT * FROM users WHERE username = ?", (req.recipient,)).fetchone()
        if not sender_row:
            raise HTTPException(status_code=404, detail="Authenticated sender not found.")
        if not recipient_row:
            raise HTTPException(status_code=404, detail=f"Recipient '{req.recipient}' not found.")

        try:
            eph_bytes = bytes.fromhex(req.ephemeral_pubkey_hex)
            nonce_bytes = bytes.fromhex(req.nonce_hex)
            ct_bytes = bytes.fromhex(req.ciphertext_hex)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Malformed hex payload.") from exc

        sig_payload = build_signature_payload(
            eph_bytes,
            nonce_bytes,
            ct_bytes,
            req.aad_text.encode("utf-8"),
        )
        if not verify_ecdsa_signature_hex(sender_row["public_key_hex"], sig_payload, req.signature_hex, req.curve):
            append_audit_log(
                conn,
                actor=current_user,
                action="MESSAGE_REJECTED",
                details=f"Invalid ECDSA envelope signature to {req.recipient}",
            )
            raise HTTPException(status_code=400, detail="ECDSA signature verification failed on encrypted packet.")

        now = utc_now_iso()
        cur = conn.execute(
            """
            INSERT INTO messages (
                sender, recipient, msg_type, filename, mime_type, file_size,
                curve, ephemeral_pubkey_hex, nonce_hex, ciphertext_hex, signature_hex, aad_text, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                current_user,
                req.recipient,
                req.msg_type,
                req.filename,
                req.mime_type,
                req.file_size,
                req.curve,
                req.ephemeral_pubkey_hex.lower(),
                req.nonce_hex.lower(),
                req.ciphertext_hex.lower(),
                req.signature_hex.lower(),
                req.aad_text,
                now,
            ),
        )
        msg_id = cur.lastrowid
        append_audit_log(
            conn,
            actor=current_user,
            action="E2EE_MESSAGE_STORED",
            details=(
                f"msg_id={msg_id} -> {req.recipient} type={req.msg_type} "
                f"ciphertext_bytes={len(ct_bytes)} eph={req.ephemeral_pubkey_hex[:14]}..."
            ),
        )

    return {"id": msg_id, "sender": current_user, "recipient": req.recipient, "created_at": now}


@app.get("/api/messages")
def list_my_messages(current_user: str = Depends(get_current_user)) -> dict:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT m.*, u.public_key_hex AS sender_public_key_hex, u.display_name AS sender_display_name
            FROM messages m
            JOIN users u ON u.username = m.sender
            WHERE m.recipient = ? OR m.sender = ?
            ORDER BY m.id DESC
            """,
            (current_user, current_user),
        ).fetchall()
    return {"username": current_user, "messages": [dict(r) for r in rows]}


@app.get("/api/messages/server-inspector")
def inspect_server_database(current_user: str = Depends(get_current_user)) -> dict:
    """Educational endpoint exposing raw encrypted database records to prove zero plaintext storage."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, sender, recipient, msg_type, filename, file_size, curve,
                   ephemeral_pubkey_hex, nonce_hex, ciphertext_hex, signature_hex, aad_text, created_at
            FROM messages
            WHERE recipient = ? OR sender = ?
            ORDER BY id DESC
            LIMIT 25
            """,
            (current_user, current_user),
        ).fetchall()
    return {
        "note": "Server Zero-Knowledge View: No plaintext messages, files, private keys, or AES keys exist on server.",
        "records": [dict(r) for r in rows],
    }


@app.post("/api/messages/{message_id}/simulate-tamper")
def simulate_ciphertext_tamper(message_id: int, current_user: str = Depends(get_current_user)) -> dict:
    """Flip 1 byte in stored ciphertext to demonstrate AES-GCM & ECDSA tamper detection."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Message not found.")
        if current_user not in (row["sender"], row["recipient"]):
            raise HTTPException(status_code=403, detail="Not authorized to tamper-test this message.")

        ct = bytearray.fromhex(row["ciphertext_hex"])
        ct[0] ^= 0xFF
        tampered_hex = ct.hex()
        conn.execute("UPDATE messages SET ciphertext_hex = ? WHERE id = ?", (tampered_hex, message_id))
        append_audit_log(
            conn,
            actor=current_user,
            action="SIMULATE_CIPHERTEXT_TAMPER",
            details=f"Flipped 1 byte in ciphertext of msg_id={message_id} for integrity verification demo",
        )
    return {"id": message_id, "tampered": True, "ciphertext_preview": tampered_hex[:32] + "..."}


# ----------------------------------------------------------------------
# Tamper-Evident Audit Log
# ----------------------------------------------------------------------
@app.get("/api/audit")
def get_audit_logs(limit: int = 50) -> dict:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
            (min(max(limit, 1), 200),),
        ).fetchall()
        integrity = verify_audit_chain(conn)
    return {"integrity": integrity, "entries": [dict(r) for r in rows]}


@app.get("/api/audit/verify")
def verify_audit() -> dict:
    with get_conn() as conn:
        return verify_audit_chain(conn)
