"""SQLite persistence and hash-chained tamper-evident audit log for ECC-SIS."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "sis_data" / "sis.db"


def get_db_path() -> Path:
    env_path = os.environ.get("SIS_DB_PATH")
    return Path(env_path) if env_path else DEFAULT_DB_PATH


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create database schema if it does not exist."""
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                curve TEXT NOT NULL DEFAULT 'secp256r1',
                public_key_hex TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS auth_challenges (
                challenge_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                expires_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                recipient TEXT NOT NULL,
                msg_type TEXT NOT NULL DEFAULT 'text',
                filename TEXT NOT NULL DEFAULT '',
                mime_type TEXT NOT NULL DEFAULT 'text/plain',
                file_size INTEGER NOT NULL DEFAULT 0,
                curve TEXT NOT NULL DEFAULT 'secp256r1',
                ephemeral_pubkey_hex TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                ciphertext_hex TEXT NOT NULL,
                signature_hex TEXT NOT NULL,
                aad_text TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
            """
        )


def _compute_audit_hash(prev_hash: str, timestamp: str, actor: str, action: str, details: str) -> str:
    payload = f"{prev_hash}|{timestamp}|{actor}|{action}|{details}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def append_audit_log(conn: sqlite3.Connection, actor: str, action: str, details: str) -> str:
    """Append a hash-chained entry to the tamper-evident audit log."""
    row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["entry_hash"] if row else ("0" * 64)
    ts = utc_now_iso()
    entry_hash = _compute_audit_hash(prev_hash, ts, actor, action, details)
    conn.execute(
        """
        INSERT INTO audit_log (timestamp, actor, action, details, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (ts, actor, action, details, prev_hash, entry_hash),
    )
    return entry_hash


def verify_audit_chain(conn: sqlite3.Connection) -> dict:
    """Verify integrity of the entire hash-chained audit log."""
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    expected_prev = "0" * 64
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "total_entries": len(rows),
                "broken_at_id": row["id"],
                "reason": "prev_hash mismatch",
            }
        recomputed = _compute_audit_hash(
            row["prev_hash"],
            row["timestamp"],
            row["actor"],
            row["action"],
            row["details"],
        )
        if recomputed != row["entry_hash"]:
            return {
                "valid": False,
                "total_entries": len(rows),
                "broken_at_id": row["id"],
                "reason": "entry_hash mismatch (record modified)",
            }
        expected_prev = row["entry_hash"]
    return {
        "valid": True,
        "total_entries": len(rows),
        "head_hash": expected_prev,
    }
