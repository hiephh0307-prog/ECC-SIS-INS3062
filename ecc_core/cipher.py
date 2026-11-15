"""AES-256-GCM (NIST SP 800-38D) with optional C acceleration via `cryptography` and pure-Python fallback."""

from __future__ import annotations

import hmac
import secrets
from typing import Final

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _CryptoAESGCM  # type: ignore

    HAS_CRYPTOGRAPHY = True
except ImportError:
    _CryptoAESGCM = None
    HAS_CRYPTOGRAPHY = False

# Standard AES S-box (FIPS 197)
_SBOX: Final[tuple[int, ...]] = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_RCON: Final[tuple[int, ...]] = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def _expand_key_256(key: bytes) -> list[bytes]:
    """Expand a 32-byte AES-256 key into 15 round keys (16 bytes each)."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key.")
    w = [list(key[i : i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = list(w[i - 1])
        if i % 8 == 0:
            temp = [_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
            temp[0] ^= _RCON[(i // 8) - 1]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        prev = w[i - 8]
        w.append([prev[j] ^ temp[j] for j in range(4)])
    return [bytes(sum(w[r * 4 : (r + 1) * 4], [])) for r in range(15)]


def _aes256_encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    """Encrypt a single 16-byte block using AES-256 (FIPS 197)."""
    s = [b ^ rk for b, rk in zip(block, round_keys[0])]
    sbox = _SBOX
    for rnd in range(1, 15):
        # SubBytes + ShiftRows
        s = [
            sbox[s[0]], sbox[s[5]], sbox[s[10]], sbox[s[15]],
            sbox[s[4]], sbox[s[9]], sbox[s[14]], sbox[s[3]],
            sbox[s[8]], sbox[s[13]], sbox[s[2]], sbox[s[7]],
            sbox[s[12]], sbox[s[1]], sbox[s[6]], sbox[s[11]],
        ]
        if rnd < 14:
            # MixColumns
            ns = [0] * 16
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c], s[c + 1], s[c + 2], s[c + 3]
                t = a0 ^ a1 ^ a2 ^ a3
                ns[c] = a0 ^ t ^ _xtime(a0 ^ a1)
                ns[c + 1] = a1 ^ t ^ _xtime(a1 ^ a2)
                ns[c + 2] = a2 ^ t ^ _xtime(a2 ^ a3)
                ns[c + 3] = a3 ^ t ^ _xtime(a3 ^ a0)
            s = ns
        rk = round_keys[rnd]
        s = [s[i] ^ rk[i] for i in range(16)]
    return bytes(s)


def _gf128_mul(x: int, y: int) -> int:
    """Multiply two 128-bit blocks in GF(2^128) per NIST SP 800-38D."""
    z = 0
    v = y
    r_poly = 0xE1000000000000000000000000000000
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= r_poly
    return z


def _ghash(h_int: int, aad: bytes, ciphertext: bytes) -> bytes:
    """Compute GHASH(H, A, C) per NIST SP 800-38D."""
    y = 0
    for data in (aad, ciphertext):
        full_len = (len(data) // 16) * 16
        for i in range(0, full_len, 16):
            blk = int.from_bytes(data[i : i + 16], "big")
            y = _gf128_mul(y ^ blk, h_int)
        rem = len(data) - full_len
        if rem:
            padded = data[full_len:] + b"\x00" * (16 - rem)
            blk = int.from_bytes(padded, "big")
            y = _gf128_mul(y ^ blk, h_int)

    len_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    y = _gf128_mul(y ^ len_block, h_int)
    return y.to_bytes(16, "big")


def _inc32(counter_block: bytes) -> bytes:
    prefix = counter_block[:12]
    ctr = (int.from_bytes(counter_block[12:], "big") + 1) & 0xFFFFFFFF
    return prefix + ctr.to_bytes(4, "big")


class PureAES256GCM:
    """Pure-Python NIST SP 800-38D AES-256-GCM authenticated encryption."""

    def __init__(self, key: bytes) -> None:
        self._round_keys = _expand_key_256(key)
        self._h_int = int.from_bytes(_aes256_encrypt_block(b"\x00" * 16, self._round_keys), "big")

    def _compute_j0(self, nonce: bytes) -> bytes:
        if len(nonce) == 12:
            return nonce + b"\x00\x00\x00\x01"
        return _ghash(self._h_int, b"", nonce)

    def _gctr(self, icb: bytes, data: bytes) -> bytes:
        if not data:
            return b""
        out = bytearray()
        cb = icb
        for i in range(0, len(data), 16):
            keystream = _aes256_encrypt_block(cb, self._round_keys)
            chunk = data[i : i + 16]
            out.extend(bytes(a ^ b for a, b in zip(chunk, keystream)))
            cb = _inc32(cb)
        return bytes(out)

    def encrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None) -> bytes:
        if not nonce:
            raise ValueError("Nonce must be non-empty.")
        aad = associated_data or b""
        j0 = self._compute_j0(nonce)
        ct = self._gctr(_inc32(j0), data)
        s_tag = _ghash(self._h_int, aad, ct)
        t_mask = _aes256_encrypt_block(j0, self._round_keys)
        tag = bytes(a ^ b for a, b in zip(s_tag, t_mask))
        return ct + tag

    def decrypt(self, nonce: bytes, data: bytes, associated_data: bytes | None = None) -> bytes:
        if len(data) < 16:
            raise ValueError("Invalid AES-GCM ciphertext (shorter than 16-byte tag).")
        aad = associated_data or b""
        ct, tag = data[:-16], data[-16:]
        j0 = self._compute_j0(nonce)
        s_tag = _ghash(self._h_int, aad, ct)
        t_mask = _aes256_encrypt_block(j0, self._round_keys)
        expected_tag = bytes(a ^ b for a, b in zip(s_tag, t_mask))
        if not hmac.compare_digest(tag, expected_tag):
            raise InvalidTagError("AES-GCM authentication tag verification failed.")
        return self._gctr(_inc32(j0), ct)


class InvalidTagError(ValueError):
    """Raised when AES-GCM authentication tag verification fails."""


def aes256_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"", nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce_12_bytes, ciphertext_plus_tag)."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    iv = nonce if nonce is not None else secrets.token_bytes(12)
    if _CryptoAESGCM is not None:
        return iv, _CryptoAESGCM(key).encrypt(iv, plaintext, aad)
    return iv, PureAES256GCM(key).encrypt(iv, plaintext, aad)


def aes256_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM ciphertext||tag, raising InvalidTagError on tampering."""
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key.")
    if _CryptoAESGCM is not None:
        try:
            return _CryptoAESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)
        except Exception as exc:
            raise InvalidTagError("AES-GCM authentication tag verification failed.") from exc
    return PureAES256GCM(key).decrypt(nonce, ciphertext_with_tag, aad)
