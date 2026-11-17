# ECC-SIS: A Study on the Implementation of the ECC Algorithm for a Secure Information System

A complete, self-contained cryptographic study and practical **End-to-End Encrypted Secure Information System (ECC-SIS)** built in Python + FastAPI + WebCrypto.

## Project Structure

```text
c:\poipoi
├── ecc_core/                # From-scratch Pure-Python ECC Cryptographic Engine
│   ├── field.py             # F_p arithmetic: Extended GCD mod_inv, Legendre, Tonelli-Shanks sqrt
│   ├── curves.py            # Short Weierstrass curves, Affine & Jacobian coordinates, SEC1 codec
│   ├── ecdh.py              # ECDH key agreement + RFC 5869 HKDF-SHA256
│   ├── ecdsa.py             # ECDSA with RFC 6979 deterministic nonce + nonce-reuse attack demo
│   ├── cipher.py            # NIST SP 800-38D AES-256-GCM (pure-Python + optional OpenSSL accel)
│   └── ecies.py             # ECIES authenticated E2EE envelope (ECDH + HKDF + AES-GCM + ECDSA)
├── benchmarks/              # Comparative Study: ECC vs RSA
│   ├── rsa_pure.py          # Pure-Python RSA (Miller-Rabin, keygen, sign/verify, enc/dec)
│   └── runner.py            # Timing, key-size, Affine vs Jacobian, & NIST SP 800-57 comparison
├── sis_app/                 # Practical Secure Information System (FastAPI + SQLite + Web UI)
│   ├── main.py              # Auth, E2EE Messaging/File API, Zero-Knowledge Inspector, Audit Log
│   ├── database.py          # SQLite schema + SHA-256 hash-chained audit trail
│   ├── security.py          # ECDSA challenge-response auth & bearer session verification
│   ├── routes_lab.py        # Interactive ECC Lab & Benchmark endpoints
│   └── static/              # Browser WebCrypto P-256 E2EE Portal + SVG Curve Visualizer
├── tests/                   # Unit & integration tests (NIST CAVP + API E2EE flows)
├── docs/
│   └── TECHNICAL_REPORT.md  # Academic study & architecture documentation
└── cli_demo.py              # Terminal end-to-end demonstration using ecc_core
```

## Quick Start

### 1. Run the Web Application (Recommended)
```powershell
uvicorn sis_app.main:app --host 127.0.0.1 --port 8000 --reload
```
Then open `http://127.0.0.1:8000` in your browser:
- **E2EE Messaging & Files**: Click **Login as Alice**, send an encrypted message or file to **Bob** (or click **Login as Bob** to decrypt & verify), inspect the raw database via **Server DB Inspector**, or click **Simulate MITM Tamper** to observe AES-GCM & ECDSA rejecting altered ciphertexts.
- **ECC Algorithm Lab**: Plot `toy_p97` ($y^2 \equiv x^3 + 3x + 2 \pmod{97}$), trace Double-and-Add step by step, run ECDH, test RFC 6979 ECDSA + Nonce-Reuse Key Recovery, and test ECIES.
- **ECC vs RSA Benchmarks**: Execute live benchmarks comparing `secp256r1`, `secp256k1`, `secp384r1` against `RSA-1024/2048/3072` and Affine vs Jacobian scalar multiplication.
- **Audit Log & Architecture**: Inspect and cryptographically verify the SHA-256 hash-chained audit log.

### 2. Run the Terminal CLI Demo
```powershell
python cli_demo.py
```

### 3. Run the Benchmark Suite from CLI
```powershell
python -m benchmarks.runner
```

### 4. Run Automated Tests
```powershell
python -m unittest discover -s tests -v
```

---

## Live Bilingual Web Demo (EN / VI — 24/7 GitHub Pages)

- **Open Live Web App Now:** https://hiephh0307-prog.github.io/ECC-SIS-INS3062/

## One-Click Run & Cloud Deploy (24/7 Public HTTPS for Team Demo)

### Windows 1-Click Local Run
Double-click `run.bat` (auto-installs `fastapi` & `uvicorn` if needed and opens `http://127.0.0.1:8000/` in your default browser).

### Deploy 24/7 Online (HTTPS required for WebCrypto P-256)
- **Render (1-Click Blueprint):** `https://render.com/deploy?repo=https://github.com/hiephh0307-prog/ECC-SIS-INS3062`
- **Docker / Hugging Face Spaces (`PORT=7860`):** Uses included `Dockerfile` (`sis_data` writable by container non-root UID).
- **Instant Local HTTPS Tunnel:** `cloudflared tunnel --url http://127.0.0.1:8000`
