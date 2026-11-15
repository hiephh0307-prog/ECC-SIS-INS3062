# Technical Study: Implementation of the ECC Algorithm for a Secure Information System

## 1. Introduction & Motivation
Modern Secure Information Systems (SIS) require confidentiality, integrity, authentication, and non-repudiation while minimizing key-management and bandwidth overhead. Elliptic Curve Cryptography (ECC), independently proposed by Neal Koblitz and Victor Miller (1985), achieves equivalent security to RSA at dramatically smaller key sizes (e.g., **256-bit ECC ≈ 3072-bit RSA** at the 128-bit security level per NIST SP 800-57) because the fastest known general algorithms for the Elliptic Curve Discrete Logarithm Problem (ECDLP) run in exponential time $O(\sqrt{n})$, whereas Integer Factorization (RSA) admits sub-exponential index-calculus attacks.

## 2. Mathematical Foundations (`ecc_core`)

### 2.1 Finite Field Arithmetic ($\mathbb{F}_p$)
Implemented in `ecc_core/field.py`:
- **Modular Inverse**: Extended Euclidean Algorithm (`extended_gcd` / `mod_inv`) in $O(\log p)$ operations.
- **Modular Square Root**: Tonelli-Shanks (`mod_sqrt`) supporting both $p \equiv 3 \pmod 4$ fast exponentiation and general primes ($p \equiv 1 \pmod 4$) for SEC1 compressed point decompression (`0x02` / `0x03`).

### 2.2 Elliptic Curves & Coordinate Systems (`ecc_core/curves.py`)
We model Short Weierstrass curves over $\mathbb{F}_p$:
$$E(\mathbb{F}_p): y^2 \equiv x^3 + ax + b \pmod p, \quad 4a^3 + 27b^2 \not\equiv 0 \pmod p$$

Supported standardized curves:
- `secp256r1` (NIST P-256, 128-bit security)
- `secp256k1` (256-bit Koblitz curve, 128-bit security)
- `secp384r1` (NIST P-384, 192-bit security)
- `toy_p97` ($y^2 \equiv x^3 + 3x + 2 \pmod{97}$, prime order $n = 103$, $G = (2, 4)$) for geometric visualization and step-by-step Double-and-Add tracing.

**Jacobian Projective Optimization**:
Affine point addition requires one modular inversion per step, which is expensive in big-integer arithmetic. By representing affine $(x, y)$ as Jacobian $(X, Y, Z)$ where $x = X/Z^2$ and $y = Y/Z^3$, all point doublings and additions inside scalar multiplication execute purely via modular multiplications and squarings, requiring **only one modular inversion** at the end (`_from_jacobian`).

## 3. Cryptographic Protocols

### 3.1 ECDH + HKDF-SHA256 (`ecc_core/ecdh.py`)
1. Public keys are validated against NIST SP 800-56A (`validate_public_key`: not $\mathcal{O}$, on curve, subgroup check $nQ = \mathcal{O}$).
2. Shared secret $Z = (d_A \cdot Q_B)_x = (d_B \cdot Q_A)_x$.
3. Symmetric 256-bit key material is derived via RFC 5869 HKDF-SHA256 (`hkdf_sha256`), binding the ephemeral public key as salt and protocol context as `info`.

### 3.2 ECDSA with RFC 6979 Deterministic Nonces (`ecc_core/ecdsa.py`)
Reusing or predicting the ephemeral signing nonce $k$ in ECDSA leaks the private key $d$:
$$k \equiv (z_1 - z_2)(s_1 - s_2)^{-1} \pmod n, \quad d \equiv (s_1 k - z_1) r^{-1} \pmod n$$
Our implementation eliminates RNG-failure risk using **RFC 6979 HMAC-DRBG (SHA-256)** deterministic nonce generation and low-$s$ canonicalization ($s \le n/2$), while preserving `recover_private_key_from_reused_nonce()` as an educational demonstration of the attack.

### 3.3 Authenticated ECIES Envelope (`ecc_core/ecies.py`, `ecc_core/cipher.py`)
Each message or file in ECC-SIS uses:
1. **Ephemeral ECDH** keypair $(k_{\text{eph}}, Q_{\text{eph}})$ for per-message forward secrecy.
2. **HKDF-SHA256** deriving a unique 256-bit AES key.
3. **NIST SP 800-38D AES-256-GCM** encrypting plaintext with Associated Authenticated Data (`sender|recipient|type|filename`).
4. **ECDSA Signature** over `ECC-SIS-SIG-v1| || Q_eph || nonce || ciphertext||tag || aad`, providing sender authenticity and non-repudiation.

## 4. Secure Information System Architecture (`sis_app`)
- **Zero-Knowledge Server**: FastAPI + SQLite stores only user public keys, ephemeral public keys, nonces, ciphertexts, and ECDSA signatures.
- **ECDSA Challenge-Response Auth**: Users authenticate by signing single-use 256-bit server challenges (`ECC-SIS-AUTH|<username>|<nonce>`), preventing password theft and replay attacks.
- **Browser WebCrypto Interoperability**: Client-side P-256 WebCrypto (`window.crypto.subtle`) produces SEC1 raw keys, IEEE P1363 ECDSA signatures, HKDF keys, and AES-256-GCM ciphertexts 100% interoperable with Python `ecc_core`.
- **Tamper-Evident Audit Log**: Every security event is hash-chained (`H_i = SHA256(H_{i-1} || timestamp || actor || action || details)`) and verifiable via `/api/audit/verify`.
