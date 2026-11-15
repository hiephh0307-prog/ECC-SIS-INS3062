"""Pure-Python Elliptic Curve Cryptography (ECC) library for study and Secure Information Systems."""

from .cipher import HAS_CRYPTOGRAPHY, InvalidTagError, PureAES256GCM, aes256_gcm_decrypt, aes256_gcm_encrypt
from .curves import CURVES, SECP256K1, SECP256R1, SECP384R1, TOY_P97, EllipticCurve, Point, get_curve
from .ecdh import (
    ECCKeyPair,
    ecdh_shared_secret,
    generate_keypair,
    hkdf_sha256,
    keypair_from_private_hex,
    validate_public_key,
)
from .ecdsa import (
    ECDSASignature,
    recover_private_key_from_reused_nonce,
    rfc6979_generate_k,
    sign,
    verify,
)
from .ecies import (
    ECIES_HKDF_INFO,
    SIG_DOMAIN_PREFIX,
    ECIESEncryptedPacket,
    build_signature_payload,
    ecies_decrypt,
    ecies_encrypt,
    sign_encrypted_packet,
    verify_encrypted_packet_signature,
)
from .field import extended_gcd, legendre_symbol, mod_inv, mod_sqrt

__all__ = [
    "CURVES",
    "ECCKeyPair",
    "ECDSASignature",
    "ECIESEncryptedPacket",
    "ECIES_HKDF_INFO",
    "EllipticCurve",
    "HAS_CRYPTOGRAPHY",
    "InvalidTagError",
    "Point",
    "PureAES256GCM",
    "SECP256K1",
    "SECP256R1",
    "SECP384R1",
    "SIG_DOMAIN_PREFIX",
    "TOY_P97",
    "aes256_gcm_decrypt",
    "aes256_gcm_encrypt",
    "build_signature_payload",
    "ecdh_shared_secret",
    "ecies_decrypt",
    "ecies_encrypt",
    "extended_gcd",
    "generate_keypair",
    "get_curve",
    "hkdf_sha256",
    "keypair_from_private_hex",
    "legendre_symbol",
    "mod_inv",
    "mod_sqrt",
    "recover_private_key_from_reused_nonce",
    "rfc6979_generate_k",
    "sign",
    "sign_encrypted_packet",
    "validate_public_key",
    "verify",
    "verify_encrypted_packet_signature",
]
