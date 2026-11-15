"""Unit tests for ecc_core (finite fields, curves, ECDH, ECDSA, AES-256-GCM, ECIES)."""

from __future__ import annotations

import unittest

from ecc_core import (
    ECDSASignature,
    ECIESEncryptedPacket,
    InvalidTagError,
    PureAES256GCM,
    SECP256K1,
    SECP256R1,
    SECP384R1,
    TOY_P97,
    ecdh_shared_secret,
    ecies_decrypt,
    ecies_encrypt,
    generate_keypair,
    hkdf_sha256,
    mod_inv,
    mod_sqrt,
    recover_private_key_from_reused_nonce,
    sign as ecdsa_sign,
    sign_encrypted_packet,
    verify as ecdsa_verify,
    verify_encrypted_packet_signature,
)


class TestFiniteField(unittest.TestCase):
    def test_mod_inv(self) -> None:
        p = 97
        for a in range(1, p):
            inv = mod_inv(a, p)
            self.assertEqual((a * inv) % p, 1)
        with self.assertRaises(ZeroDivisionError):
            mod_inv(0, p)

    def test_mod_sqrt_tonelli_shanks(self) -> None:
        # p = 97 == 1 (mod 4) exercises full Tonelli-Shanks path
        for x in range(1, 97):
            sq = (x * x) % 97
            r = mod_sqrt(sq, 97)
            self.assertIsNotNone(r)
            assert r is not None
            self.assertEqual((r * r) % 97, sq)

        # p = 23 == 3 (mod 4) exercises fast path
        r23 = mod_sqrt(13, 23)
        self.assertIsNotNone(r23)
        assert r23 is not None
        self.assertEqual((r23 * r23) % 23, 13)
        self.assertIsNone(mod_sqrt(5, 23))


class TestEllipticCurves(unittest.TestCase):
    def test_toy_curve_group_order_and_trace(self) -> None:
        pts = TOY_P97.enumerate_points()
        self.assertEqual(len(pts), TOY_P97.n)
        self.assertEqual(TOY_P97.n * TOY_P97.G, TOY_P97.infinity)

        p7, trace = TOY_P97.G.scalar_mul_with_trace(7)
        self.assertEqual(p7, TOY_P97.G.scalar_mul_affine(7))
        self.assertEqual(p7, TOY_P97.G.scalar_mul_jacobian(7))
        self.assertEqual(len(trace), 3)  # 7 = 0b111

    def test_standard_curves_order_and_affine_vs_jacobian(self) -> None:
        for curve in (SECP256R1, SECP256K1, SECP384R1):
            with self.subTest(curve=curve.name):
                self.assertEqual(curve.n * curve.G, curve.infinity)
                k = 0x123456789ABCDEF0123456789ABCDEF
                self.assertEqual(
                    curve.G.scalar_mul_affine(k),
                    curve.G.scalar_mul_jacobian(k),
                )

    def test_sec1_point_compression_roundtrip(self) -> None:
        for curve in (SECP256R1, SECP256K1, SECP384R1):
            with self.subTest(curve=curve.name):
                kp = generate_keypair(curve)
                uncompressed = kp.public_key.to_bytes(compressed=False)
                compressed = kp.public_key.to_bytes(compressed=True)
                self.assertEqual(len(uncompressed), 1 + 2 * curve.coord_byte_size)
                self.assertEqual(len(compressed), 1 + curve.coord_byte_size)
                self.assertEqual(curve.decode_point(uncompressed), kp.public_key)
                self.assertEqual(curve.decode_point(compressed), kp.public_key)


class TestECDHAndHKDF(unittest.TestCase):
    def test_ecdh_key_agreement(self) -> None:
        for curve in (SECP256R1, SECP256K1, SECP384R1):
            with self.subTest(curve=curve.name):
                alice = generate_keypair(curve)
                bob = generate_keypair(curve)
                s1 = ecdh_shared_secret(alice.private_key, bob.public_key)
                s2 = ecdh_shared_secret(bob.private_key, alice.public_key)
                self.assertEqual(s1, s2)
                k1 = hkdf_sha256(s1, 32, salt=b"salt", info=b"info")
                k2 = hkdf_sha256(s2, 32, salt=b"salt", info=b"info")
                self.assertEqual(k1, k2)
                self.assertEqual(len(k1), 32)


class TestECDSA(unittest.TestCase):
    def test_rfc6979_deterministic_sign_and_verify(self) -> None:
        for curve in (SECP256R1, SECP256K1, SECP384R1):
            with self.subTest(curve=curve.name):
                kp = generate_keypair(curve)
                msg = b"ECC-SIS Authentic Message"
                sig1 = ecdsa_sign(kp.private_key, msg, curve)
                sig2 = ecdsa_sign(kp.private_key, msg, curve)
                self.assertEqual(sig1.to_p1363(), sig2.to_p1363())
                self.assertTrue(ecdsa_verify(kp.public_key, msg, sig1))
                self.assertFalse(ecdsa_verify(kp.public_key, msg + b"!", sig1))

                # Tamper r
                bad_sig = ECDSASignature(r=(sig1.r + 1) % curve.n or 1, s=sig1.s, order_byte_size=curve.order_byte_size)
                self.assertFalse(ecdsa_verify(kp.public_key, msg, bad_sig))

    def test_nonce_reuse_key_recovery(self) -> None:
        kp = generate_keypair(SECP256R1)
        reused_k = 0xDEADBEEF1234567890ABCDEF
        m1 = b"First message"
        m2 = b"Second message"
        sig1 = ecdsa_sign(kp.private_key, m1, SECP256R1, nonce_override=reused_k)
        sig2 = ecdsa_sign(kp.private_key, m2, SECP256R1, nonce_override=reused_k)
        recovered = recover_private_key_from_reused_nonce(SECP256R1, m1, sig1, m2, sig2)
        self.assertEqual(recovered, kp.private_key)


class TestAES256GCMAndECIES(unittest.TestCase):
    def test_nist_cavp_aes256_gcm_vectors(self) -> None:
        # NIST SP 800-38D Test Case 15
        key15 = bytes(32)
        iv15 = bytes(12)
        pt15 = bytes(16)
        ct15 = PureAES256GCM(key15).encrypt(iv15, pt15, b"")
        self.assertEqual(
            ct15.hex(),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919",
        )
        self.assertEqual(PureAES256GCM(key15).decrypt(iv15, ct15, b""), pt15)

        # NIST SP 800-38D Test Case 16 (with AAD)
        key16 = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        iv16 = bytes.fromhex("cafebabefacedbaddecaf888")
        pt16 = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        )
        aad16 = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        expected_ct16 = (
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
            "76fc6ece0f4e1768cddf8853bb2d551b"
        )
        ct16 = PureAES256GCM(key16).encrypt(iv16, pt16, aad16)
        self.assertEqual(ct16.hex(), expected_ct16)
        self.assertEqual(PureAES256GCM(key16).decrypt(iv16, ct16, aad16), pt16)

    def test_ecies_authenticated_envelope_roundtrip_and_tamper(self) -> None:
        alice = generate_keypair(SECP256R1)
        bob = generate_keypair(SECP256R1)
        plaintext = b"Sensitive financial transfer order #8821"
        aad = b"alice|bob|text|"

        pkt = ecies_encrypt(bob.public_key, plaintext, aad=aad)
        sig = sign_encrypted_packet(alice.private_key, pkt, alice.public_key, aad=aad)

        self.assertTrue(verify_encrypted_packet_signature(alice.public_key, pkt, sig, aad=aad))
        recovered = ecies_decrypt(bob.private_key, pkt, bob.public_key, aad=aad)
        self.assertEqual(recovered, plaintext)

        # Flip 1 byte in ciphertext -> both ECDSA and AES-GCM reject
        bad_ct = bytearray(pkt.ciphertext)
        bad_ct[0] ^= 0x01
        tampered_pkt = ECIESEncryptedPacket(
            curve_name=pkt.curve_name,
            ephemeral_public_key=pkt.ephemeral_public_key,
            nonce=pkt.nonce,
            ciphertext=bytes(bad_ct),
        )
        self.assertFalse(verify_encrypted_packet_signature(alice.public_key, tampered_pkt, sig, aad=aad))
        with self.assertRaises(InvalidTagError):
            ecies_decrypt(bob.private_key, tampered_pkt, bob.public_key, aad=aad)


if __name__ == "__main__":
    unittest.main()
