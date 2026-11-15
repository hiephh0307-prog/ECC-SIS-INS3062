"""Integration tests for ECC-SIS backend workflows, Pydantic validation, auth, E2EE, and audit log."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

from ecc_core import (
    ECDSASignature,
    ECIESEncryptedPacket,
    InvalidTagError,
    SECP256R1,
    ecies_decrypt,
    ecies_encrypt,
    generate_keypair,
    sign as ecdsa_sign,
    sign_encrypted_packet,
    verify_encrypted_packet_signature,
)


class TestSISAPI(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        os.environ["SIS_DB_PATH"] = str(Path(self._tmpdir.name) / "test_sis.db")
        from sis_app.database import init_db

        init_db()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _register_and_login(self, username: str, display_name: str):
        from sis_app.main import (
            ChallengeRequest,
            RegisterRequest,
            VerifyChallengeRequest,
            register_user,
            request_challenge,
            verify_challenge,
        )

        kp = generate_keypair(SECP256R1)
        reg = register_user(
            RegisterRequest(
                username=username,
                display_name=display_name,
                curve="secp256r1",
                public_key_hex=kp.public_hex(),
            )
        )
        self.assertEqual(reg["username"], username)

        ch = request_challenge(ChallengeRequest(username=username))
        msg = b"ECC-SIS-AUTH|" + username.encode("utf-8") + b"|" + bytes.fromhex(ch["nonce_hex"])
        sig = ecdsa_sign(kp.private_key, msg, SECP256R1)
        ver = verify_challenge(
            VerifyChallengeRequest(
                challenge_id=ch["challenge_id"],
                username=username,
                signature_hex=sig.to_hex(),
            )
        )
        self.assertIn("access_token", ver)

        # Replay of same challenge must fail
        with self.assertRaises(HTTPException) as ctx:
            verify_challenge(
                VerifyChallengeRequest(
                    challenge_id=ch["challenge_id"],
                    username=username,
                    signature_hex=sig.to_hex(),
                )
            )
        self.assertEqual(ctx.exception.status_code, 400)
        return kp, ver["access_token"]

    def test_invalid_public_key_rejected(self) -> None:
        from sis_app.main import RegisterRequest, register_user

        with self.assertRaises(HTTPException) as ctx:
            register_user(
                RegisterRequest(
                    username="mallory",
                    display_name="Mallory",
                    curve="secp256r1",
                    public_key_hex="04" + "00" * 64,
                )
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_e2ee_messaging_tamper_and_audit(self) -> None:
        from sis_app.main import (
            SendEncryptedMessageRequest,
            inspect_server_database,
            list_my_messages,
            send_encrypted_message,
            simulate_ciphertext_tamper,
            verify_audit,
        )
        from sis_app.security import get_current_user

        alice_kp, alice_token = self._register_and_login("alice", "Alice")
        bob_kp, bob_token = self._register_and_login("bob", "Bob")

        alice_user = get_current_user(f"Bearer {alice_token}")
        bob_user = get_current_user(f"Bearer {bob_token}")
        self.assertEqual(alice_user, "alice")
        self.assertEqual(bob_user, "bob")

        aad_text = "alice|bob|text|"
        plaintext = b"Top secret medical record for Bob"
        pkt = ecies_encrypt(bob_kp.public_key, plaintext, aad=aad_text.encode("utf-8"))
        sig = sign_encrypted_packet(alice_kp.private_key, pkt, alice_kp.public_key, aad=aad_text.encode("utf-8"))

        sent = send_encrypted_message(
            SendEncryptedMessageRequest(
                recipient="bob",
                msg_type="text",
                filename="",
                mime_type="text/plain",
                file_size=0,
                curve="secp256r1",
                ephemeral_pubkey_hex=pkt.ephemeral_public_key.hex(),
                nonce_hex=pkt.nonce.hex(),
                ciphertext_hex=pkt.ciphertext.hex(),
                signature_hex=sig.to_hex(),
                aad_text=aad_text,
            ),
            current_user=alice_user,
        )
        msg_id = sent["id"]

        # Zero-knowledge inspector must not contain plaintext
        insp = inspect_server_database(current_user=bob_user)
        self.assertNotIn("Top secret medical record", str(insp))

        # Bob verifies and decrypts
        inbox = list_my_messages(current_user=bob_user)["messages"]
        self.assertEqual(len(inbox), 1)
        m = inbox[0]
        rec_pkt = ECIESEncryptedPacket(
            curve_name=m["curve"],
            ephemeral_public_key=bytes.fromhex(m["ephemeral_pubkey_hex"]),
            nonce=bytes.fromhex(m["nonce_hex"]),
            ciphertext=bytes.fromhex(m["ciphertext_hex"]),
        )
        rec_sig = ECDSASignature.from_p1363(bytes.fromhex(m["signature_hex"]), 32)
        sender_pub = SECP256R1.decode_point(bytes.fromhex(m["sender_public_key_hex"]))
        self.assertTrue(verify_encrypted_packet_signature(sender_pub, rec_pkt, rec_sig, aad=aad_text.encode("utf-8")))
        self.assertEqual(ecies_decrypt(bob_kp.private_key, rec_pkt, bob_kp.public_key, aad=aad_text.encode("utf-8")), plaintext)

        # Simulate tamper on server DB -> Bob's verification & decryption both fail
        tamper = simulate_ciphertext_tamper(msg_id, current_user=bob_user)
        self.assertTrue(tamper["tampered"])

        inbox2 = list_my_messages(current_user=bob_user)["messages"]
        m2 = inbox2[0]
        bad_pkt = ECIESEncryptedPacket(
            curve_name=m2["curve"],
            ephemeral_public_key=bytes.fromhex(m2["ephemeral_pubkey_hex"]),
            nonce=bytes.fromhex(m2["nonce_hex"]),
            ciphertext=bytes.fromhex(m2["ciphertext_hex"]),
        )
        self.assertFalse(verify_encrypted_packet_signature(sender_pub, bad_pkt, rec_sig, aad=aad_text.encode("utf-8")))
        with self.assertRaises(InvalidTagError):
            ecies_decrypt(bob_kp.private_key, bad_pkt, bob_kp.public_key, aad=aad_text.encode("utf-8"))

        # Audit chain integrity check
        audit = verify_audit()
        self.assertTrue(audit["valid"])
        self.assertGreaterEqual(audit["total_entries"], 6)

    def test_lab_endpoints(self) -> None:
        from sis_app.routes_lab import (
            CurveSelectRequest,
            ECDSADemoRequest,
            ECIESDemoRequest,
            PointOpsRequest,
            compute_toy_point_ops,
            get_toy_curve_points,
            run_ecdh_demo,
            run_ecdsa_demo,
            run_ecies_demo,
        )

        toy = get_toy_curve_points()
        self.assertEqual(toy["order"], 103)
        ops = compute_toy_point_ops(PointOpsRequest(px=2, py=4, qx=1, qy=43, k=5))
        self.assertEqual(len(ops["trace"]), 3)
        ecdh = run_ecdh_demo(CurveSelectRequest(curve="secp256r1"))
        self.assertTrue(ecdh["shared_secrets_match"])
        ecdsa = run_ecdsa_demo(ECDSADemoRequest(demonstrate_nonce_reuse=True))
        self.assertTrue(ecdsa["nonce_reuse_attack"]["private_key_compromised"])
        ecies = run_ecies_demo(ECIESDemoRequest(simulate_tamper=True))
        self.assertTrue(ecies["tamper_rejected"])


if __name__ == "__main__":
    unittest.main()
