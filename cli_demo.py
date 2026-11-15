"""Terminal end-to-end demonstration of ECC-SIS powered purely by `ecc_core`."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from ecc_core import (
    ECDSASignature,
    ECIESEncryptedPacket,
    SECP256R1,
    ecies_decrypt,
    ecies_encrypt,
    generate_keypair,
    sign as ecdsa_sign,
    sign_encrypted_packet,
    verify_encrypted_packet_signature,
)


def authenticate_user(username: str, keypair) -> str:
    from sis_app.main import ChallengeRequest, VerifyChallengeRequest, request_challenge, verify_challenge

    ch = request_challenge(ChallengeRequest(username=username))
    msg = b"ECC-SIS-AUTH|" + username.encode("utf-8") + b"|" + bytes.fromhex(ch["nonce_hex"])
    sig = ecdsa_sign(keypair.private_key, msg, SECP256R1)
    ver = verify_challenge(
        VerifyChallengeRequest(
            challenge_id=ch["challenge_id"],
            username=username,
            signature_hex=sig.to_hex(),
        )
    )
    return ver["access_token"]


def main() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ["SIS_DB_PATH"] = str(Path(tmpdir) / "demo.db")
        from sis_app.database import init_db
        from sis_app.main import (
            RegisterRequest,
            SendEncryptedMessageRequest,
            list_my_messages,
            register_user,
            send_encrypted_message,
            verify_audit,
        )
        from sis_app.security import get_current_user

        init_db()

        print("=== 1. Generating P-256 Identity Keypairs (pure-Python ecc_core) ===")
        alice = generate_keypair(SECP256R1)
        bob = generate_keypair(SECP256R1)
        print(f"Alice PubKey (compressed): {alice.public_hex(compressed=True)}")
        print(f"Bob   PubKey (compressed): {bob.public_hex(compressed=True)}")

        register_user(
            RegisterRequest(
                username="alice",
                display_name="Alice Tran",
                curve="secp256r1",
                public_key_hex=alice.public_hex(),
            )
        )
        register_user(
            RegisterRequest(
                username="bob",
                display_name="Bob Le",
                curve="secp256r1",
                public_key_hex=bob.public_hex(),
            )
        )

        print("\n=== 2. ECDSA Challenge-Response Authentication ===")
        alice_token = authenticate_user("alice", alice)
        bob_token = authenticate_user("bob", bob)
        alice_user = get_current_user(f"Bearer {alice_token}")
        bob_user = get_current_user(f"Bearer {bob_token}")
        print("Alice & Bob authenticated successfully via ECDSA signatures.")

        print("\n=== 3. Alice Encrypts (ECIES: ECDH + HKDF + AES-256-GCM) & Signs (ECDSA) ===")
        secret_text = b"Confidential System Key Rotation Token: X9A-772-ECC"
        aad_text = "alice|bob|text|"
        pkt = ecies_encrypt(bob.public_key, secret_text, aad=aad_text.encode("utf-8"))
        sig = sign_encrypted_packet(alice.private_key, pkt, alice.public_key, aad=aad_text.encode("utf-8"))

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
        print(f"Stored encrypted packet msg_id={sent['id']} on server (ciphertext={pkt.ciphertext.hex()[:32]}...).")

        print("\n=== 4. Bob Fetches, Verifies ECDSA Signature, and Decrypts ===")
        inbox = list_my_messages(current_user=bob_user)["messages"]
        m = inbox[0]
        rec_pkt = ECIESEncryptedPacket(
            curve_name=m["curve"],
            ephemeral_public_key=bytes.fromhex(m["ephemeral_pubkey_hex"]),
            nonce=bytes.fromhex(m["nonce_hex"]),
            ciphertext=bytes.fromhex(m["ciphertext_hex"]),
        )
        rec_sig = ECDSASignature.from_p1363(bytes.fromhex(m["signature_hex"]), 32)
        sender_pub = SECP256R1.decode_point(bytes.fromhex(m["sender_public_key_hex"]))
        aad_bytes = m["aad_text"].encode("utf-8")

        assert verify_encrypted_packet_signature(sender_pub, rec_pkt, rec_sig, aad=aad_bytes)
        plaintext = ecies_decrypt(bob.private_key, rec_pkt, bob.public_key, aad=aad_bytes)
        print(f"Verified ECDSA signature & decrypted plaintext: {plaintext.decode('utf-8')}")

        print("\n=== 5. Audit Log Hash Chain Verification ===")
        print(json.dumps(verify_audit(), indent=2))


if __name__ == "__main__":
    main()
