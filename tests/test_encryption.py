"""Secure channel encryption tests."""

from __future__ import annotations

import unittest

from lightweight_secure_channel.crypto.kdf import derive_session_keys
from lightweight_secure_channel.protocol.secure_channel import ReplayError, SecureChannel, SecurePacket


class EncryptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key_material = derive_session_keys(
            shared_secret=b"shared-secret-for-test-suite-32-bytes!",
            mode="ascon",
        )

    def test_encrypt_decrypt_round_trip(self) -> None:
        sender = SecureChannel(session_id="sess-test", key_material=self.key_material)
        receiver = SecureChannel(session_id="sess-test", key_material=self.key_material)
        packet = sender.encrypt_packet(b"hello secure world")
        plaintext = receiver.decrypt_packet(packet)
        self.assertEqual(plaintext, b"hello secure world")

    def test_replay_attack_prevention(self) -> None:
        sender = SecureChannel(session_id="sess-test", key_material=self.key_material)
        receiver = SecureChannel(session_id="sess-test", key_material=self.key_material)
        packet = sender.encrypt_packet(b"message-1")
        _ = receiver.decrypt_packet(packet)
        with self.assertRaises(ReplayError):
            receiver.decrypt_packet(packet)

    def test_authentication_failure(self) -> None:
        sender = SecureChannel(session_id="sess-test", key_material=self.key_material)
        receiver = SecureChannel(session_id="sess-test", key_material=self.key_material)
        packet = sender.encrypt_packet(b"tamper-check")
        tampered = SecurePacket(
            session_id=packet.session_id,
            sequence_number=packet.sequence_number,
            nonce=packet.nonce,
            ciphertext=packet.ciphertext[:-1] + bytes([packet.ciphertext[-1] ^ 0x01]),
            tag=packet.tag,
        )
        with self.assertRaises(ValueError):
            receiver.decrypt_packet(tampered)


if __name__ == "__main__":
    unittest.main()

