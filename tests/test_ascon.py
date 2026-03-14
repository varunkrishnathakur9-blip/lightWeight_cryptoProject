"""ASCON AEAD tests."""

from __future__ import annotations

import os
import unittest

from lightweight_secure_channel.crypto.ascon_cipher import decrypt, encrypt


class TestASCON(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self) -> None:
        key = os.urandom(16)
        nonce = os.urandom(16)
        plaintext = b"iot-sensor-payload"
        associated_data = b"session|42|v2"

        ciphertext, tag = encrypt(key, nonce, plaintext, associated_data)
        recovered = decrypt(key, nonce, ciphertext, associated_data, authentication_tag=tag)
        self.assertEqual(recovered, plaintext)

    def test_four_argument_decrypt_mode(self) -> None:
        key = os.urandom(16)
        nonce = os.urandom(16)
        plaintext = b"abc123"
        associated_data = b"aad"

        ciphertext, tag = encrypt(key, nonce, plaintext, associated_data)
        packed = ciphertext + tag
        recovered = decrypt(key, nonce, packed, associated_data)
        self.assertEqual(recovered, plaintext)

    def test_tag_verification_failure(self) -> None:
        key = os.urandom(16)
        nonce = os.urandom(16)
        plaintext = b"critical"
        associated_data = b"aad"

        ciphertext, tag = encrypt(key, nonce, plaintext, associated_data)
        bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
        with self.assertRaises(ValueError):
            decrypt(key, nonce, ciphertext, associated_data, authentication_tag=bad_tag)


if __name__ == "__main__":
    unittest.main()
