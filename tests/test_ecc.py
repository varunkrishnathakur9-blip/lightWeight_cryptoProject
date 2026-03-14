"""ECC primitive tests."""

from __future__ import annotations

import unittest

from lightweight_secure_channel.crypto.ecc import (
    compute_shared_secret,
    deserialize_public_key,
    generate_keypair,
    serialize_public_key,
)


class TestECC(unittest.TestCase):
    def test_ecdh_shared_secret_match(self) -> None:
        priv_a, pub_a = generate_keypair()
        priv_b, pub_b = generate_keypair()

        secret_a = compute_shared_secret(priv_a, pub_b)
        secret_b = compute_shared_secret(priv_b, pub_a)
        self.assertEqual(secret_a, secret_b)

    def test_public_key_serialize_roundtrip(self) -> None:
        _, public_key = generate_keypair()
        encoded = serialize_public_key(public_key)
        decoded = deserialize_public_key(encoded)
        self.assertEqual(serialize_public_key(decoded), encoded)


if __name__ == "__main__":
    unittest.main()
