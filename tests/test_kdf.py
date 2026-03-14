"""Sponge KDF tests."""

from __future__ import annotations

import unittest

from lightweight_secure_channel.crypto.kdf import absorb, derive_keys, permute, squeeze


class TestKDF(unittest.TestCase):
    def test_absorb_permute_squeeze_flow(self) -> None:
        state = absorb(b"shared-secret", b"context")
        self.assertEqual(len(state), 5)
        permuted = permute(state)
        out = squeeze(permuted, output_length=48)
        self.assertEqual(len(out), 48)

    def test_derive_keys_lengths(self) -> None:
        material = derive_keys(b"secret-material", b"device->gateway")
        self.assertEqual(len(material.session_key), 16)
        self.assertEqual(len(material.auth_key), 16)
        self.assertEqual(len(material.nonce_seed), 16)

    def test_context_changes_output(self) -> None:
        base = derive_keys(b"secret-material", b"ctx-a")
        changed = derive_keys(b"secret-material", b"ctx-b")
        self.assertNotEqual(base.session_key, changed.session_key)


if __name__ == "__main__":
    unittest.main()
