"""Session manager tests for resumption and expiration behavior."""

from __future__ import annotations

import time
import unittest

from lightweight_secure_channel.crypto.kdf import derive_session_keys
from lightweight_secure_channel.protocol.session_manager import SessionManager


class SessionResumptionTests(unittest.TestCase):
    def test_store_and_resume_session(self) -> None:
        manager = SessionManager(session_timeout=300)
        key_material = derive_session_keys(b"session-resumption-shared-secret", mode="ascon")
        token = manager.store_session(session_id="session-1", key_material=key_material)
        resumed = manager.resume_session(token)
        self.assertIsNotNone(resumed)
        assert resumed is not None
        self.assertEqual(resumed.session_id, "session-1")

    def test_session_expiration(self) -> None:
        manager = SessionManager(session_timeout=1)
        key_material = derive_session_keys(b"expiration-test-shared-secret", mode="ascon")
        token = manager.store_session(session_id="session-exp", key_material=key_material)

        # Age the token and entry beyond timeout for deterministic expiration.
        token["timestamp"] = time.time() - 10
        manager.session_table["session-exp"].timestamp = time.time() - 10
        resumed = manager.resume_session(token)
        self.assertIsNone(resumed)

    def test_cleanup_expired_sessions(self) -> None:
        manager = SessionManager(session_timeout=1)
        key_material = derive_session_keys(b"cleanup-test-shared-secret", mode="ascon")
        manager.store_session(session_id="session-clean", key_material=key_material)
        manager.session_table["session-clean"].timestamp = time.time() - 10
        manager.cleanup_expired_sessions()
        self.assertNotIn("session-clean", manager.session_table)


if __name__ == "__main__":
    unittest.main()

