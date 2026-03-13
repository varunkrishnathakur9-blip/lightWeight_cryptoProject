"""Handshake protocol tests."""

from __future__ import annotations

import socket
import threading
import unittest

from lightweight_secure_channel.protocol.handshake import (
    perform_client_handshake,
    perform_server_handshake,
)
from lightweight_secure_channel.protocol.session_manager import SessionManager


class HandshakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client_manager = SessionManager(session_timeout=300)
        self.server_manager = SessionManager(session_timeout=300)

    def _run_handshake(self, resume_token: dict | None = None):
        client_sock, server_sock = socket.socketpair()
        server_result: dict = {}

        def _server() -> None:
            with server_sock:
                stream = server_sock.makefile("rwb")
                try:
                    server_result["result"] = perform_server_handshake(
                        stream=stream,
                        session_manager=self.server_manager,
                        kdf_mode="ascon",
                    )
                finally:
                    stream.close()

        thread = threading.Thread(target=_server, daemon=True)
        thread.start()

        with client_sock:
            stream = client_sock.makefile("rwb")
            try:
                client_result = perform_client_handshake(
                    stream=stream,
                    session_manager=self.client_manager,
                    resume_token=resume_token,
                    kdf_mode="ascon",
                )
            finally:
                stream.close()
        thread.join(timeout=5)
        self.assertIn("result", server_result)
        return client_result, server_result["result"]

    def test_successful_full_handshake(self) -> None:
        client_result, server_result = self._run_handshake()
        self.assertEqual(client_result.session_id, server_result.session_id)
        self.assertEqual(
            client_result.key_material.session_key, server_result.key_material.session_key
        )
        self.assertFalse(client_result.resumed)
        self.assertFalse(server_result.resumed)

    def test_successful_resumed_handshake(self) -> None:
        first_client_result, _ = self._run_handshake()
        second_client_result, second_server_result = self._run_handshake(
            resume_token=first_client_result.session_token
        )
        self.assertTrue(second_client_result.resumed)
        self.assertTrue(second_server_result.resumed)
        self.assertEqual(second_client_result.session_id, first_client_result.session_id)


if __name__ == "__main__":
    unittest.main()

