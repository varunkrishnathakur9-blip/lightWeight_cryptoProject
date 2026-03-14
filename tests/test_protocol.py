"""Protocol integration tests."""

from __future__ import annotations

import socket
import threading
import unittest

from lightweight_secure_channel.protocol.handshake import perform_client_handshake, perform_server_handshake
from lightweight_secure_channel.protocol.secure_channel import SecureChannel, receive_secure_message, send_secure_message
from lightweight_secure_channel.protocol.session_manager import SessionManager


class TestProtocol(unittest.TestCase):
    def setUp(self) -> None:
        self.client_sessions = SessionManager(session_timeout=300)
        self.server_sessions = SessionManager(session_timeout=300)

    def _run_pair(self, resume_cid: str | None = None) -> tuple[bool, str]:
        client_sock, server_sock = socket.socketpair()
        result_box: dict = {}

        def server_worker() -> None:
            with server_sock:
                stream = server_sock.makefile("rwb")
                try:
                    server_handshake = perform_server_handshake(stream, self.server_sessions)
                    server_channel = SecureChannel(
                        session_id=server_handshake.session_id,
                        key_material=server_handshake.key_material,
                    )
                    incoming = receive_secure_message(stream, server_channel)
                    send_secure_message(stream, server_channel, b"ACK:" + incoming)
                    result_box["resumed"] = server_handshake.resumed
                    result_box["cid"] = server_handshake.connection_id
                finally:
                    stream.close()

        thread = threading.Thread(target=server_worker, daemon=True)
        thread.start()

        with client_sock:
            stream = client_sock.makefile("rwb")
            try:
                client_handshake = perform_client_handshake(
                    stream,
                    self.client_sessions,
                    resume_connection_id=resume_cid,
                )
                client_channel = SecureChannel(
                    session_id=client_handshake.session_id,
                    key_material=client_handshake.key_material,
                )
                send_secure_message(stream, client_channel, b"hello")
                response = receive_secure_message(stream, client_channel)
                self.assertEqual(response, b"ACK:hello")
                result_box["client_resumed"] = client_handshake.resumed
                result_box["client_cid"] = client_handshake.connection_id
            finally:
                stream.close()

        thread.join(timeout=5)
        self.assertIn("cid", result_box)
        self.assertIn("client_cid", result_box)
        self.assertEqual(result_box["cid"], result_box["client_cid"])
        return bool(result_box["client_resumed"]), str(result_box["client_cid"])

    def test_full_then_resumed_handshake(self) -> None:
        resumed_first, cid = self._run_pair()
        self.assertFalse(resumed_first)

        resumed_second, _ = self._run_pair(resume_cid=cid)
        self.assertTrue(resumed_second)


if __name__ == "__main__":
    unittest.main()
