"""Gateway server implementation for lightweight secure channel."""

from __future__ import annotations

import logging
import socket
import threading
from typing import Optional

from lightweight_secure_channel.protocol.handshake import HandshakeResult, perform_server_handshake
from lightweight_secure_channel.protocol.secure_channel import (
    ReplayProtectionError,
    SecureChannel,
    receive_secure_message,
    send_secure_message,
)
from lightweight_secure_channel.protocol.session_manager import SessionManager


logger = logging.getLogger(__name__)


class GatewayServer:
    """Server-side endpoint supporting full and resumed secure sessions."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9010,
        session_timeout: int = 300,
    ) -> None:
        self.host = host
        self.port = port
        self.session_manager = SessionManager(session_timeout=session_timeout)
        self._running = threading.Event()
        self._server_socket: Optional[socket.socket] = None

    def listen(self) -> None:
        """Listen for connections and handle each sequentially."""
        self._running.set()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            self._server_socket = server_socket
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            server_socket.settimeout(1.0)

            while self._running.is_set():
                try:
                    connection, _ = server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    self._handle_connection(connection)
                except Exception:
                    # Keep the server alive even if a client speaks a different protocol.
                    logger.exception("Connection handling failed; continuing listener loop.")

    def start_in_thread(self) -> threading.Thread:
        """Start listener in a daemon thread."""
        thread = threading.Thread(target=self.listen, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        """Stop listener loop."""
        self._running.clear()
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def perform_handshake(self, stream) -> tuple[HandshakeResult, SecureChannel]:
        """Perform handshake and prepare secure channel for one connection."""
        result = perform_server_handshake(
            stream=stream,
            session_manager=self.session_manager,
            context_info=b"iot-device->gateway",
        )
        session_record = self.session_manager.get_session(result.session_id)
        start_counter = session_record.nonce_counter if session_record is not None else 0
        channel = SecureChannel(
            session_id=result.session_id,
            key_material=result.key_material,
            start_nonce_counter=start_counter,
        )
        return result, channel

    def receive_encrypted_packets(self, stream, channel: SecureChannel) -> None:
        """Receive encrypted packets and return encrypted acknowledgements."""
        while True:
            try:
                plaintext = receive_secure_message(stream, channel)
            except EOFError:
                break
            except ReplayProtectionError:
                break

            if plaintext == b"__close__":
                break
            send_secure_message(stream, channel, b"ACK:" + plaintext)

        self.session_manager.advance_nonce_counter(channel.session_id, channel.nonce_counter)

    def _handle_connection(self, connection: socket.socket) -> None:
        with connection:
            stream = connection.makefile("rwb")
            try:
                _, channel = self.perform_handshake(stream)
                self.receive_encrypted_packets(stream, channel)
            finally:
                stream.close()
