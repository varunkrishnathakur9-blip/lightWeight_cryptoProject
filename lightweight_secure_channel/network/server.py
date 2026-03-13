"""TCP gateway server for the lightweight secure channel protocol."""

from __future__ import annotations

import socket
import threading
from typing import Optional

from lightweight_secure_channel.protocol.handshake import HandshakeResult, perform_server_handshake
from lightweight_secure_channel.protocol.secure_channel import ReplayError, SecureChannel
from lightweight_secure_channel.protocol.session_manager import SessionManager
from lightweight_secure_channel.utils.logger import configure_logger


class GatewayServer:
    """Gateway endpoint implementing secure channel handshakes and packet exchange."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9009,
        kdf_mode: str = "ascon",
        session_timeout: int = 300,
    ) -> None:
        self.host = host
        self.port = port
        self.kdf_mode = kdf_mode
        self.session_manager = SessionManager(session_timeout=session_timeout)
        self.logger = configure_logger("lscp.server")
        self._running = threading.Event()
        self._server_socket: Optional[socket.socket] = None

    def start_in_thread(self) -> threading.Thread:
        """Start server in a daemon thread."""
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread

    def stop(self) -> None:
        """Request server shutdown."""
        self._running.clear()
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass

    def serve_forever(self) -> None:
        """Run accept loop until stopped."""
        self._running.set()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            self._server_socket = server_socket
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen()
            server_socket.settimeout(1.0)
            self.logger.info("Gateway listening on %s:%s", self.host, self.port)

            while self._running.is_set():
                try:
                    conn, addr = server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                self.logger.info("Accepted connection from %s:%s", addr[0], addr[1])
                self._handle_connection(conn)

    def _handle_connection(self, conn: socket.socket) -> None:
        with conn:
            stream = conn.makefile("rwb")
            try:
                handshake: HandshakeResult = perform_server_handshake(
                    stream=stream,
                    session_manager=self.session_manager,
                    kdf_mode=self.kdf_mode,
                )
                channel = SecureChannel(
                    session_id=handshake.session_id,
                    key_material=handshake.key_material,
                )
                self.logger.info(
                    "Handshake complete (session_id=%s resumed=%s)",
                    handshake.session_id,
                    handshake.resumed,
                )

                while True:
                    try:
                        plaintext = channel.receive_secure_message(stream)
                    except EOFError:
                        break
                    except ReplayError as error:
                        self.logger.warning("Dropped replayed packet: %s", error)
                        break

                    message = plaintext.decode("utf-8")
                    if message == "__close__":
                        break
                    channel.send_secure_message(stream, f"ACK:{message}")
            finally:
                stream.close()

