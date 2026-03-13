"""TCP client for secure communication with the gateway server."""

from __future__ import annotations

import socket
from typing import Optional

from lightweight_secure_channel.protocol.handshake import HandshakeResult, perform_client_handshake
from lightweight_secure_channel.protocol.secure_channel import SecureChannel
from lightweight_secure_channel.protocol.session_manager import SessionManager
from lightweight_secure_channel.utils.logger import configure_logger


class IoTClient:
    """IoT node simulation client."""

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
        self.logger = configure_logger("lscp.client")

        self.socket: Optional[socket.socket] = None
        self.stream = None
        self.channel: Optional[SecureChannel] = None
        self.resume_token: dict | None = None

    def connect(self) -> HandshakeResult:
        """Connect to server and establish (or resume) secure session."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.stream = self.socket.makefile("rwb")

        result = perform_client_handshake(
            stream=self.stream,
            session_manager=self.session_manager,
            resume_token=self.resume_token,
            kdf_mode=self.kdf_mode,
        )
        self.resume_token = result.session_token
        self.channel = SecureChannel(
            session_id=result.session_id,
            key_material=result.key_material,
        )
        self.logger.info(
            "Connected with session_id=%s resumed=%s",
            result.session_id,
            result.resumed,
        )
        return result

    def send_message(self, message: str) -> str:
        """Send an encrypted message and wait for server response."""
        if self.channel is None or self.stream is None:
            raise RuntimeError("Client is not connected.")
        self.channel.send_secure_message(self.stream, message)
        response = self.channel.receive_secure_message(self.stream)
        return response.decode("utf-8")

    def close(self) -> None:
        """Close active connection."""
        try:
            if self.channel is not None and self.stream is not None:
                self.channel.send_secure_message(self.stream, "__close__")
        except Exception:
            pass
        finally:
            if self.stream is not None:
                self.stream.close()
            if self.socket is not None:
                self.socket.close()
            self.stream = None
            self.socket = None
            self.channel = None

