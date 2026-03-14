"""IoT client for secure communication with a gateway."""

from __future__ import annotations

import socket
from typing import Optional

from lightweight_secure_channel.protocol.handshake import HandshakeResult, perform_client_handshake
from lightweight_secure_channel.protocol.secure_channel import SecureChannel, receive_secure_message, send_secure_message
from lightweight_secure_channel.protocol.session_manager import SessionManager


class IoTClient:
    """Client-side network and protocol orchestration."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9010,
        session_timeout: int = 300,
    ) -> None:
        self.host = host
        self.port = port
        self.session_manager = SessionManager(session_timeout=session_timeout)
        self.socket: Optional[socket.socket] = None
        self.stream = None
        self.channel: Optional[SecureChannel] = None
        self._last_connection_id: str | None = None

    def connect(self) -> None:
        """Open TCP connection to gateway."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.stream = self.socket.makefile("rwb")

    def resume_session_if_available(self) -> str | None:
        """Return connection ID for resumption when available."""
        if self._last_connection_id is None:
            return None
        record = self.session_manager.resume_session(self._last_connection_id)
        if record is None:
            return None
        return record.connection_id

    def perform_handshake(self) -> HandshakeResult:
        """Execute handshake; try lightweight resumption first."""
        if self.stream is None:
            raise RuntimeError("Client must connect before handshake.")

        resume_connection_id = self.resume_session_if_available()
        result = perform_client_handshake(
            stream=self.stream,
            session_manager=self.session_manager,
            resume_connection_id=resume_connection_id,
            context_info=b"iot-device->gateway",
        )

        session_record = self.session_manager.get_session(result.session_id)
        start_counter = session_record.nonce_counter if session_record is not None else 0
        self.channel = SecureChannel(
            session_id=result.session_id,
            key_material=result.key_material,
            start_nonce_counter=start_counter,
        )
        self._last_connection_id = result.connection_id
        return result

    def send_encrypted_messages(self, messages: list[str]) -> list[str]:
        """Send encrypted messages and collect encrypted ACK responses."""
        if self.stream is None or self.channel is None:
            raise RuntimeError("Handshake must be completed before sending messages.")

        responses: list[str] = []
        for message in messages:
            send_secure_message(self.stream, self.channel, message.encode("utf-8"))
            response = receive_secure_message(self.stream, self.channel)
            responses.append(response.decode("utf-8"))

        self.session_manager.advance_nonce_counter(self.channel.session_id, self.channel.nonce_counter)
        return responses

    def close(self) -> None:
        """Gracefully close network resources."""
        try:
            if self.stream is not None and self.channel is not None:
                send_secure_message(self.stream, self.channel, b"__close__")
        except Exception:
            pass

        if self.stream is not None:
            self.stream.close()
        if self.socket is not None:
            self.socket.close()

        self.stream = None
        self.socket = None
        self.channel = None
