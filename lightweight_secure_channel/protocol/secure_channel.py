"""Encrypted packet layer for secure message transport."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from io import BufferedRWPair
from typing import Any

from lightweight_secure_channel.crypto.ascon_cipher import ascon_decrypt, ascon_encrypt, ascon_hash
from lightweight_secure_channel.crypto.kdf import KeyMaterial
from lightweight_secure_channel.protocol.handshake import PROTOCOL_VERSION


class ReplayError(ValueError):
    """Raised when sequence number validation fails."""


@dataclass(frozen=True)
class SecurePacket:
    """Wire packet format for encrypted channel payloads."""

    session_id: str
    sequence_number: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "sequence_number": self.sequence_number,
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "tag": self.tag.hex(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecurePacket":
        return cls(
            session_id=str(payload["session_id"]),
            sequence_number=int(payload["sequence_number"]),
            nonce=bytes.fromhex(payload["nonce"]),
            ciphertext=bytes.fromhex(payload["ciphertext"]),
            tag=bytes.fromhex(payload["tag"]),
        )


def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload).encode("utf-8") + b"\n")
    stream.flush()


def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
    line = stream.readline()
    if not line:
        raise EOFError("Connection closed while reading secure packet.")
    return json.loads(line.decode("utf-8"))


class SecureChannel:
    """Session-bound ASCON secure transport layer."""

    def __init__(
        self,
        session_id: str,
        key_material: KeyMaterial,
        protocol_version: str = PROTOCOL_VERSION,
    ) -> None:
        self.session_id = session_id
        self.key_material = key_material
        self.protocol_version = protocol_version
        self._send_sequence = 0
        self._last_received_sequence = -1

    def _build_ad(self, sequence_number: int) -> bytes:
        version_bytes = self.protocol_version.encode("utf-8")
        return (
            self.session_id.encode("utf-8")
            + struct.pack(">Q", sequence_number)
            + struct.pack(">H", len(version_bytes))
            + version_bytes
        )

    def _derive_nonce(self, sequence_number: int) -> bytes:
        return ascon_hash(
            self.key_material.nonce_seed + struct.pack(">Q", sequence_number), out_len=16
        )

    def encrypt_packet(self, plaintext: bytes) -> SecurePacket:
        """Encrypt plaintext and return an authenticated packet."""
        sequence_number = self._send_sequence
        nonce = self._derive_nonce(sequence_number)
        ad = self._build_ad(sequence_number)
        ciphertext, tag = ascon_encrypt(
            key=self.key_material.session_key,
            nonce=nonce,
            ad=ad,
            plaintext=plaintext,
        )
        self._send_sequence += 1
        return SecurePacket(
            session_id=self.session_id,
            sequence_number=sequence_number,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
        )

    def decrypt_packet(self, packet: SecurePacket) -> bytes:
        """Decrypt packet after replay and session checks."""
        if packet.session_id != self.session_id:
            raise ValueError("Session ID mismatch.")
        if packet.sequence_number <= self._last_received_sequence:
            raise ReplayError("Replay attack detected due to stale sequence number.")

        ad = self._build_ad(packet.sequence_number)
        plaintext = ascon_decrypt(
            key=self.key_material.session_key,
            nonce=packet.nonce,
            ad=ad,
            ciphertext=packet.ciphertext,
            tag=packet.tag,
        )
        self._last_received_sequence = packet.sequence_number
        return plaintext

    def send_secure_message(self, stream: BufferedRWPair, message: str | bytes) -> SecurePacket:
        """Encrypt and write a message to the stream."""
        payload = message.encode("utf-8") if isinstance(message, str) else message
        packet = self.encrypt_packet(payload)
        _send_json(stream, {"type": "SecurePacket", "packet": packet.to_dict()})
        return packet

    def receive_secure_message(self, stream: BufferedRWPair) -> bytes:
        """Read, verify, and decrypt one secure packet."""
        envelope = _recv_json(stream)
        if envelope.get("type") != "SecurePacket":
            raise ValueError("Expected SecurePacket envelope.")
        packet = SecurePacket.from_dict(envelope["packet"])
        return self.decrypt_packet(packet)

