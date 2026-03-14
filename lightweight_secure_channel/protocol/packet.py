"""Protocol packet definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SecurePacket:
    """Encrypted packet transported over the secure channel."""

    protocol_version: str
    session_id: str
    sequence_number: int
    nonce: bytes
    ciphertext: bytes
    authentication_tag: bytes

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "session_id": self.session_id,
            "sequence_number": self.sequence_number,
            "nonce": self.nonce.hex(),
            "ciphertext": self.ciphertext.hex(),
            "authentication_tag": self.authentication_tag.hex(),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SecurePacket":
        return cls(
            protocol_version=str(payload["protocol_version"]),
            session_id=str(payload["session_id"]),
            sequence_number=int(payload["sequence_number"]),
            nonce=bytes.fromhex(payload["nonce"]),
            ciphertext=bytes.fromhex(payload["ciphertext"]),
            authentication_tag=bytes.fromhex(payload["authentication_tag"]),
        )


def build_associated_data(packet: SecurePacket) -> bytes:
    """Build associated data for packet authentication."""
    return (
        packet.protocol_version.encode("utf-8")
        + b"|"
        + packet.session_id.encode("utf-8")
        + b"|"
        + str(packet.sequence_number).encode("utf-8")
    )
