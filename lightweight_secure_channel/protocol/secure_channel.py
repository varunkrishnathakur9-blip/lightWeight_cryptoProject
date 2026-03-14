"""Secure channel packet encryption/decryption routines."""

from __future__ import annotations

import json
from io import BufferedRWPair
from typing import Any

from lightweight_secure_channel.crypto.ascon_cipher import decrypt, encrypt
from lightweight_secure_channel.crypto.kdf import KeyMaterial
from lightweight_secure_channel.crypto.nonce_manager import NonceManager
from lightweight_secure_channel.protocol.handshake import PROTOCOL_VERSION
from lightweight_secure_channel.protocol.packet import SecurePacket, build_associated_data


class ReplayProtectionError(ValueError):
    """Raised when sequence numbers indicate replay or reordering attack."""


class SecureChannel:
    """Session-bound ASCON-protected communication channel."""

    def __init__(self, session_id: str, key_material: KeyMaterial, start_nonce_counter: int = 0) -> None:
        self.session_id = session_id
        self.key_material = key_material
        self.nonce_manager = NonceManager(nonce_seed=key_material.nonce_seed, counter=start_nonce_counter)
        self._last_received_sequence = -1

    def encrypt_packet(self, plaintext: bytes) -> SecurePacket:
        """Encrypt payload into prompt-required packet format."""
        nonce, sequence_number = self.nonce_manager.next_nonce()
        aad_probe = SecurePacket(
            protocol_version=PROTOCOL_VERSION,
            session_id=self.session_id,
            sequence_number=sequence_number,
            nonce=nonce,
            ciphertext=b"",
            authentication_tag=b"",
        )
        associated_data = build_associated_data(aad_probe)
        ciphertext, tag = encrypt(
            key=self.key_material.session_key,
            nonce=nonce,
            plaintext=plaintext,
            associated_data=associated_data,
        )
        return SecurePacket(
            protocol_version=PROTOCOL_VERSION,
            session_id=self.session_id,
            sequence_number=sequence_number,
            nonce=nonce,
            ciphertext=ciphertext,
            authentication_tag=tag,
        )

    def decrypt_packet(self, packet: SecurePacket) -> bytes:
        """Decrypt and authenticate a packet while enforcing replay protection."""
        if packet.session_id != self.session_id:
            raise ValueError("Session ID mismatch.")
        if packet.sequence_number <= self._last_received_sequence:
            raise ReplayProtectionError("Detected stale sequence number.")

        associated_data = build_associated_data(packet)
        plaintext = decrypt(
            key=self.key_material.session_key,
            nonce=packet.nonce,
            ciphertext=packet.ciphertext,
            associated_data=associated_data,
            authentication_tag=packet.authentication_tag,
        )
        self._last_received_sequence = packet.sequence_number
        return plaintext

    @property
    def nonce_counter(self) -> int:
        return self.nonce_manager.counter


def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
    stream.flush()


def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
    line = stream.readline()
    if not line:
        raise EOFError("Stream closed while reading secure packet.")
    return json.loads(line.decode("utf-8"))


def send_secure_message(stream: BufferedRWPair, channel: SecureChannel, plaintext: bytes) -> SecurePacket:
    """Serialize and send an encrypted packet."""
    packet = channel.encrypt_packet(plaintext)
    _send_json(stream, {"type": "SecurePacket", "packet": packet.to_dict()})
    return packet


def receive_secure_message(stream: BufferedRWPair, channel: SecureChannel) -> bytes:
    """Receive one encrypted packet and decrypt it."""
    envelope = _recv_json(stream)
    if envelope.get("type") != "SecurePacket":
        raise ValueError("Expected SecurePacket envelope.")
    packet = SecurePacket.from_dict(envelope["packet"])
    return channel.decrypt_packet(packet)
