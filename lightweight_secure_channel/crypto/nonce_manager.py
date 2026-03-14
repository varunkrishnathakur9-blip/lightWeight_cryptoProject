"""Nonce management for deterministic per-packet nonces."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from lightweight_secure_channel.crypto.ascon_cipher import sponge_hash


@dataclass
class NonceManager:
    """Generates unique 16-byte nonces from a session-local seed and counter."""

    nonce_seed: bytes
    counter: int = 0

    def next_nonce(self) -> tuple[bytes, int]:
        """Return a nonce and the sequence number used to derive it."""
        sequence_number = self.counter
        nonce = sponge_hash(self.nonce_seed + struct.pack(">Q", sequence_number), output_length=16)
        self.counter += 1
        return nonce, sequence_number

    def peek_nonce(self) -> tuple[bytes, int]:
        """Return nonce for the current counter without incrementing state."""
        sequence_number = self.counter
        nonce = sponge_hash(self.nonce_seed + struct.pack(">Q", sequence_number), output_length=16)
        return nonce, sequence_number

    def set_counter(self, value: int) -> None:
        """Set nonce counter explicitly (e.g., during session restore)."""
        if value < 0:
            raise ValueError("Counter must be non-negative.")
        self.counter = value
