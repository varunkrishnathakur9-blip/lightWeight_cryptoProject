"""Sponge-based lightweight KDF for session material derivation (native ASCON backend)."""

from __future__ import annotations

from dataclasses import dataclass

from lightweight_secure_channel.crypto.ascon_cipher import sponge_hash

STATE_WORDS = 5
WORD_BYTES = 8
STATE_BYTES = STATE_WORDS * WORD_BYTES


@dataclass(frozen=True)
class KeyMaterial:
    """Derived per-session keys and nonce seed."""

    session_key: bytes
    auth_key: bytes
    nonce_seed: bytes


def _state_to_bytes(state: list[int]) -> bytes:
    if len(state) != STATE_WORDS:
        raise ValueError(f"state must have {STATE_WORDS} 64-bit words")
    return b"".join(int(word & ((1 << 64) - 1)).to_bytes(WORD_BYTES, "big") for word in state)


def _bytes_to_state(blob: bytes) -> list[int]:
    if len(blob) != STATE_BYTES:
        raise ValueError(f"state encoding must be {STATE_BYTES} bytes")
    return [int.from_bytes(blob[index : index + WORD_BYTES], "big") for index in range(0, STATE_BYTES, WORD_BYTES)]


def absorb(shared_secret: bytes, context_info: bytes = b"") -> list[int]:
    """Absorb phase using native ASCON sponge/hash primitive."""
    payload = b"LSCP-SPONGE-ABSORB" + context_info + shared_secret
    return _bytes_to_state(sponge_hash(payload, output_length=STATE_BYTES))


def permute(state: list[int]) -> list[int]:
    """Permute phase using native ASCON sponge/hash primitive."""
    material = sponge_hash(b"LSCP-SPONGE-PERMUTE" + _state_to_bytes(state), output_length=STATE_BYTES)
    state[:] = _bytes_to_state(material)
    return state


def squeeze(state: list[int], output_length: int = 48) -> bytes:
    """Squeeze phase using native ASCON sponge/hash primitive."""
    if output_length <= 0:
        raise ValueError("output_length must be positive.")
    return sponge_hash(b"LSCP-SPONGE-SQUEEZE" + _state_to_bytes(state), output_length=output_length)


def derive_keys(shared_secret: bytes, context_info: bytes = b"") -> KeyMaterial:
    """Derive session keys from shared secret and optional context."""
    state = absorb(shared_secret=shared_secret, context_info=context_info)
    permute(state)
    material = squeeze(state, output_length=48)
    return KeyMaterial(
        session_key=material[:16],
        auth_key=material[16:32],
        nonce_seed=material[32:48],
    )
