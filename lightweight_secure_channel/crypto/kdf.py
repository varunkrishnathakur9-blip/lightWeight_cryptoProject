"""Sponge-based lightweight KDF for session material derivation."""

from __future__ import annotations

from dataclasses import dataclass

from lightweight_secure_channel.crypto.ascon_cipher import permute_state

RATE_BYTES = 8


@dataclass(frozen=True)
class KeyMaterial:
    """Derived per-session keys and nonce seed."""

    session_key: bytes
    auth_key: bytes
    nonce_seed: bytes


def _pad(block: bytes, rate: int = RATE_BYTES) -> bytes:
    if len(block) >= rate:
        raise ValueError("Padding requires a partial block.")
    return block + b"\x80" + b"\x00" * (rate - len(block) - 1)


def absorb(shared_secret: bytes, context_info: bytes = b"") -> list[int]:
    """Absorb phase of the sponge-based KDF."""
    state = [0x00400C0000000100, 0, 0, 0, 0]
    permute_state(state, rounds=12)
    payload = b"LSCP-SPONGE-KDF" + context_info + shared_secret

    full_blocks = len(payload) // RATE_BYTES
    for block_index in range(full_blocks):
        block = payload[block_index * RATE_BYTES : (block_index + 1) * RATE_BYTES]
        state[0] ^= int.from_bytes(block, "big")
        permute_state(state, rounds=12)

    remainder = payload[full_blocks * RATE_BYTES :]
    state[0] ^= int.from_bytes(_pad(remainder), "big")
    return state


def permute(state: list[int]) -> list[int]:
    """Permute phase of the sponge construction."""
    permute_state(state, rounds=12)
    return state


def squeeze(state: list[int], output_length: int = 48) -> bytes:
    """Squeeze phase of the sponge construction."""
    if output_length <= 0:
        raise ValueError("output_length must be positive.")

    output = bytearray()
    while len(output) < output_length:
        output.extend(state[0].to_bytes(RATE_BYTES, "big"))
        permute_state(state, rounds=12)
    return bytes(output[:output_length])


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
