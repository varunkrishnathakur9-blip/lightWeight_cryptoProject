"""Pure-Python ASCON-128 AEAD and sponge primitives.

This module exposes Stage 2 prompt-compatible function names:
- encrypt(...)
- decrypt(...)
"""

from __future__ import annotations

import hmac
import os
from typing import Iterable

MASK64 = (1 << 64) - 1
RATE_BYTES = 8
KEY_BYTES = 16
NONCE_BYTES = 16
TAG_BYTES = 16
ASCON_128_IV = 0x80400C0600000000
ASCON_HASH_IV = 0x00400C0000000100
ROUND_CONSTANTS = [
    0xF0,
    0xE1,
    0xD2,
    0xC3,
    0xB4,
    0xA5,
    0x96,
    0x87,
    0x78,
    0x69,
    0x5A,
    0x4B,
]


def _rotr(value: int, nbits: int) -> int:
    return ((value >> nbits) | (value << (64 - nbits))) & MASK64


def _pad(block: bytes, rate: int = RATE_BYTES) -> bytes:
    if len(block) >= rate:
        raise ValueError("Padding requires a partial block.")
    return block + b"\x80" + b"\x00" * (rate - len(block) - 1)


def permute_state(state: list[int], rounds: int = 12) -> None:
    """Apply ASCON permutation to a 320-bit state."""
    for constant in ROUND_CONSTANTS[12 - rounds :]:
        state[2] ^= constant

        state[0] ^= state[4]
        state[4] ^= state[3]
        state[2] ^= state[1]

        t0 = (~state[0] & state[1]) & MASK64
        t1 = (~state[1] & state[2]) & MASK64
        t2 = (~state[2] & state[3]) & MASK64
        t3 = (~state[3] & state[4]) & MASK64
        t4 = (~state[4] & state[0]) & MASK64

        state[0] ^= t0
        state[1] ^= t1
        state[2] ^= t2
        state[3] ^= t3
        state[4] ^= t4

        state[1] ^= state[0]
        state[0] ^= state[4]
        state[3] ^= state[2]
        state[2] = (~state[2]) & MASK64

        state[0] ^= _rotr(state[0], 19) ^ _rotr(state[0], 28)
        state[1] ^= _rotr(state[1], 61) ^ _rotr(state[1], 39)
        state[2] ^= _rotr(state[2], 1) ^ _rotr(state[2], 6)
        state[3] ^= _rotr(state[3], 10) ^ _rotr(state[3], 17)
        state[4] ^= _rotr(state[4], 7) ^ _rotr(state[4], 41)

        state[0] &= MASK64
        state[1] &= MASK64
        state[2] &= MASK64
        state[3] &= MASK64
        state[4] &= MASK64


def _iter_full_blocks(data: bytes, block_size: int) -> Iterable[bytes]:
    for index in range(0, len(data) // block_size):
        start = index * block_size
        yield data[start : start + block_size]


def generate_nonce() -> bytes:
    """Generate a random 16-byte nonce for ASCON-128."""
    return os.urandom(NONCE_BYTES)


def _encrypt_detached(
    key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
) -> tuple[bytes, bytes]:
    if len(key) != KEY_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte key.")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte nonce.")

    k0 = int.from_bytes(key[:8], "big")
    k1 = int.from_bytes(key[8:], "big")
    n0 = int.from_bytes(nonce[:8], "big")
    n1 = int.from_bytes(nonce[8:], "big")

    state = [ASCON_128_IV, k0, k1, n0, n1]
    permute_state(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    if associated_data:
        for block in _iter_full_blocks(associated_data, RATE_BYTES):
            state[0] ^= int.from_bytes(block, "big")
            permute_state(state, 6)
        last_ad = associated_data[(len(associated_data) // RATE_BYTES) * RATE_BYTES :]
        state[0] ^= int.from_bytes(_pad(last_ad), "big")
        permute_state(state, 6)
    state[4] ^= 1

    ciphertext = bytearray()
    for block in _iter_full_blocks(plaintext, RATE_BYTES):
        state[0] ^= int.from_bytes(block, "big")
        ciphertext.extend(state[0].to_bytes(RATE_BYTES, "big"))
        permute_state(state, 6)

    last_plaintext = plaintext[(len(plaintext) // RATE_BYTES) * RATE_BYTES :]
    state[0] ^= int.from_bytes(_pad(last_plaintext), "big")
    ciphertext.extend(state[0].to_bytes(RATE_BYTES, "big")[: len(last_plaintext)])

    state[1] ^= k0
    state[2] ^= k1
    permute_state(state, 12)
    state[3] ^= k0
    state[4] ^= k1
    tag = state[3].to_bytes(8, "big") + state[4].to_bytes(8, "big")
    return bytes(ciphertext), tag


def _decrypt_detached(
    key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes, authentication_tag: bytes
) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte key.")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte nonce.")
    if len(authentication_tag) != TAG_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte authentication tag.")

    k0 = int.from_bytes(key[:8], "big")
    k1 = int.from_bytes(key[8:], "big")
    n0 = int.from_bytes(nonce[:8], "big")
    n1 = int.from_bytes(nonce[8:], "big")

    state = [ASCON_128_IV, k0, k1, n0, n1]
    permute_state(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    if associated_data:
        for block in _iter_full_blocks(associated_data, RATE_BYTES):
            state[0] ^= int.from_bytes(block, "big")
            permute_state(state, 6)
        last_ad = associated_data[(len(associated_data) // RATE_BYTES) * RATE_BYTES :]
        state[0] ^= int.from_bytes(_pad(last_ad), "big")
        permute_state(state, 6)
    state[4] ^= 1

    plaintext = bytearray()
    for block in _iter_full_blocks(ciphertext, RATE_BYTES):
        c_int = int.from_bytes(block, "big")
        p_int = state[0] ^ c_int
        plaintext.extend(p_int.to_bytes(RATE_BYTES, "big"))
        state[0] = c_int
        permute_state(state, 6)

    last_ciphertext = ciphertext[(len(ciphertext) // RATE_BYTES) * RATE_BYTES :]
    state_bytes = state[0].to_bytes(RATE_BYTES, "big")
    plaintext.extend(
        bytes(c ^ s for c, s in zip(last_ciphertext, state_bytes[: len(last_ciphertext)]))
    )

    state_bytes_mut = bytearray(state_bytes)
    for index, value in enumerate(last_ciphertext):
        state_bytes_mut[index] = value
    state_bytes_mut[len(last_ciphertext)] ^= 0x80
    state[0] = int.from_bytes(state_bytes_mut, "big")

    state[1] ^= k0
    state[2] ^= k1
    permute_state(state, 12)
    state[3] ^= k0
    state[4] ^= k1
    expected_tag = state[3].to_bytes(8, "big") + state[4].to_bytes(8, "big")
    if not hmac.compare_digest(expected_tag, authentication_tag):
        raise ValueError("ASCON tag verification failed.")
    return bytes(plaintext)


def encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
) -> tuple[bytes, bytes]:
    """Encrypt using ASCON-128 and return detached ciphertext + tag."""
    return _encrypt_detached(key, nonce, plaintext, associated_data)


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes,
    authentication_tag: bytes | None = None,
) -> bytes:
    """Decrypt using ASCON-128.

    Prompt-compatible four-argument usage is supported by passing
    `ciphertext = raw_ciphertext || tag` and leaving `authentication_tag=None`.
    """
    if authentication_tag is None:
        if len(ciphertext) < TAG_BYTES:
            raise ValueError("Ciphertext is too short to contain an authentication tag.")
        ciphertext, authentication_tag = ciphertext[:-TAG_BYTES], ciphertext[-TAG_BYTES:]
    return _decrypt_detached(key, nonce, ciphertext, associated_data, authentication_tag)


def sponge_hash(data: bytes, output_length: int = 32) -> bytes:
    """ASCON sponge absorb-permute-squeeze construction."""
    if output_length <= 0:
        raise ValueError("output_length must be positive.")

    state = [ASCON_HASH_IV, 0, 0, 0, 0]
    permute_state(state, 12)

    for block in _iter_full_blocks(data, RATE_BYTES):
        state[0] ^= int.from_bytes(block, "big")
        permute_state(state, 12)

    last_block = data[(len(data) // RATE_BYTES) * RATE_BYTES :]
    state[0] ^= int.from_bytes(_pad(last_block), "big")
    permute_state(state, 12)

    output = bytearray()
    while len(output) < output_length:
        output.extend(state[0].to_bytes(RATE_BYTES, "big"))
        permute_state(state, 12)
    return bytes(output[:output_length])
