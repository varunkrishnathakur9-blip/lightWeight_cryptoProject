"""Pure-Python ASCON utilities used by the secure channel prototype."""

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


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64


def _pad(block: bytes, rate: int = RATE_BYTES) -> bytes:
    if len(block) >= rate:
        raise ValueError("Padding requires a partial block.")
    return block + b"\x80" + b"\x00" * (rate - len(block) - 1)


def _ascon_permutation(state: list[int], rounds: int) -> None:
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
    """Generate a random ASCON nonce."""
    return os.urandom(NONCE_BYTES)


def ascon_encrypt(key: bytes, nonce: bytes, ad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using ASCON-128 AEAD.

    Args:
        key: 16-byte key.
        nonce: 16-byte nonce.
        ad: Associated data (authenticated only).
        plaintext: Plaintext payload.

    Returns:
        Tuple of (ciphertext, tag).
    """
    if len(key) != KEY_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte key.")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte nonce.")

    k0 = int.from_bytes(key[:8], "big")
    k1 = int.from_bytes(key[8:], "big")
    n0 = int.from_bytes(nonce[:8], "big")
    n1 = int.from_bytes(nonce[8:], "big")

    state = [ASCON_128_IV, k0, k1, n0, n1]
    _ascon_permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    if ad:
        for block in _iter_full_blocks(ad, RATE_BYTES):
            state[0] ^= int.from_bytes(block, "big")
            _ascon_permutation(state, 6)
        last_ad = ad[(len(ad) // RATE_BYTES) * RATE_BYTES :]
        state[0] ^= int.from_bytes(_pad(last_ad), "big")
        _ascon_permutation(state, 6)
    state[4] ^= 1

    ciphertext = bytearray()
    for block in _iter_full_blocks(plaintext, RATE_BYTES):
        state[0] ^= int.from_bytes(block, "big")
        ciphertext.extend(state[0].to_bytes(RATE_BYTES, "big"))
        _ascon_permutation(state, 6)

    last_plaintext = plaintext[(len(plaintext) // RATE_BYTES) * RATE_BYTES :]
    state[0] ^= int.from_bytes(_pad(last_plaintext), "big")
    ciphertext.extend(state[0].to_bytes(RATE_BYTES, "big")[: len(last_plaintext)])

    state[1] ^= k0
    state[2] ^= k1
    _ascon_permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    tag = state[3].to_bytes(8, "big") + state[4].to_bytes(8, "big")
    return bytes(ciphertext), tag


def ascon_decrypt(key: bytes, nonce: bytes, ad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypt ciphertext using ASCON-128 AEAD and verify authentication tag."""
    if len(key) != KEY_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte key.")
    if len(nonce) != NONCE_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte nonce.")
    if len(tag) != TAG_BYTES:
        raise ValueError("ASCON-128 requires a 16-byte tag.")

    k0 = int.from_bytes(key[:8], "big")
    k1 = int.from_bytes(key[8:], "big")
    n0 = int.from_bytes(nonce[:8], "big")
    n1 = int.from_bytes(nonce[8:], "big")

    state = [ASCON_128_IV, k0, k1, n0, n1]
    _ascon_permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1

    if ad:
        for block in _iter_full_blocks(ad, RATE_BYTES):
            state[0] ^= int.from_bytes(block, "big")
            _ascon_permutation(state, 6)
        last_ad = ad[(len(ad) // RATE_BYTES) * RATE_BYTES :]
        state[0] ^= int.from_bytes(_pad(last_ad), "big")
        _ascon_permutation(state, 6)
    state[4] ^= 1

    plaintext = bytearray()
    for block in _iter_full_blocks(ciphertext, RATE_BYTES):
        c_int = int.from_bytes(block, "big")
        p_int = state[0] ^ c_int
        plaintext.extend(p_int.to_bytes(RATE_BYTES, "big"))
        state[0] = c_int
        _ascon_permutation(state, 6)

    last_ciphertext = ciphertext[(len(ciphertext) // RATE_BYTES) * RATE_BYTES :]
    state_bytes = state[0].to_bytes(RATE_BYTES, "big")
    plaintext.extend(
        bytes(c ^ s for c, s in zip(last_ciphertext, state_bytes[: len(last_ciphertext)]))
    )

    state_bytes_mut = bytearray(state_bytes)
    for idx, value in enumerate(last_ciphertext):
        state_bytes_mut[idx] = value
    state_bytes_mut[len(last_ciphertext)] ^= 0x80
    state[0] = int.from_bytes(state_bytes_mut, "big")

    state[1] ^= k0
    state[2] ^= k1
    _ascon_permutation(state, 12)
    state[3] ^= k0
    state[4] ^= k1
    expected_tag = state[3].to_bytes(8, "big") + state[4].to_bytes(8, "big")

    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("ASCON authentication tag verification failed.")
    return bytes(plaintext)


def ascon_hash(data: bytes, out_len: int = 32) -> bytes:
    """ASCON sponge-style hash/XOF for lightweight KDF operations.

    This function uses an ASCON permutation-based sponge construction to provide
    deterministic pseudo-random output suitable for key derivation in this prototype.
    """
    if out_len <= 0:
        raise ValueError("out_len must be positive.")

    state = [ASCON_HASH_IV, 0, 0, 0, 0]
    _ascon_permutation(state, 12)

    for block in _iter_full_blocks(data, RATE_BYTES):
        state[0] ^= int.from_bytes(block, "big")
        _ascon_permutation(state, 12)

    last = data[(len(data) // RATE_BYTES) * RATE_BYTES :]
    state[0] ^= int.from_bytes(_pad(last), "big")
    _ascon_permutation(state, 12)

    out = bytearray()
    while len(out) < out_len:
        out.extend(state[0].to_bytes(8, "big"))
        _ascon_permutation(state, 12)
    return bytes(out[:out_len])

