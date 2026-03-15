"""ASCON-128 AEAD with mandatory native backend.

A native ASCON module (``pyascon`` or ``ascon``) must be installed.
Pure-Python fallback is disabled intentionally for strict benchmarking.
"""

from __future__ import annotations

import hmac
import importlib
from typing import Any, Iterable

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


_NATIVE_MODULE = None
_NATIVE_MODULE_NAME = ""


def _load_native_backend() -> tuple[Any | None, str]:
    for module_name in ("pyascon", "ascon"):
        try:
            return importlib.import_module(module_name), module_name
        except Exception:
            continue
    return None, ""


_NATIVE_MODULE, _NATIVE_MODULE_NAME = _load_native_backend()
if _NATIVE_MODULE is None:
    raise RuntimeError(
        "Native ASCON backend is mandatory but not found. Install `pyascon` or `ascon`."
    )



def active_backend() -> str:
    """Return active backend descriptor."""
    return f"native:{_NATIVE_MODULE_NAME}"


def _to_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return value.encode("utf-8")
    if isinstance(value, list):
        return bytes(value)
    raise TypeError(f"Unsupported bytes conversion for type: {type(value)}")


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
    import os

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


def _native_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
) -> tuple[bytes, bytes]:
    module = _NATIVE_MODULE
    if module is None:
        raise RuntimeError("No native ASCON backend is loaded.")

    candidate_calls: list[Any] = []

    if hasattr(module, "encrypt"):
        fn = getattr(module, "encrypt")
        candidate_calls.extend(
            [
                lambda: fn(key, nonce, associated_data, plaintext),
                lambda: fn(key, nonce, plaintext, associated_data),
                lambda: fn(key=key, nonce=nonce, associateddata=associated_data, plaintext=plaintext),
                lambda: fn(key=key, nonce=nonce, associated_data=associated_data, plaintext=plaintext),
                lambda: fn(key=key, nonce=nonce, ad=associated_data, plaintext=plaintext),
            ]
        )

    if hasattr(module, "ascon_encrypt"):
        fn = getattr(module, "ascon_encrypt")
        candidate_calls.extend(
            [
                lambda: fn(key, nonce, associated_data, plaintext),
                lambda: fn(key=key, nonce=nonce, associateddata=associated_data, plaintext=plaintext),
                lambda: fn(key=key, nonce=nonce, associated_data=associated_data, plaintext=plaintext),
            ]
        )

    last_error: Exception | None = None
    for call in candidate_calls:
        try:
            result = call()
            if isinstance(result, tuple) and len(result) == 2:
                return _to_bytes(result[0]), _to_bytes(result[1])
            combined = _to_bytes(result)
            if len(combined) < TAG_BYTES:
                raise ValueError("Native ASCON encrypt output too short.")
            return combined[:-TAG_BYTES], combined[-TAG_BYTES:]
        except Exception as error:
            last_error = error
            continue

    raise RuntimeError(f"Native ASCON encrypt call patterns failed: {last_error}")


def _native_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes,
    authentication_tag: bytes,
) -> bytes:
    module = _NATIVE_MODULE
    if module is None:
        raise RuntimeError("No native ASCON backend is loaded.")

    combined = ciphertext + authentication_tag

    def _normalize_decrypt_result(result: Any) -> bytes:
        if result is None:
            raise ValueError("ASCON tag verification failed.")
        return _to_bytes(result)

    candidate_calls: list[Any] = []

    if hasattr(module, "decrypt"):
        fn = getattr(module, "decrypt")
        candidate_calls.extend(
            [
                lambda: fn(key, nonce, associated_data, combined),
                lambda: fn(key, nonce, combined, associated_data),
                lambda: fn(key=key, nonce=nonce, associateddata=associated_data, ciphertext=combined),
                lambda: fn(key=key, nonce=nonce, associated_data=associated_data, ciphertext=combined),
                lambda: fn(key=key, nonce=nonce, ad=associated_data, ciphertext=combined),
            ]
        )

    if hasattr(module, "ascon_decrypt"):
        fn = getattr(module, "ascon_decrypt")
        candidate_calls.extend(
            [
                lambda: fn(key, nonce, associated_data, combined),
                lambda: fn(key=key, nonce=nonce, associateddata=associated_data, ciphertext=combined),
                lambda: fn(key=key, nonce=nonce, associated_data=associated_data, ciphertext=combined),
            ]
        )

    last_error: Exception | None = None
    for call in candidate_calls:
        try:
            result = call()
            return _normalize_decrypt_result(result)
        except Exception as error:
            message = str(error).lower()
            if any(token in message for token in ("auth", "tag", "mac", "verify")):
                raise ValueError("ASCON tag verification failed.") from error
            last_error = error
            continue

    raise RuntimeError(f"Native ASCON decrypt call patterns failed: {last_error}")


def _native_sponge(data: bytes, output_length: int) -> bytes:
    """Compute sponge/hash output using native ASCON hash or XOF APIs."""
    if output_length <= 0:
        raise ValueError("output_length must be positive.")

    module = _NATIVE_MODULE
    if module is None:
        raise RuntimeError("No native ASCON backend is loaded.")

    candidate_calls: list[Any] = []

    if hasattr(module, "xof"):
        fn = getattr(module, "xof")
        candidate_calls.extend(
            [
                lambda: fn(data, output_length),
                lambda: fn(data, outlen=output_length),
                lambda: fn(data, output_length=output_length),
                lambda: fn(message=data, outlen=output_length),
                lambda: fn(message=data, output_length=output_length),
            ]
        )

    if hasattr(module, "ascon_xof"):
        fn = getattr(module, "ascon_xof")
        candidate_calls.extend(
            [
                lambda: fn(data, output_length),
                lambda: fn(data, hashlength=output_length),
                lambda: fn(data, variant="Ascon-Xof", hashlength=output_length),
                lambda: fn(data, variant="Ascon-XOF", hashlength=output_length),
                lambda: fn(message=data, hashlength=output_length),
                lambda: fn(message=data, output_length=output_length),
            ]
        )

    if hasattr(module, "hash"):
        fn = getattr(module, "hash")
        candidate_calls.extend(
            [
                lambda: fn(data, output_length),
                lambda: fn(data, hashlength=output_length),
                lambda: fn(data, variant="Ascon-Xof", hashlength=output_length),
                lambda: fn(data, variant="Ascon-XOF", hashlength=output_length),
                lambda: fn(data, variant="Ascon-Hash", hashlength=output_length),
                lambda: fn(message=data, hashlength=output_length),
                lambda: fn(message=data, output_length=output_length),
            ]
        )

    if hasattr(module, "ascon_hash"):
        fn = getattr(module, "ascon_hash")
        candidate_calls.extend(
            [
                lambda: fn(data, hashlength=output_length),
                lambda: fn(data, output_length),
                lambda: fn(data, variant="Ascon-Xof", hashlength=output_length),
                lambda: fn(data, variant="Ascon-XOF", hashlength=output_length),
                lambda: fn(data, variant="Ascon-Hash", hashlength=output_length),
                lambda: fn(message=data, hashlength=output_length),
                lambda: fn(message=data, output_length=output_length),
            ]
        )

    last_error: Exception | None = None
    for call in candidate_calls:
        try:
            result = _to_bytes(call())
            if len(result) >= output_length:
                return result[:output_length]
            if len(result) > 0:
                # Treat short output as mismatch and keep probing for an XOF-capable call shape.
                raise ValueError("Native ASCON hash output shorter than requested length.")
        except Exception as error:
            last_error = error
            continue

    raise RuntimeError(f"Native ASCON sponge/hash call patterns failed: {last_error}")


def encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
) -> tuple[bytes, bytes]:
    """Encrypt using ASCON-128 and return detached ciphertext + tag.

    Native backend is mandatory.
    """
    return _native_encrypt(key, nonce, plaintext, associated_data)


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    associated_data: bytes,
    authentication_tag: bytes | None = None,
) -> bytes:
    """Decrypt using ASCON-128.

    Prompt-compatible four-argument usage is supported by passing
    ``ciphertext = raw_ciphertext || tag`` and leaving ``authentication_tag=None``.
    Native backend is mandatory.
    """
    if authentication_tag is None:
        if len(ciphertext) < TAG_BYTES:
            raise ValueError("Ciphertext is too short to contain an authentication tag.")
        ciphertext, authentication_tag = ciphertext[:-TAG_BYTES], ciphertext[-TAG_BYTES:]

    return _native_decrypt(key, nonce, ciphertext, associated_data, authentication_tag)


def sponge_hash(data: bytes, output_length: int = 32) -> bytes:
    """Compute sponge/hash output using the mandatory native ASCON backend."""
    return _native_sponge(data, output_length)
