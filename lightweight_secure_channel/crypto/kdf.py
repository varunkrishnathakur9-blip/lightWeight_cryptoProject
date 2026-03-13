"""Key-derivation functions for session key material."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from lightweight_secure_channel.crypto.ascon_cipher import ascon_hash


@dataclass(frozen=True)
class KeyMaterial:
    """Derived session key material."""

    session_key: bytes
    auth_key: bytes
    nonce_seed: bytes


def hkdf_sha256(shared_secret: bytes) -> KeyMaterial:
    """Baseline key derivation using HKDF-SHA256."""
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=None,
        info=b"LSCP-HKDF-SHA256",
    ).derive(shared_secret)
    return KeyMaterial(
        session_key=okm[:16],
        auth_key=okm[16:32],
        nonce_seed=okm[32:48],
    )


def ascon_kdf(shared_secret: bytes) -> KeyMaterial:
    """Lightweight ASCON sponge-based KDF."""
    xof_output = ascon_hash(b"LSCP-ASCON-KDF" + shared_secret, out_len=48)
    return KeyMaterial(
        session_key=xof_output[:16],
        auth_key=xof_output[16:32],
        nonce_seed=xof_output[32:48],
    )


def derive_session_keys(shared_secret: bytes, mode: str = "ascon") -> KeyMaterial:
    """Derive session keys with either HKDF-SHA256 or ASCON-based KDF."""
    normalized_mode = mode.lower()
    if normalized_mode == "hkdf":
        return hkdf_sha256(shared_secret)
    if normalized_mode == "ascon":
        return ascon_kdf(shared_secret)
    raise ValueError(f"Unsupported KDF mode: {mode}")

