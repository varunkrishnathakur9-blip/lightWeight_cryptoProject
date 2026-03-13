"""ECC helpers for ECDH key exchange on secp256r1."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PrivateKey = ec.EllipticCurvePrivateKey
PublicKey = ec.EllipticCurvePublicKey


def generate_keypair() -> tuple[PrivateKey, PublicKey]:
    """Generate a secp256r1 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def serialize_public_key(public_key: PublicKey) -> bytes:
    """Serialize a public key to uncompressed X9.62 point format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def deserialize_public_key(data: bytes) -> PublicKey:
    """Deserialize an uncompressed X9.62 public key."""
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def compute_shared_secret(private_key: PrivateKey, peer_public_key: PublicKey) -> bytes:
    """Compute an ECDH shared secret."""
    return private_key.exchange(ec.ECDH(), peer_public_key)

