"""Baseline AES-GCM secure channel used for comparative evaluation."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass
from io import BufferedRWPair
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from lightweight_secure_channel.crypto.ecc import (
    compute_shared_secret,
    deserialize_public_key,
    generate_keypair,
    serialize_public_key,
)

BASELINE_VERSION = "BASE-1.0"


@dataclass(frozen=True)
class BaselineKeyMaterial:
    """Derived baseline channel key material."""

    session_key: bytes
    auth_key: bytes
    nonce_seed: bytes


@dataclass(frozen=True)
class BaselineHandshakeResult:
    """Handshake output for baseline protocol."""

    session_id: str
    key_material: BaselineKeyMaterial


@dataclass(frozen=True)
class BaselinePacket:
    """Packet structure aligned with project packet schema."""

    protocol_version: str
    session_id: str
    sequence_number: int
    nonce: bytes
    ciphertext: bytes
    authentication_tag: bytes


def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
    stream.flush()


def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
    line = stream.readline()
    if not line:
        raise EOFError("Connection closed during baseline handshake.")
    return json.loads(line.decode("utf-8"))


def _hkdf_sha256(shared_secret: bytes, info: bytes) -> BaselineKeyMaterial:
    output = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return BaselineKeyMaterial(
        session_key=output[:16],
        auth_key=output[16:32],
        nonce_seed=output[32:48],
    )


def _transcript_hash(messages: list[dict[str, Any]]) -> bytes:
    encoded = b"||".join(
        json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
        for message in messages
    )
    return hashlib.sha256(encoded).digest()


def _finished_tag(auth_key: bytes, transcript_digest: bytes, role: bytes) -> str:
    return hmac.new(auth_key, transcript_digest + role, digestmod=hashlib.sha256).hexdigest()


def perform_baseline_client_handshake(
    stream: BufferedRWPair,
    context_info: bytes = b"baseline-iot",
) -> BaselineHandshakeResult:
    """Client side of baseline ECDH + HKDF + AES-GCM handshake."""
    private_key, public_key = generate_keypair()
    client_nonce = time.time_ns().to_bytes(16, "big", signed=False)

    client_hello = {
        "type": "ClientHello",
        "protocol_version": BASELINE_VERSION,
        "client_public_key": serialize_public_key(public_key).hex(),
        "client_nonce": client_nonce.hex(),
    }
    _send_json(stream, client_hello)

    server_hello = _recv_json(stream)
    if server_hello.get("type") != "ServerHello":
        raise ValueError("Expected ServerHello in baseline handshake.")

    transcript = [client_hello, server_hello]
    server_public_key = deserialize_public_key(bytes.fromhex(server_hello["server_public_key"]))
    server_nonce = bytes.fromhex(server_hello["server_nonce"])
    session_id = str(server_hello["session_id"])

    shared_secret = compute_shared_secret(private_key, server_public_key)
    info = context_info + client_nonce + server_nonce + session_id.encode("utf-8")
    key_material = _hkdf_sha256(shared_secret, info)

    client_finished = {
        "type": "ClientFinished",
        "verify": _finished_tag(key_material.auth_key, _transcript_hash(transcript), b"client"),
    }
    _send_json(stream, client_finished)
    transcript.append(client_finished)

    server_finished = _recv_json(stream)
    if server_finished.get("type") != "ServerFinished":
        raise ValueError("Expected ServerFinished in baseline handshake.")
    expected = _finished_tag(key_material.auth_key, _transcript_hash(transcript), b"server")
    if server_finished.get("verify") != expected:
        raise ValueError("Baseline server finished verification failed.")

    return BaselineHandshakeResult(session_id=session_id, key_material=key_material)


def perform_baseline_server_handshake(
    stream: BufferedRWPair,
    context_info: bytes = b"baseline-iot",
) -> BaselineHandshakeResult:
    """Server side of baseline ECDH + HKDF + AES-GCM handshake."""
    client_hello = _recv_json(stream)
    if client_hello.get("type") != "ClientHello":
        raise ValueError("Expected ClientHello in baseline handshake.")

    client_public_key = deserialize_public_key(bytes.fromhex(client_hello["client_public_key"]))
    client_nonce = bytes.fromhex(client_hello["client_nonce"])

    private_key, public_key = generate_keypair()
    session_id = secrets.token_hex(8)
    server_nonce = time.time_ns().to_bytes(16, "big", signed=False)

    shared_secret = compute_shared_secret(private_key, client_public_key)
    info = context_info + client_nonce + server_nonce + session_id.encode("utf-8")
    key_material = _hkdf_sha256(shared_secret, info)

    server_hello = {
        "type": "ServerHello",
        "protocol_version": BASELINE_VERSION,
        "session_id": session_id,
        "server_public_key": serialize_public_key(public_key).hex(),
        "server_nonce": server_nonce.hex(),
    }
    _send_json(stream, server_hello)

    transcript = [client_hello, server_hello]
    client_finished = _recv_json(stream)
    if client_finished.get("type") != "ClientFinished":
        raise ValueError("Expected ClientFinished in baseline handshake.")
    expected_client = _finished_tag(key_material.auth_key, _transcript_hash(transcript), b"client")
    if client_finished.get("verify") != expected_client:
        raise ValueError("Baseline client finished verification failed.")
    transcript.append(client_finished)

    server_finished = {
        "type": "ServerFinished",
        "verify": _finished_tag(key_material.auth_key, _transcript_hash(transcript), b"server"),
    }
    _send_json(stream, server_finished)

    return BaselineHandshakeResult(session_id=session_id, key_material=key_material)


def run_baseline_handshake_pair() -> tuple[float, BaselineHandshakeResult]:
    """Run one client/server baseline handshake over socketpair and return latency."""
    client_sock, server_sock = socket.socketpair()
    results: dict[str, BaselineHandshakeResult] = {}

    def _server_worker() -> None:
        with server_sock:
            stream = server_sock.makefile("rwb")
            try:
                results["server"] = perform_baseline_server_handshake(stream)
            finally:
                stream.close()

    thread = threading.Thread(target=_server_worker, daemon=True)
    thread.start()

    start = time.perf_counter()
    with client_sock:
        stream = client_sock.makefile("rwb")
        try:
            client_result = perform_baseline_client_handshake(stream)
        finally:
            stream.close()
    latency_ms = (time.perf_counter() - start) * 1000.0

    thread.join(timeout=5)
    if "server" not in results:
        raise RuntimeError("Baseline server handshake did not complete.")
    return latency_ms, client_result


class BaselineSecureChannel:
    """AES-GCM secure channel abstraction for baseline experiments."""

    def __init__(self, session_id: str, key_material: BaselineKeyMaterial) -> None:
        self.session_id = session_id
        self.key_material = key_material
        self._aead = AESGCM(key_material.session_key)
        self._send_seq = 0
        self._last_recv_seq = -1

    def _aad(self, sequence_number: int) -> bytes:
        return (
            BASELINE_VERSION.encode("utf-8")
            + b"|"
            + self.session_id.encode("utf-8")
            + b"|"
            + struct.pack(">Q", sequence_number)
        )

    def _nonce(self, sequence_number: int) -> bytes:
        digest = hashlib.sha256(self.key_material.nonce_seed + struct.pack(">Q", sequence_number)).digest()
        return digest[:12]

    def encrypt_packet(self, plaintext: bytes) -> BaselinePacket:
        sequence_number = self._send_seq
        nonce = self._nonce(sequence_number)
        aad = self._aad(sequence_number)
        combined = self._aead.encrypt(nonce, plaintext, aad)
        ciphertext, tag = combined[:-16], combined[-16:]
        self._send_seq += 1
        return BaselinePacket(
            protocol_version=BASELINE_VERSION,
            session_id=self.session_id,
            sequence_number=sequence_number,
            nonce=nonce,
            ciphertext=ciphertext,
            authentication_tag=tag,
        )

    def decrypt_packet(self, packet: BaselinePacket) -> bytes:
        if packet.sequence_number <= self._last_recv_seq:
            raise ValueError("Replay detected in baseline channel.")
        aad = self._aad(packet.sequence_number)
        plaintext = self._aead.decrypt(
            packet.nonce,
            packet.ciphertext + packet.authentication_tag,
            aad,
        )
        self._last_recv_seq = packet.sequence_number
        return plaintext
