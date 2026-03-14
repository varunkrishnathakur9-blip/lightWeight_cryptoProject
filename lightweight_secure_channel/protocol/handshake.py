"""Optimized ECC handshake with lightweight session resumption."""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from io import BufferedRWPair
from typing import Any

from lightweight_secure_channel.crypto.ascon_cipher import sponge_hash
from lightweight_secure_channel.crypto.ecc import (
    PrivateKey,
    PublicKey,
    compute_shared_secret,
    deserialize_public_key,
    generate_keypair,
    serialize_public_key,
)
from lightweight_secure_channel.crypto.kdf import KeyMaterial, derive_keys
from lightweight_secure_channel.protocol.session_manager import SessionManager

PROTOCOL_VERSION = "LSCP-2.0"


@dataclass(frozen=True)
class HandshakeResult:
    """Handshake outcome used to initialize secure channel state."""

    session_id: str
    connection_id: str
    key_material: KeyMaterial
    resumed: bool


class EphemeralKeyPool:
    """Precomputed ephemeral ECDH keys to reduce handshake latency."""

    def __init__(self, size: int = 8) -> None:
        self.size = size
        self._lock = threading.Lock()
        self._pool: deque[tuple[PrivateKey, PublicKey]] = deque()
        self._fill_pool()

    def _fill_pool(self) -> None:
        while len(self._pool) < self.size:
            self._pool.append(generate_keypair())

    def acquire(self) -> tuple[PrivateKey, PublicKey]:
        with self._lock:
            if not self._pool:
                self._fill_pool()
            keypair = self._pool.popleft()
            self._pool.append(generate_keypair())
            return keypair


_CLIENT_KEY_POOL = EphemeralKeyPool(size=8)
_SERVER_KEY_POOL = EphemeralKeyPool(size=8)


def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
    stream.flush()


def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
    line = stream.readline()
    if not line:
        raise EOFError("Connection closed during handshake.")
    return json.loads(line.decode("utf-8"))


def _transcript_hash(messages: list[dict[str, Any]]) -> bytes:
    encoded = b"||".join(
        json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
        for message in messages
    )
    return sponge_hash(encoded, output_length=32)


def _finished_tag(auth_key: bytes, transcript_digest: bytes, role: bytes) -> str:
    return sponge_hash(auth_key + transcript_digest + role, output_length=16).hex()


def perform_client_handshake(
    stream: BufferedRWPair,
    session_manager: SessionManager,
    resume_connection_id: str | None = None,
    context_info: bytes = b"lscp-iot",
) -> HandshakeResult:
    """Perform client-side handshake with optional session resumption."""
    private_key, public_key = _CLIENT_KEY_POOL.acquire()
    client_nonce = time.time_ns().to_bytes(16, "big", signed=False)
    client_hello = {
        "type": "ClientHello",
        "protocol_version": PROTOCOL_VERSION,
        "client_public_key": serialize_public_key(public_key).hex(),
        "client_nonce": client_nonce.hex(),
        "resume_connection_id": resume_connection_id,
    }
    _send_json(stream, client_hello)

    server_message = _recv_json(stream)
    transcript = [client_hello, server_message]

    if server_message.get("type") == "ResumeAccept":
        connection_id = str(server_message["connection_id"])
        session_id = str(server_message["session_id"])
        local_record = session_manager.resume_session(connection_id)
        if local_record is None:
            raise ValueError("Server resumed session not found in local client cache.")

        server_nonce = bytes.fromhex(server_message["server_nonce"])
        refresh_context = context_info + client_nonce + server_nonce + b"resume"
        key_material = derive_keys(shared_secret=local_record.session_key, context_info=refresh_context)

        client_finished = {
            "type": "ClientFinished",
            "verify": _finished_tag(
                key_material.auth_key,
                _transcript_hash(transcript),
                role=b"client",
            ),
        }
        _send_json(stream, client_finished)
        transcript.append(client_finished)

        server_finished = _recv_json(stream)
        if server_finished.get("type") != "ServerFinished":
            raise ValueError("Expected ServerFinished during resumed handshake.")
        expected = _finished_tag(key_material.auth_key, _transcript_hash(transcript), role=b"server")
        if server_finished.get("verify") != expected:
            raise ValueError("Server finished verification failed for resumed session.")

        session_manager.store_session(
            key_material=key_material,
            session_id=session_id,
            connection_id=connection_id,
            nonce_counter=local_record.nonce_counter,
        )
        return HandshakeResult(
            session_id=session_id,
            connection_id=connection_id,
            key_material=key_material,
            resumed=True,
        )

    if server_message.get("type") != "ServerHello":
        raise ValueError("Expected ServerHello.")

    server_public_key = deserialize_public_key(bytes.fromhex(server_message["server_public_key"]))
    server_nonce = bytes.fromhex(server_message["server_nonce"])
    session_id = str(server_message["session_id"])
    connection_id = str(server_message["connection_id"])

    shared_secret = compute_shared_secret(private_key, server_public_key)
    derive_context = context_info + client_nonce + server_nonce + session_id.encode("utf-8")
    key_material = derive_keys(shared_secret=shared_secret, context_info=derive_context)

    client_finished = {
        "type": "ClientFinished",
        "verify": _finished_tag(
            key_material.auth_key,
            _transcript_hash(transcript),
            role=b"client",
        ),
    }
    _send_json(stream, client_finished)
    transcript.append(client_finished)

    server_finished = _recv_json(stream)
    if server_finished.get("type") != "ServerFinished":
        raise ValueError("Expected ServerFinished.")
    expected_server_verify = _finished_tag(
        key_material.auth_key,
        _transcript_hash(transcript),
        role=b"server",
    )
    if server_finished.get("verify") != expected_server_verify:
        raise ValueError("Server finished verification failed.")

    session_manager.store_session(
        key_material=key_material,
        session_id=session_id,
        connection_id=connection_id,
        nonce_counter=0,
    )
    return HandshakeResult(
        session_id=session_id,
        connection_id=connection_id,
        key_material=key_material,
        resumed=False,
    )


def perform_server_handshake(
    stream: BufferedRWPair,
    session_manager: SessionManager,
    context_info: bytes = b"lscp-iot",
) -> HandshakeResult:
    """Perform server-side handshake and return negotiated session state."""
    client_hello = _recv_json(stream)
    if client_hello.get("type") != "ClientHello":
        raise ValueError("Expected ClientHello.")
    if client_hello.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError("Unsupported protocol version.")

    transcript: list[dict[str, Any]] = [client_hello]
    client_nonce = bytes.fromhex(client_hello["client_nonce"])

    resume_connection_id = client_hello.get("resume_connection_id")
    if isinstance(resume_connection_id, str):
        resumed = session_manager.resume_session(resume_connection_id)
        if resumed is not None:
            server_nonce = time.time_ns().to_bytes(16, "big", signed=False)
            refresh_context = context_info + client_nonce + server_nonce + b"resume"
            key_material = derive_keys(shared_secret=resumed.session_key, context_info=refresh_context)

            resume_accept = {
                "type": "ResumeAccept",
                "session_id": resumed.session_id,
                "connection_id": resumed.connection_id,
                "server_nonce": server_nonce.hex(),
            }
            _send_json(stream, resume_accept)
            transcript.append(resume_accept)

            client_finished = _recv_json(stream)
            if client_finished.get("type") != "ClientFinished":
                raise ValueError("Expected ClientFinished for resumed handshake.")
            expected = _finished_tag(key_material.auth_key, _transcript_hash(transcript), role=b"client")
            if client_finished.get("verify") != expected:
                raise ValueError("Client finished verification failed for resumed handshake.")
            transcript.append(client_finished)

            server_finished = {
                "type": "ServerFinished",
                "verify": _finished_tag(
                    key_material.auth_key,
                    _transcript_hash(transcript),
                    role=b"server",
                ),
            }
            _send_json(stream, server_finished)

            session_manager.store_session(
                key_material=key_material,
                session_id=resumed.session_id,
                connection_id=resumed.connection_id,
                nonce_counter=resumed.nonce_counter,
            )
            return HandshakeResult(
                session_id=resumed.session_id,
                connection_id=resumed.connection_id,
                key_material=key_material,
                resumed=True,
            )

    client_public_key = deserialize_public_key(bytes.fromhex(client_hello["client_public_key"]))
    server_private_key, server_public_key = _SERVER_KEY_POOL.acquire()

    session_id = secrets.token_hex(8)
    connection_id = secrets.token_hex(8)
    server_nonce = time.time_ns().to_bytes(16, "big", signed=False)
    shared_secret = compute_shared_secret(server_private_key, client_public_key)
    derive_context = context_info + client_nonce + server_nonce + session_id.encode("utf-8")
    key_material = derive_keys(shared_secret=shared_secret, context_info=derive_context)

    session_manager.store_session(
        key_material=key_material,
        session_id=session_id,
        connection_id=connection_id,
        nonce_counter=0,
    )

    server_hello = {
        "type": "ServerHello",
        "protocol_version": PROTOCOL_VERSION,
        "session_id": session_id,
        "connection_id": connection_id,
        "server_public_key": serialize_public_key(server_public_key).hex(),
        "server_nonce": server_nonce.hex(),
    }
    _send_json(stream, server_hello)
    transcript.append(server_hello)

    client_finished = _recv_json(stream)
    if client_finished.get("type") != "ClientFinished":
        raise ValueError("Expected ClientFinished.")
    expected_client_verify = _finished_tag(
        key_material.auth_key,
        _transcript_hash(transcript),
        role=b"client",
    )
    if client_finished.get("verify") != expected_client_verify:
        raise ValueError("Client finished verification failed.")
    transcript.append(client_finished)

    server_finished = {
        "type": "ServerFinished",
        "verify": _finished_tag(
            key_material.auth_key,
            _transcript_hash(transcript),
            role=b"server",
        ),
    }
    _send_json(stream, server_finished)

    return HandshakeResult(
        session_id=session_id,
        connection_id=connection_id,
        key_material=key_material,
        resumed=False,
    )
