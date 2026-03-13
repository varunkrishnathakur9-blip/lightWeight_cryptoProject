"""TLS-like handshake with ECC key exchange and optional session resumption."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from io import BufferedRWPair
from typing import Any

from lightweight_secure_channel.crypto.ecc import (
    compute_shared_secret,
    deserialize_public_key,
    generate_keypair,
    serialize_public_key,
)
from lightweight_secure_channel.crypto.kdf import KeyMaterial, derive_session_keys
from lightweight_secure_channel.protocol.session_manager import SessionManager

PROTOCOL_VERSION = "LSCP-1.0"


@dataclass(frozen=True)
class HandshakeResult:
    """Outcome of a client/server handshake operation."""

    session_id: str
    key_material: KeyMaterial
    session_token: dict[str, Any]
    resumed: bool


def _send_json(stream: BufferedRWPair, payload: dict[str, Any]) -> None:
    stream.write(json.dumps(payload).encode("utf-8") + b"\n")
    stream.flush()


def _recv_json(stream: BufferedRWPair) -> dict[str, Any]:
    line = stream.readline()
    if not line:
        raise EOFError("Connection closed while waiting for handshake data.")
    return json.loads(line.decode("utf-8"))


def perform_client_handshake(
    stream: BufferedRWPair,
    session_manager: SessionManager,
    resume_token: dict[str, Any] | None = None,
    kdf_mode: str = "ascon",
) -> HandshakeResult:
    """Run client-side handshake sequence."""
    private_key, public_key = generate_keypair()
    client_hello = {
        "type": "ClientHello",
        "protocol_version": PROTOCOL_VERSION,
        "kdf_mode": kdf_mode,
        "client_pub": serialize_public_key(public_key).hex(),
        "resume_token": resume_token,
    }
    _send_json(stream, client_hello)

    server_hello = _recv_json(stream)
    if server_hello.get("type") != "ServerHello":
        raise ValueError("Expected ServerHello.")

    if server_hello.get("resumed", False):
        token = server_hello["token"]
        resumed_entry = session_manager.resume_session(token)
        if resumed_entry is None:
            raise ValueError("Server attempted to resume an invalid session.")
        _send_json(
            stream,
            {
                "type": "HandshakeComplete",
                "session_id": resumed_entry.session_id,
                "resumed": True,
            },
        )
        return HandshakeResult(
            session_id=resumed_entry.session_id,
            key_material=resumed_entry.key_material,
            session_token=token,
            resumed=True,
        )

    key_exchange = _recv_json(stream)
    if key_exchange.get("type") != "KeyExchange":
        raise ValueError("Expected KeyExchange.")
    session_id = str(key_exchange["session_id"])

    server_public_key = deserialize_public_key(bytes.fromhex(key_exchange["server_pub"]))
    shared_secret = compute_shared_secret(private_key, server_public_key)
    key_material = derive_session_keys(shared_secret, mode=kdf_mode)

    _send_json(
        stream,
        {
            "type": "SessionKeyDerivation",
            "session_id": session_id,
            "derived_key_hash": session_manager.derived_key_hash(key_material),
        },
    )

    complete = _recv_json(stream)
    if complete.get("type") != "HandshakeComplete":
        raise ValueError("Expected HandshakeComplete.")
    token = complete["token"]
    if token["session_id"] != session_id:
        raise ValueError("Session ID mismatch in server token.")

    session_manager.store_session(session_id=session_id, key_material=key_material, token=token)
    return HandshakeResult(
        session_id=session_id,
        key_material=key_material,
        session_token=token,
        resumed=False,
    )


def perform_server_handshake(
    stream: BufferedRWPair,
    session_manager: SessionManager,
    kdf_mode: str = "ascon",
) -> HandshakeResult:
    """Run server-side handshake sequence."""
    client_hello = _recv_json(stream)
    if client_hello.get("type") != "ClientHello":
        raise ValueError("Expected ClientHello.")
    if client_hello.get("protocol_version") != PROTOCOL_VERSION:
        raise ValueError("Protocol version mismatch.")

    offered_kdf_mode = str(client_hello.get("kdf_mode", kdf_mode))
    resume_token = client_hello.get("resume_token")
    if isinstance(resume_token, dict):
        resumed_entry = session_manager.resume_session(resume_token)
        if resumed_entry is not None:
            token = session_manager.export_token(resumed_entry)
            _send_json(
                stream,
                {
                    "type": "ServerHello",
                    "protocol_version": PROTOCOL_VERSION,
                    "resumed": True,
                    "session_id": resumed_entry.session_id,
                    "token": token,
                },
            )
            complete = _recv_json(stream)
            if complete.get("type") != "HandshakeComplete":
                raise ValueError("Expected HandshakeComplete for resumed session.")
            return HandshakeResult(
                session_id=resumed_entry.session_id,
                key_material=resumed_entry.key_material,
                session_token=token,
                resumed=True,
            )

    client_public_key = deserialize_public_key(bytes.fromhex(client_hello["client_pub"]))
    server_private_key, server_public_key = generate_keypair()
    shared_secret = compute_shared_secret(server_private_key, client_public_key)
    key_material = derive_session_keys(shared_secret, mode=offered_kdf_mode)

    session_id = secrets.token_hex(8)
    _send_json(
        stream,
        {
            "type": "ServerHello",
            "protocol_version": PROTOCOL_VERSION,
            "resumed": False,
            "kdf_mode": offered_kdf_mode,
        },
    )
    _send_json(
        stream,
        {
            "type": "KeyExchange",
            "session_id": session_id,
            "server_pub": serialize_public_key(server_public_key).hex(),
        },
    )

    derivation_msg = _recv_json(stream)
    if derivation_msg.get("type") != "SessionKeyDerivation":
        raise ValueError("Expected SessionKeyDerivation.")
    if derivation_msg.get("session_id") != session_id:
        raise ValueError("Session ID mismatch in derivation message.")
    if derivation_msg.get("derived_key_hash") != session_manager.derived_key_hash(key_material):
        raise ValueError("Client key derivation hash mismatch.")

    token = session_manager.store_session(session_id=session_id, key_material=key_material)
    _send_json(
        stream,
        {
            "type": "HandshakeComplete",
            "session_id": session_id,
            "token": token,
        },
    )
    return HandshakeResult(
        session_id=session_id,
        key_material=key_material,
        session_token=token,
        resumed=False,
    )

