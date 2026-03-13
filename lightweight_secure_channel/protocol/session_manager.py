"""Session cache and resumption token management."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from lightweight_secure_channel.crypto.kdf import KeyMaterial


@dataclass
class SessionEntry:
    """Cached session data for resumption."""

    session_id: str
    key_material: KeyMaterial
    timestamp: float
    nonce_counter: int


class SessionManager:
    """In-memory session store with expiration and token validation."""

    def __init__(self, session_timeout: int = 300) -> None:
        self.session_timeout = session_timeout
        self.session_table: dict[str, SessionEntry] = {}

    @staticmethod
    def derived_key_hash(key_material: KeyMaterial) -> str:
        digest = hashlib.sha256(
            key_material.session_key + key_material.auth_key + key_material.nonce_seed
        ).hexdigest()
        return digest

    def _is_expired(self, timestamp: float) -> bool:
        return (time.time() - timestamp) > self.session_timeout

    def export_token(self, entry: SessionEntry) -> dict[str, Any]:
        return {
            "session_id": entry.session_id,
            "derived_key_hash": self.derived_key_hash(entry.key_material),
            "timestamp": entry.timestamp,
            "nonce_seed": entry.key_material.nonce_seed.hex(),
        }

    def store_session(
        self,
        session_id: str,
        key_material: KeyMaterial,
        token: dict[str, Any] | None = None,
        nonce_counter: int = 0,
    ) -> dict[str, Any]:
        """Store session and return a resumption token."""
        timestamp = float(token["timestamp"]) if token and "timestamp" in token else time.time()
        entry = SessionEntry(
            session_id=session_id,
            key_material=key_material,
            timestamp=timestamp,
            nonce_counter=nonce_counter,
        )
        self.session_table[session_id] = entry

        if token is not None:
            return {
                "session_id": token["session_id"],
                "derived_key_hash": token["derived_key_hash"],
                "timestamp": timestamp,
                "nonce_seed": token["nonce_seed"],
            }
        return self.export_token(entry)

    def resume_session(self, token: dict[str, Any]) -> SessionEntry | None:
        """Validate token and return active session if available."""
        self.cleanup_expired_sessions()
        required_fields = {"session_id", "derived_key_hash", "timestamp", "nonce_seed"}
        if not required_fields.issubset(token.keys()):
            return None

        session_id = str(token["session_id"])
        entry = self.session_table.get(session_id)
        if entry is None:
            return None

        token_timestamp = float(token["timestamp"])
        if self._is_expired(token_timestamp) or self._is_expired(entry.timestamp):
            self.invalidate_session(session_id)
            return None

        if token["derived_key_hash"] != self.derived_key_hash(entry.key_material):
            return None
        if token["nonce_seed"] != entry.key_material.nonce_seed.hex():
            return None

        # Sliding expiration window on successful resume.
        entry.timestamp = time.time()
        return entry

    def invalidate_session(self, session_id: str) -> None:
        """Invalidate a session by its identifier."""
        self.session_table.pop(session_id, None)

    def cleanup_expired_sessions(self) -> None:
        """Remove expired sessions from cache."""
        expired_ids = [
            session_id
            for session_id, entry in self.session_table.items()
            if self._is_expired(entry.timestamp)
        ]
        for session_id in expired_ids:
            self.invalidate_session(session_id)

