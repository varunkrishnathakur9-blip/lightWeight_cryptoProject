"""Session cache and resumption state management."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass

from lightweight_secure_channel.crypto.kdf import KeyMaterial


@dataclass
class SessionRecord:
    """Stored session information used for data transfer and resumption."""

    session_id: str
    connection_id: str
    session_key: bytes
    auth_key: bytes
    nonce_seed: bytes
    timestamp: float
    nonce_counter: int


class SessionManager:
    """In-memory store for active and resumable sessions."""

    def __init__(self, session_timeout: int = 300) -> None:
        self.session_timeout = session_timeout
        self._sessions_by_sid: dict[str, SessionRecord] = {}
        self._sessions_by_cid: dict[str, SessionRecord] = {}

    def _is_expired(self, timestamp: float) -> bool:
        return (time.time() - timestamp) > self.session_timeout

    def store_session(
        self,
        key_material: KeyMaterial,
        session_id: str | None = None,
        connection_id: str | None = None,
        nonce_counter: int = 0,
    ) -> SessionRecord:
        """Create and store a session record."""
        sid = session_id or secrets.token_hex(8)
        cid = connection_id or secrets.token_hex(8)

        record = SessionRecord(
            session_id=sid,
            connection_id=cid,
            session_key=key_material.session_key,
            auth_key=key_material.auth_key,
            nonce_seed=key_material.nonce_seed,
            timestamp=time.time(),
            nonce_counter=nonce_counter,
        )
        self._sessions_by_sid[sid] = record
        self._sessions_by_cid[cid] = record
        return record

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Get session by session ID if still valid."""
        record = self._sessions_by_sid.get(session_id)
        if record is None:
            return None
        if self._is_expired(record.timestamp):
            self.invalidate_session(record.session_id)
            return None
        return record

    def resume_session(self, connection_id: str) -> SessionRecord | None:
        """Resume by DTLS-CID-inspired connection identifier."""
        record = self._sessions_by_cid.get(connection_id)
        if record is None:
            return None
        if self._is_expired(record.timestamp):
            self.invalidate_session(record.session_id)
            return None

        record.timestamp = time.time()
        return record

    def advance_nonce_counter(self, session_id: str, new_counter: int) -> None:
        """Persist nonce counter to preserve uniqueness across reconnects."""
        record = self._sessions_by_sid.get(session_id)
        if record is None:
            return
        if new_counter > record.nonce_counter:
            record.nonce_counter = new_counter
            record.timestamp = time.time()

    def invalidate_session(self, session_id: str) -> None:
        """Remove session from cache."""
        record = self._sessions_by_sid.pop(session_id, None)
        if record is not None:
            self._sessions_by_cid.pop(record.connection_id, None)

    def cleanup_expired_sessions(self) -> None:
        """Remove all expired sessions."""
        expired = [
            sid
            for sid, record in self._sessions_by_sid.items()
            if self._is_expired(record.timestamp)
        ]
        for sid in expired:
            self.invalidate_session(sid)
