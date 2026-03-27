"""
Peer abstraction for the P2P layer.

A :class:`Peer` is a remote nexus node identified by:

* ``peer_id``   — SHA-256 of the peer's public key (a stable identifier)
* ``host``      — IP address or hostname
* ``port``      — TCP port
* ``public_key_hex`` — hex-encoded Ed25519 public key (optional until
                       the handshake completes)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Peer:
    """A remote nexus node."""

    peer_id: str
    host: str
    port: int
    public_key_hex: Optional[str] = None
    last_seen: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def address(self) -> str:
        """Human-readable ``host:port`` address."""
        return f"{self.host}:{self.port}"

    def is_reachable(self, timeout_seconds: float = 300.0) -> bool:
        """Return True if the peer was seen within *timeout_seconds*."""
        return (time.time() - self.last_seen) < timeout_seconds

    def touch(self) -> None:
        """Update the last-seen timestamp to now."""
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        return {
            "peer_id": self.peer_id,
            "host": self.host,
            "port": self.port,
            "public_key_hex": self.public_key_hex,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Peer":
        return cls(
            peer_id=data["peer_id"],
            host=data["host"],
            port=data["port"],
            public_key_hex=data.get("public_key_hex"),
            last_seen=data.get("last_seen", time.time()),
        )

    def __str__(self) -> str:
        return f"Peer({self.peer_id[:8]}…@{self.address})"
