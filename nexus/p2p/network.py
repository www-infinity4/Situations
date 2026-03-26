"""
P2P network manager.

The :class:`Network` class:

* Maintains a registry of known :class:`~nexus.p2p.peer.Peer` objects.
* Provides message routing: ``send`` a typed message to a peer;
  ``broadcast`` a message to all reachable peers.
* Fires registered handlers when a message of a given type arrives.
* Integrates with the :class:`~nexus.ai.threat_detector.ThreatDetector`
  so that suspicious messages are quarantined before being dispatched.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Callable, Dict, List, Optional

from .peer import Peer

logger = logging.getLogger(__name__)

# Type alias for message handler callbacks
MessageHandler = Callable[[Peer, dict], None]


class Network:
    """Manages peers and message routing for a nexus node."""

    def __init__(
        self,
        local_peer_id: str,
        threat_detector=None,
    ) -> None:
        self.local_peer_id = local_peer_id
        self._threat_detector = threat_detector
        self._peers: Dict[str, Peer] = {}
        self._handlers: Dict[str, List[MessageHandler]] = {}

    # ------------------------------------------------------------------
    # Peer management
    # ------------------------------------------------------------------

    def add_peer(self, peer: Peer) -> None:
        """Register *peer* with the network."""
        self._peers[peer.peer_id] = peer
        logger.info("Added %s", peer)

    def remove_peer(self, peer_id: str) -> None:
        """Remove the peer identified by *peer_id*."""
        self._peers.pop(peer_id, None)

    def get_peer(self, peer_id: str) -> Optional[Peer]:
        """Return the :class:`Peer` for *peer_id*, or ``None``."""
        return self._peers.get(peer_id)

    def reachable_peers(self) -> List[Peer]:
        """Return all peers that have been seen recently."""
        return [p for p in self._peers.values() if p.is_reachable()]

    @property
    def peer_count(self) -> int:
        return len(self._peers)

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def on(self, message_type: str, handler: MessageHandler) -> None:
        """Register *handler* to be called when a ``message_type`` message arrives."""
        self._handlers.setdefault(message_type, []).append(handler)

    # ------------------------------------------------------------------
    # Message dispatch
    # ------------------------------------------------------------------

    def receive(self, sender_peer_id: str, raw_message: bytes) -> None:
        """Process an incoming *raw_message* from *sender_peer_id*.

        1. Locate the sender in the peer table (or create a transient entry).
        2. Run the message through the threat detector.
        3. Dispatch to registered handlers.
        """
        peer = self._peers.get(sender_peer_id)
        if peer is None:
            logger.warning(
                "Message from unknown peer %s — creating transient entry",
                sender_peer_id[:8],
            )
            peer = Peer(peer_id=sender_peer_id, host="unknown", port=0)
            self._peers[sender_peer_id] = peer

        peer.touch()

        try:
            message = json.loads(raw_message)
        except json.JSONDecodeError:
            logger.warning("Dropping malformed message from %s", peer)
            return

        # Threat detection gate
        if self._threat_detector is not None:
            threat = self._threat_detector.inspect(message)
            if threat.is_blocked:
                logger.warning(
                    "Blocked message from %s (threat level=%s)",
                    peer,
                    threat.level.name,
                )
                return

        msg_type = message.get("type", "")
        for handler in self._handlers.get(msg_type, []):
            try:
                handler(peer, message)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Handler %s raised %s for message type %s",
                    handler.__name__,
                    exc,
                    msg_type,
                )

    def send(self, peer: Peer, message: dict) -> bytes:
        """Serialise *message* as JSON and return the wire bytes.

        In a real network stack this would write to a socket; here we
        return the serialised bytes so callers can forward them however
        they like (sockets, radio, optical fibre, etc.).
        """
        payload = json.dumps(message).encode()
        logger.debug("→ %s  type=%s", peer, message.get("type"))
        return payload

    def broadcast(self, message: dict) -> List[bytes]:
        """Serialise and *return* the wire bytes for each reachable peer.

        Returns a list so callers can iterate and dispatch over their
        chosen transport layer.
        """
        return [self.send(p, message) for p in self.reachable_peers()]
