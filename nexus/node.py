"""
Nexus node — top-level orchestrator.

A :class:`Node` wires together:

* A cryptographic :class:`~nexus.crypto.Identity` (your sovereign key)
* A :class:`~nexus.store.ContentStore` (your local object database)
* A :class:`~nexus.p2p.Network` (your peer connections)
* A :class:`~nexus.ai.ThreatDetector` (your edge-local security layer)

It registers the core P2P message handlers (``hello``, ``ping``/``pong``,
``push``/``pull``) and exposes a high-level API for publishing data and
interacting with repositories.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from nexus.ai.threat_detector import ThreatDetector
from nexus.crypto.identity import Identity
from nexus.p2p.network import Network
from nexus.p2p.peer import Peer
from nexus.protocol.repository import Repository
from nexus.store import ContentStore

logger = logging.getLogger(__name__)


class Node:
    """A Personal Nexus node.

    Parameters
    ----------
    identity:
        The cryptographic identity for this node.  A new random identity
        is generated if not provided.
    store:
        Backing content store.  A fresh in-memory store is used if not
        provided.
    """

    def __init__(
        self,
        identity: Optional[Identity] = None,
        store: Optional[ContentStore] = None,
    ) -> None:
        self.identity = identity or Identity.generate()
        self.store = store or ContentStore()
        self.threat_detector = ThreatDetector()
        self.network = Network(
            local_peer_id=self.identity.node_id,
            threat_detector=self.threat_detector,
        )
        self._repositories: dict[str, Repository] = {}
        self._started_at: float = time.time()

        self._register_handlers()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Announce the node to the network (log-level hook for now)."""
        logger.info(
            "Node %s started (pubkey=%s…)",
            self.identity.node_id[:12],
            self.identity.public_key_hex[:16],
        )
        # Broadcast a HELLO to all known peers
        hello = self._hello_message()
        self.network.broadcast(hello)

    def uptime(self) -> float:
        """Return the number of seconds since the node was created."""
        return time.time() - self._started_at

    # ------------------------------------------------------------------
    # Repository management
    # ------------------------------------------------------------------

    def create_repository(self, name: str) -> Repository:
        """Create a new repository backed by this node's content store."""
        if name in self._repositories:
            raise ValueError(f"Repository '{name}' already exists on this node")
        repo = Repository(name=name, store=self.store)
        self._repositories[name] = repo
        logger.info("Created repository '%s'", name)
        return repo

    def get_repository(self, name: str) -> Optional[Repository]:
        """Return the named repository, or ``None`` if not found."""
        return self._repositories.get(name)

    # ------------------------------------------------------------------
    # Content publishing
    # ------------------------------------------------------------------

    def publish(self, data: bytes) -> str:
        """Store *data* in the content store and return its CID.

        The CID can be shared with peers who can then fetch the object.
        """
        cid = self.store.put(data)
        logger.info("Published object CID=%s…", cid[:12])
        return cid

    def fetch(self, cid: str) -> bytes:
        """Retrieve a previously published object by CID."""
        return self.store.get(cid)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hello_message(self) -> dict:
        return {
            "type": "hello",
            "node_id": self.identity.node_id,
            "public_key": self.identity.public_key_hex,
            "timestamp": time.time(),
        }

    def _register_handlers(self) -> None:
        """Register built-in P2P message handlers."""

        def handle_hello(peer: Peer, message: dict) -> None:
            peer.public_key_hex = message.get("public_key")
            logger.info("Handshake with %s complete", peer)

        def handle_ping(peer: Peer, message: dict) -> None:  # noqa: ARG001
            pong = {"type": "pong", "node_id": self.identity.node_id}
            self.network.send(peer, pong)

        def handle_push(peer: Peer, message: dict) -> None:  # noqa: ARG001
            objects: dict = message.get("objects", {})
            added = 0
            for cid, hex_data in objects.items():
                data = bytes.fromhex(hex_data)
                if not self.store.contains(cid):
                    self.store.put(data)
                    added += 1
            logger.info("Received PUSH from %s: %d new objects", peer, added)

        def handle_pull(peer: Peer, message: dict) -> None:  # noqa: ARG001
            requested = message.get("cids", [])
            response: dict = {
                "type": "store",
                "objects": {},
            }
            for cid in requested:
                if self.store.contains(cid):
                    response["objects"][cid] = self.store.get(cid).hex()
            self.network.send(peer, response)

        self.network.on("hello", handle_hello)
        self.network.on("ping", handle_ping)
        self.network.on("push", handle_push)
        self.network.on("pull", handle_pull)
