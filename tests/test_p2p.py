"""Tests for nexus.p2p (Peer and Network)."""

import json
import time

import pytest

from nexus.p2p.peer import Peer
from nexus.p2p.network import Network


class TestPeer:
    def _make_peer(self, peer_id="abc123", host="127.0.0.1", port=7474):
        return Peer(peer_id=peer_id, host=host, port=port)

    def test_address(self):
        peer = self._make_peer(host="10.0.0.1", port=8080)
        assert peer.address == "10.0.0.1:8080"

    def test_is_reachable_recent(self):
        peer = self._make_peer()
        assert peer.is_reachable()

    def test_is_reachable_stale(self):
        peer = self._make_peer()
        peer.last_seen = time.time() - 400
        assert not peer.is_reachable()

    def test_touch_refreshes_timestamp(self):
        peer = self._make_peer()
        peer.last_seen = time.time() - 400
        peer.touch()
        assert peer.is_reachable()

    def test_to_dict_from_dict_round_trip(self):
        peer = self._make_peer(peer_id="xyz789", host="192.168.1.1", port=9000)
        peer.public_key_hex = "deadbeef"
        restored = Peer.from_dict(peer.to_dict())
        assert restored.peer_id == peer.peer_id
        assert restored.host == peer.host
        assert restored.port == peer.port
        assert restored.public_key_hex == peer.public_key_hex


class TestNetwork:
    def setup_method(self):
        self.network = Network(local_peer_id="local-node-id")

    def _make_peer(self, peer_id="remote-001", host="127.0.0.1", port=7475):
        peer = Peer(peer_id=peer_id, host=host, port=port)
        return peer

    def test_add_and_get_peer(self):
        peer = self._make_peer()
        self.network.add_peer(peer)
        assert self.network.get_peer(peer.peer_id) is peer

    def test_remove_peer(self):
        peer = self._make_peer()
        self.network.add_peer(peer)
        self.network.remove_peer(peer.peer_id)
        assert self.network.get_peer(peer.peer_id) is None

    def test_peer_count(self):
        assert self.network.peer_count == 0
        self.network.add_peer(self._make_peer("p1"))
        self.network.add_peer(self._make_peer("p2"))
        assert self.network.peer_count == 2

    def test_reachable_peers_excludes_stale(self):
        fresh = self._make_peer("fresh")
        stale = self._make_peer("stale", port=7476)
        stale.last_seen = time.time() - 400
        self.network.add_peer(fresh)
        self.network.add_peer(stale)
        reachable = self.network.reachable_peers()
        assert fresh in reachable
        assert stale not in reachable

    def test_handler_dispatch(self):
        received = []
        self.network.on("ping", lambda peer, msg: received.append(msg))

        peer = self._make_peer()
        self.network.add_peer(peer)
        raw = json.dumps({"type": "ping", "nonce": "n1"}).encode()
        self.network.receive(peer.peer_id, raw)
        assert len(received) == 1
        assert received[0]["type"] == "ping"

    def test_malformed_message_dropped(self):
        received = []
        self.network.on("ping", lambda peer, msg: received.append(msg))

        peer = self._make_peer()
        self.network.add_peer(peer)
        self.network.receive(peer.peer_id, b"not valid json{{{")
        assert received == []

    def test_send_returns_bytes(self):
        peer = self._make_peer()
        payload = self.network.send(peer, {"type": "hello"})
        assert isinstance(payload, bytes)
        assert json.loads(payload)["type"] == "hello"
