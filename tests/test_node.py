"""Integration tests for nexus.node (Node orchestrator)."""

import json

import pytest

from nexus.node import Node
from nexus.p2p.peer import Peer


class TestNode:
    def setup_method(self):
        self.node = Node()

    def test_node_has_identity(self):
        assert self.node.identity is not None
        assert len(self.node.identity.node_id) == 64

    def test_publish_and_fetch(self):
        data = b"sovereign data"
        cid = self.node.publish(data)
        assert self.node.fetch(cid) == data

    def test_create_repository(self):
        repo = self.node.create_repository("my-project")
        assert repo.name == "my-project"

    def test_create_duplicate_repository_raises(self):
        self.node.create_repository("dup")
        with pytest.raises(ValueError, match="already exists"):
            self.node.create_repository("dup")

    def test_get_repository(self):
        self.node.create_repository("alpha")
        assert self.node.get_repository("alpha") is not None
        assert self.node.get_repository("nonexistent") is None

    def test_start_runs_without_error(self):
        # No peers registered, so broadcast is a no-op
        self.node.start()

    def test_uptime_increases(self):
        import time
        t1 = self.node.uptime()
        time.sleep(0.05)
        t2 = self.node.uptime()
        assert t2 > t1

    def test_ping_handler_sends_pong(self):
        # Wire up a peer and deliver a PING; inspect the SEND return value
        peer = Peer(peer_id="remote-peer", host="127.0.0.1", port=9000)
        self.node.network.add_peer(peer)

        sent_payloads = []
        original_send = self.node.network.send

        def capture_send(p, msg):
            payload = original_send(p, msg)
            sent_payloads.append(msg)
            return payload

        self.node.network.send = capture_send

        raw = json.dumps({"type": "ping", "nonce": "unique-ping-nonce"}).encode()
        self.node.network.receive(peer.peer_id, raw)

        pong_msgs = [m for m in sent_payloads if m.get("type") == "pong"]
        assert len(pong_msgs) == 1

    def test_push_handler_stores_objects(self):
        data = b"pushed content"
        import hashlib
        cid = hashlib.sha256(data).hexdigest()

        peer = Peer(peer_id="pusher", host="127.0.0.1", port=9001)
        self.node.network.add_peer(peer)

        raw = json.dumps({
            "type": "push",
            "objects": {cid: data.hex()},
            "nonce": "push-nonce-1",
        }).encode()
        self.node.network.receive(peer.peer_id, raw)

        assert self.node.store.contains(cid)
