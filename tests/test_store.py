"""Tests for nexus.store (ContentStore)."""

import pytest

from nexus.store import ContentStore


class TestContentStore:
    def setup_method(self):
        self.store = ContentStore()

    def test_put_returns_cid(self):
        cid = self.store.put(b"hello")
        assert isinstance(cid, str)
        assert len(cid) == 64  # SHA-256 hex

    def test_get_round_trip(self):
        data = b"decentralized is better"
        cid = self.store.put(data)
        assert self.store.get(cid) == data

    def test_get_unknown_raises_key_error(self):
        with pytest.raises(KeyError):
            self.store.get("0" * 64)

    def test_idempotent_put(self):
        data = b"same data"
        cid1 = self.store.put(data)
        cid2 = self.store.put(data)
        assert cid1 == cid2
        assert len(self.store) == 1

    def test_contains(self):
        cid = self.store.put(b"check")
        assert self.store.contains(cid)
        assert not self.store.contains("a" * 64)

    def test_cids_lists_all(self):
        cids = [self.store.put(f"item{i}".encode()) for i in range(5)]
        assert set(cids) == set(self.store.cids())

    def test_len(self):
        assert len(self.store) == 0
        self.store.put(b"one")
        assert len(self.store) == 1
        self.store.put(b"two")
        assert len(self.store) == 2
