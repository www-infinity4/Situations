"""Tests for nexus.crypto.identity."""

import hashlib
import pytest

from nexus.crypto.identity import Identity, content_id


class TestContentId:
    def test_deterministic(self):
        data = b"hello nexus"
        assert content_id(data) == content_id(data)

    def test_matches_sha256(self):
        data = b"sovereign"
        assert content_id(data) == hashlib.sha256(data).hexdigest()

    def test_different_data_different_id(self):
        assert content_id(b"a") != content_id(b"b")


class TestIdentity:
    def test_generate_produces_unique_keys(self):
        id1 = Identity.generate()
        id2 = Identity.generate()
        assert id1.public_key_hex != id2.public_key_hex
        assert id1.node_id != id2.node_id

    def test_node_id_is_hash_of_pubkey(self):
        identity = Identity.generate()
        expected = hashlib.sha256(bytes.fromhex(identity.public_key_hex)).hexdigest()
        assert identity.node_id == expected

    def test_sign_verify_round_trip(self):
        identity = Identity.generate()
        message = b"hello, nexus"
        sig = identity.sign(message)
        assert identity.verify(message, sig)

    def test_tampered_message_fails_verify(self):
        identity = Identity.generate()
        sig = identity.sign(b"original")
        assert not identity.verify(b"tampered", sig)

    def test_from_private_bytes_round_trip(self):
        original = Identity.generate()
        restored = Identity.from_private_bytes(original._private_key_bytes)
        assert restored.public_key_hex == original.public_key_hex
        assert restored.node_id == original.node_id

    def test_save_and_load(self, tmp_path):
        key_file = tmp_path / "identity.key"
        original = Identity.generate()
        original.save(str(key_file))
        loaded = Identity.load(str(key_file))
        assert loaded.public_key_hex == original.public_key_hex

    def test_to_dict_has_expected_keys(self):
        identity = Identity.generate()
        d = identity.to_dict()
        assert "node_id" in d
        assert "public_key" in d
