"""Tests for nexus.protocol.repository."""

import pytest

from nexus.protocol.repository import Commit, Repository, TreeEntry
from nexus.store import ContentStore


class TestRepository:
    def setup_method(self):
        self.repo = Repository(name="test-repo")

    def test_put_get_blob(self):
        data = b"file contents"
        cid = self.repo.put_blob(data)
        assert self.repo.get_blob(cid) == data

    def test_commit_advances_branch(self):
        entries = [TreeEntry(name="README.md", cid=self.repo.put_blob(b"# Hello"))]
        cid = self.repo.commit(
            author="alice", message="Initial commit", entries=entries
        )
        assert self.repo.branch_tip("main") == cid

    def test_commit_chain(self):
        e1 = [TreeEntry(name="a.txt", cid=self.repo.put_blob(b"v1"))]
        cid1 = self.repo.commit(author="bob", message="first", entries=e1)

        e2 = [TreeEntry(name="a.txt", cid=self.repo.put_blob(b"v2"))]
        cid2 = self.repo.commit(author="bob", message="second", entries=e2)

        commit2 = self.repo.get_commit(cid2)
        assert cid1 in commit2.parent_cids

    def test_log_returns_history(self):
        e = [TreeEntry(name="f", cid=self.repo.put_blob(b"x"))]
        self.repo.commit(author="a", message="c1", entries=e)
        self.repo.commit(author="a", message="c2", entries=e)
        self.repo.commit(author="a", message="c3", entries=e)

        history = self.repo.log()
        assert len(history) == 3
        assert history[0].message == "c3"

    def test_list_branches(self):
        e = [TreeEntry(name="f", cid=self.repo.put_blob(b"x"))]
        self.repo.commit(author="a", message="m", entries=e, branch="main")
        self.repo.commit(author="a", message="m", entries=e, branch="dev")
        branches = self.repo.list_branches()
        assert "main" in branches
        assert "dev" in branches

    def test_export_import_objects(self):
        source = Repository(name="source")
        e = [TreeEntry(name="f.txt", cid=source.put_blob(b"data"))]
        source.commit(author="x", message="init", entries=e)

        dest = Repository(name="dest")
        objects = source.export_objects()
        added = dest.import_objects(objects)
        assert added == len(objects)

        # Second import should add nothing new
        added_again = dest.import_objects(objects)
        assert added_again == 0

    def test_tree_round_trip(self):
        entries = [
            TreeEntry(name="file1.py", cid=self.repo.put_blob(b"print('hello')")),
            TreeEntry(name="file2.py", cid=self.repo.put_blob(b"x = 1")),
        ]
        tree_cid = self.repo.put_tree(entries)
        restored = self.repo.get_tree(tree_cid)
        assert {e.name for e in restored} == {"file1.py", "file2.py"}


class TestCommit:
    def test_serialisation_round_trip(self):
        c = Commit(
            author="alice",
            message="hello",
            tree_cid="abc123",
            parent_cids=["parent1"],
            timestamp=1000.0,
        )
        restored = Commit.from_bytes(c.to_bytes())
        assert restored.author == c.author
        assert restored.message == c.message
        assert restored.tree_cid == c.tree_cid
        assert restored.parent_cids == c.parent_cids
