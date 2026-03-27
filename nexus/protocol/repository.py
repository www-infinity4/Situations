"""
Decentralized repository protocol.

A :class:`Repository` is a content-addressed DAG of :class:`Commit` objects
backed by a :class:`~nexus.store.ContentStore`.  It follows the same
immutable-history model as Git:

* Every commit records the CID of its tree (a snapshot of file contents)
  and the CIDs of its parent commits.
* Branches are mutable named pointers to a commit CID, just as in Git.
* Because all objects are content-addressed, two repositories that have
  exchanged objects are guaranteed to share identical history — there is
  no authoritative central server that could serve a different version.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from nexus.store import ContentStore


# ---------------------------------------------------------------------------
# Data objects
# ---------------------------------------------------------------------------

@dataclass
class TreeEntry:
    """A single file entry in a tree."""

    name: str
    cid: str        # CID of the blob (file content)
    mode: str = "100644"

    def to_dict(self) -> dict:
        return {"name": self.name, "cid": self.cid, "mode": self.mode}

    @classmethod
    def from_dict(cls, data: dict) -> "TreeEntry":
        return cls(name=data["name"], cid=data["cid"], mode=data.get("mode", "100644"))


@dataclass
class Commit:
    """An immutable snapshot of the repository at a point in time."""

    author: str
    message: str
    tree_cid: str
    parent_cids: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_bytes(self) -> bytes:
        """Canonical serialisation used to compute the commit CID."""
        payload = {
            "author": self.author,
            "message": self.message,
            "tree_cid": self.tree_cid,
            "parent_cids": sorted(self.parent_cids),
            "timestamp": self.timestamp,
        }
        return json.dumps(payload, sort_keys=True).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Commit":
        payload = json.loads(data)
        return cls(
            author=payload["author"],
            message=payload["message"],
            tree_cid=payload["tree_cid"],
            parent_cids=payload.get("parent_cids", []),
            timestamp=payload.get("timestamp", time.time()),
        )


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class Repository:
    """A decentralized, content-addressed code repository.

    Parameters
    ----------
    name:
        Human-readable name for the repository.
    store:
        The :class:`~nexus.store.ContentStore` to use.  If not provided
        a fresh in-memory store is created.
    """

    def __init__(self, name: str, store: Optional[ContentStore] = None) -> None:
        self.name = name
        self._store = store or ContentStore()
        self._branches: Dict[str, str] = {}  # branch name → commit CID

    # ------------------------------------------------------------------
    # Low-level store access
    # ------------------------------------------------------------------

    def put_blob(self, data: bytes) -> str:
        """Store raw file contents and return the blob CID."""
        return self._store.put(data)

    def get_blob(self, cid: str) -> bytes:
        """Retrieve raw file contents by CID."""
        return self._store.get(cid)

    # ------------------------------------------------------------------
    # Tree operations
    # ------------------------------------------------------------------

    def put_tree(self, entries: List[TreeEntry]) -> str:
        """Serialise *entries* to the store and return the tree CID."""
        payload = json.dumps(
            [e.to_dict() for e in entries], sort_keys=True
        ).encode()
        return self._store.put(payload)

    def get_tree(self, tree_cid: str) -> List[TreeEntry]:
        """Retrieve the tree identified by *tree_cid*."""
        data = self._store.get(tree_cid)
        return [TreeEntry.from_dict(e) for e in json.loads(data)]

    # ------------------------------------------------------------------
    # Commit operations
    # ------------------------------------------------------------------

    def commit(
        self,
        author: str,
        message: str,
        entries: List[TreeEntry],
        branch: str = "main",
        parent_cids: Optional[List[str]] = None,
    ) -> str:
        """Create a commit and advance *branch* to it.

        Returns the new commit CID.
        """
        if parent_cids is None:
            # If the branch already exists, use its current tip as the parent
            current = self._branches.get(branch)
            parent_cids = [current] if current else []

        tree_cid = self.put_tree(entries)
        c = Commit(
            author=author,
            message=message,
            tree_cid=tree_cid,
            parent_cids=parent_cids,
        )
        commit_bytes = c.to_bytes()
        cid = self._store.put(commit_bytes)
        self._branches[branch] = cid
        return cid

    def get_commit(self, cid: str) -> Commit:
        """Retrieve and deserialise the commit identified by *cid*."""
        return Commit.from_bytes(self._store.get(cid))

    # ------------------------------------------------------------------
    # Branch operations
    # ------------------------------------------------------------------

    def branch_tip(self, branch: str = "main") -> Optional[str]:
        """Return the commit CID at the tip of *branch*, or ``None``."""
        return self._branches.get(branch)

    def list_branches(self) -> List[str]:
        """Return all branch names."""
        return list(self._branches.keys())

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def log(self, branch: str = "main") -> List[Commit]:
        """Walk the commit graph from *branch* tip and return all commits.

        History is returned in reverse chronological order (newest first).
        """
        history: List[Commit] = []
        visited: set = set()
        queue = []

        tip = self._branches.get(branch)
        if tip:
            queue.append(tip)

        while queue:
            cid = queue.pop(0)
            if cid in visited:
                continue
            visited.add(cid)
            commit = self.get_commit(cid)
            history.append(commit)
            queue.extend(commit.parent_cids)

        return history

    # ------------------------------------------------------------------
    # Replication helpers
    # ------------------------------------------------------------------

    def export_objects(self) -> Dict[str, bytes]:
        """Return all CID→bytes pairs for replication to a peer."""
        return {cid: self._store.get(cid) for cid in self._store.cids()}

    def import_objects(self, objects: Dict[str, bytes]) -> int:
        """Import CID→bytes pairs received from a peer.

        Returns the number of *new* objects added.
        """
        added = 0
        for cid, data in objects.items():
            if not self._store.contains(cid):
                stored_cid = self._store.put(data)
                if stored_cid == cid:
                    added += 1
        return added
