"""
Content-addressed, tamper-evident object store.

Inspired by both IPFS and Git's object database:

* Every object is stored under its SHA-256 hash (the content identifier).
* Retrieving an object re-verifies its hash, so any corruption is caught
  immediately.
* The store is append-only: objects are never mutated, only added.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, Optional


class ContentStore:
    """In-memory content-addressed store.

    For production use this would be backed by an on-disk key/value
    store (e.g. RocksDB or SQLite), but keeping it in-memory makes the
    code testable without any I/O setup.
    """

    def __init__(self) -> None:
        self._store: Dict[str, bytes] = {}

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def put(self, data: bytes) -> str:
        """Store *data* and return its content identifier (CID).

        If the same data has already been stored this is a no-op and the
        existing CID is returned.
        """
        cid = self._hash(data)
        self._store[cid] = data
        return cid

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, cid: str) -> bytes:
        """Retrieve the object identified by *cid*.

        Raises :class:`KeyError` if the CID is unknown and
        :class:`ValueError` if the stored data no longer matches the CID
        (indicating corruption or tampering).
        """
        if cid not in self._store:
            raise KeyError(f"CID not found: {cid}")

        data = self._store[cid]
        actual = self._hash(data)
        if actual != cid:
            raise ValueError(
                f"Content integrity failure: expected {cid}, got {actual}"
            )
        return data

    def contains(self, cid: str) -> bool:
        """Return True if *cid* is present in the store."""
        return cid in self._store

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def cids(self) -> Iterable[str]:
        """Iterate over all stored content identifiers."""
        return list(self._store.keys())

    def __len__(self) -> int:
        return len(self._store)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()
