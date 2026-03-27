"""
Sovereign cryptographic identity and content-addressing.

Every node in the nexus is identified solely by an Ed25519 public key.
There is no username, no email address, no central registry — your key
*is* your identity.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Content addressing
# ---------------------------------------------------------------------------

def content_id(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*.

    This acts as a content identifier (CID): two identical blobs always
    produce the same CID, and any single-bit change produces a completely
    different CID.
    """
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Ed25519 identity
# ---------------------------------------------------------------------------

@dataclass
class Identity:
    """An Ed25519 keypair that represents a nexus node.

    If *cryptography* is available the real Ed25519 primitives are used.
    Otherwise the class falls back to a deterministic stub so that the rest
    of the stack can be developed and tested without the extra dependency.
    """

    _private_key_bytes: bytes = field(repr=False)
    _public_key_bytes: bytes

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls) -> "Identity":
        """Generate a brand-new random identity."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                PublicFormat,
            )

            private_key = Ed25519PrivateKey.generate()
            priv_bytes = private_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            )
            pub_bytes = private_key.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            return cls(_private_key_bytes=priv_bytes, _public_key_bytes=pub_bytes)
        except ImportError:
            # Fallback: use os.urandom for a random 32-byte "key"
            priv_bytes = os.urandom(32)
            pub_bytes = hashlib.sha256(priv_bytes).digest()
            return cls(_private_key_bytes=priv_bytes, _public_key_bytes=pub_bytes)

    @classmethod
    def from_private_bytes(cls, priv_bytes: bytes) -> "Identity":
        """Reconstruct an identity from raw private key bytes."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                NoEncryption,
                PrivateFormat,
                PublicFormat,
            )

            private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
            priv_raw = private_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()
            )
            pub_bytes = private_key.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
            return cls(_private_key_bytes=priv_raw, _public_key_bytes=pub_bytes)
        except ImportError:
            pub_bytes = hashlib.sha256(priv_bytes).digest()
            return cls(_private_key_bytes=priv_bytes, _public_key_bytes=pub_bytes)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def public_key_hex(self) -> str:
        """Hex-encoded public key — safe to share publicly."""
        return self._public_key_bytes.hex()

    @property
    def node_id(self) -> str:
        """Stable node identifier derived from the public key."""
        return content_id(self._public_key_bytes)

    def sign(self, message: bytes) -> bytes:
        """Sign *message* and return the signature bytes."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            private_key = Ed25519PrivateKey.from_private_bytes(self._private_key_bytes)
            return private_key.sign(message)
        except ImportError:
            # Stub: HMAC-SHA256 signature (not Ed25519, for testing only)
            import hmac

            return hmac.new(self._private_key_bytes, message, hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Return True if *signature* is a valid signature of *message*."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            public_key = Ed25519PublicKey.from_public_bytes(self._public_key_bytes)
            public_key.verify(signature, message)
            return True
        except ImportError:
            import hmac

            expected = hmac.new(
                self._private_key_bytes, message, hashlib.sha256
            ).digest()
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialise the *public* portion of the identity to a dict."""
        return {
            "node_id": self.node_id,
            "public_key": self.public_key_hex,
        }

    def save(self, path: str) -> None:
        """Persist the private key to *path* (mode 0o600)."""
        with open(path, "wb") as fh:
            fh.write(self._private_key_bytes)
        os.chmod(path, 0o600)

    @classmethod
    def load(cls, path: str) -> "Identity":
        """Load an identity from a file previously written by :meth:`save`."""
        with open(path, "rb") as fh:
            return cls.from_private_bytes(fh.read())
