# Situations — Personal Nexus

A decentralized, sovereign peer-to-peer network and code-collaboration platform that operates independently of centralized services (no GitHub, no DNS, no traditional ISP routing required).

## Vision

The **Personal Nexus** is built around three complementary layers:

| Layer | Purpose | Technology |
|-------|---------|------------|
| **Physical** | Sovereign signal transport | P2P mesh / optical / radio links |
| **OS** | Adaptive, self-hardening runtime | Neuromorphic-inspired, edge AI |
| **Protocol** | Decentralized code & data sharing | Content-addressed, P2P replication |

---

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│               Personal Nexus                │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Crypto  │  │   P2P    │  │    AI    │  │
│  │ Identity │◄─►│ Network  │◄─►│ Defender │  │
│  └────┬─────┘  └────┬─────┘  └──────────┘  │
│       │              │                      │
│  ┌────▼─────────────▼─────────────────┐    │
│  │         Content Store (DAG)         │    │
│  └────────────────────┬────────────────┘    │
│                       │                     │
│  ┌────────────────────▼────────────────┐    │
│  │       Repository Protocol           │    │
│  │  (decentralized code collaboration) │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

---

## Modules

### `nexus/crypto/` — Sovereign Identity
* Ed25519 keypair generation — your identity is a cryptographic key, not a username on a corporate server.
* Content addressing with SHA-256 — every object is identified by its hash, ensuring integrity.

### `nexus/p2p/` — Peer-to-Peer Network
* `Peer` — represents a remote node identified by its public key and network address.
* `Network` — manages peer discovery, message routing, and connection lifecycle.

### `nexus/store.py` — Content-Addressed Store
* Immutable, content-addressed DAG store (inspired by IPFS / Git objects).
* Every blob of data is stored under `SHA-256(data)`, making the store tamper-evident.

### `nexus/protocol/` — Decentralized Repository
* Branch / commit model identical in spirit to Git, but replicated across peers with no central authority.
* Push/pull of commits over the P2P layer.

### `nexus/ai/` — Threat & Anomaly Detection
* Lightweight, **edge-local** anomaly detector — no cloud call-home required.
* Scores incoming messages for anomalous patterns and flags suspicious peers.

### `nexus/node.py` — Nexus Node
* Ties all layers together: starts the P2P network, mounts the content store, and runs the AI defender.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Start a nexus node (generates a fresh keypair on first run)
python -m nexus --host 0.0.0.0 --port 7474

# Connect to a peer
python -m nexus --host 0.0.0.0 --port 7475 --peer 127.0.0.1:7474

# Publish a file to the store
python -m nexus publish path/to/file.txt

# Clone a repository from a peer
python -m nexus clone <repo-cid> --peer 127.0.0.1:7474
```

---

## Security Model

* **No central authority** — every node is identified by its Ed25519 public key.
* **Tamper-evident content** — every object's address *is* its hash; substitution is immediately detectable.
* **Edge-local AI** — the threat detector runs entirely on-device; there is no cloud dependency that can be revoked.
* **Quantum-forward** — the architecture is designed so that the signature scheme can be swapped (e.g., to CRYSTALS-Dilithium) without changing the rest of the stack.

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## License

MIT
<script src="https://www-infinity4.github.io/Mint-For-Infinity/infinity-wallet-menu.js" defer></script>
