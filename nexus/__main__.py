"""
CLI entry point for the Personal Nexus node.

Usage
-----
    python -m nexus [OPTIONS] [COMMAND]

Options
-------
    --host TEXT      Bind address (default: 0.0.0.0)
    --port INTEGER   Listen port (default: 7474)
    --peer TEXT      Bootstrap peer address as host:port
    --identity FILE  Path to persisted identity file

Commands
--------
    start            Start the node and enter event loop (default)
    publish FILE     Publish a file to the content store and print its CID
    info             Print node information
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from nexus.crypto.identity import Identity
from nexus.node import Node
from nexus.store import ContentStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("nexus.cli")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexus",
        description="Personal Nexus — sovereign decentralized node",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=7474, help="Listen port")
    parser.add_argument("--peer", help="Bootstrap peer (host:port)")
    parser.add_argument("--identity", help="Path to identity file")

    sub = parser.add_subparsers(dest="command")
    sub.add_parser("start", help="Start the nexus node")
    sub.add_parser("info", help="Print node information")

    publish_p = sub.add_parser("publish", help="Publish a file to the content store")
    publish_p.add_argument("file", help="Path to the file to publish")

    return parser


def _load_or_generate_identity(path: str | None) -> Identity:
    if path and Path(path).exists():
        logger.info("Loading identity from %s", path)
        return Identity.load(path)
    identity = Identity.generate()
    if path:
        identity.save(path)
        logger.info("Generated and saved new identity to %s", path)
    return identity


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    identity = _load_or_generate_identity(args.identity)
    node = Node(identity=identity, store=ContentStore())

    command = args.command or "start"

    if command == "info":
        print(f"Node ID  : {node.identity.node_id}")
        print(f"Public Key: {node.identity.public_key_hex}")
        print(f"Uptime    : {node.uptime():.2f}s")
        return 0

    if command == "publish":
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"Error: file not found: {file_path}", file=sys.stderr)
            return 1
        data = file_path.read_bytes()
        cid = node.publish(data)
        print(f"Published {file_path} → CID: {cid}")
        return 0

    # Default: start
    logger.info(
        "Starting nexus node %s on %s:%d",
        node.identity.node_id[:12],
        args.host,
        args.port,
    )
    node.start()
    logger.info("Node is running.  Press Ctrl-C to stop.")
    try:
        import time

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
