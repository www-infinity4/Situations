"""
Edge-local threat and anomaly detection.

The :class:`ThreatDetector` runs entirely on the local node — there is no
cloud dependency, no call-home, and no third party that can disable it.

Detection strategy (lightweight, no ML framework required)
----------------------------------------------------------
Messages are scored against a set of heuristic rules.  Each rule
contributes a weight to a cumulative *threat score*.  When the score
exceeds a threshold the message is classified as :attr:`ThreatLevel.HIGH`
and the :class:`ThreatAssessment` marks it as blocked.

The rule set is intentionally extensible: add a new :class:`Rule` subclass
and register it in :class:`ThreatDetector.__init__` to expand coverage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List


# ---------------------------------------------------------------------------
# Threat levels
# ---------------------------------------------------------------------------

class ThreatLevel(Enum):
    NONE = auto()    # clean message
    LOW = auto()     # mildly suspicious
    MEDIUM = auto()  # noteworthy
    HIGH = auto()    # blocked


# ---------------------------------------------------------------------------
# Assessment result
# ---------------------------------------------------------------------------

@dataclass
class ThreatAssessment:
    """The result of inspecting a single message."""

    level: ThreatLevel
    score: float
    reasons: List[str] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.level == ThreatLevel.HIGH


# ---------------------------------------------------------------------------
# Heuristic rules
# ---------------------------------------------------------------------------

class Rule:
    """Base class for a detection rule."""

    weight: float = 1.0
    description: str = "generic rule"

    def match(self, message: dict) -> bool:  # noqa: ARG002
        return False


class OversizedPayloadRule(Rule):
    """Flag messages whose payload field exceeds a safe size limit."""

    weight = 2.0
    description = "oversized payload"
    _MAX_PAYLOAD_BYTES = 1_048_576  # 1 MiB

    def match(self, message: dict) -> bool:
        payload = message.get("payload", "")
        if isinstance(payload, (str, bytes)):
            return len(payload) > self._MAX_PAYLOAD_BYTES
        return False


class UnknownTypeRule(Rule):
    """Flag messages that carry no recognisable type field."""

    weight = 0.5
    description = "missing or unknown message type"
    _KNOWN_TYPES = {"hello", "ping", "pong", "push", "pull", "store", "fetch"}

    def match(self, message: dict) -> bool:
        return message.get("type", "") not in self._KNOWN_TYPES


class ReplayRule(Rule):
    """Flag messages whose nonce has already been seen (replay attack)."""

    weight = 4.0
    description = "replay attack (duplicate nonce)"

    def __init__(self) -> None:
        self._seen: set = set()

    def match(self, message: dict) -> bool:
        nonce = message.get("nonce")
        if nonce is None:
            return False
        if nonce in self._seen:
            return True
        self._seen.add(nonce)
        return False


class InjectionPatternRule(Rule):
    """Flag messages that contain shell / code injection patterns."""

    weight = 4.0
    description = "injection pattern detected"
    _PATTERNS = [
        re.compile(r";\s*(?:rm|dd|mkfs|format)\b", re.IGNORECASE),
        re.compile(r"\$\{[^}]*\}", re.IGNORECASE),
        re.compile(r"<script", re.IGNORECASE),
    ]

    def match(self, message: dict) -> bool:
        text = str(message)
        return any(p.search(text) for p in self._PATTERNS)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class ThreatDetector:
    """Inspect incoming messages and return a :class:`ThreatAssessment`.

    Parameters
    ----------
    block_threshold:
        Cumulative score at which a message is classified as
        :attr:`ThreatLevel.HIGH` and blocked.  Default ``4.0``.
    """

    def __init__(self, block_threshold: float = 4.0) -> None:
        self.block_threshold = block_threshold
        self._rules: List[Rule] = [
            OversizedPayloadRule(),
            UnknownTypeRule(),
            ReplayRule(),
            InjectionPatternRule(),
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def inspect(self, message: dict) -> ThreatAssessment:
        """Evaluate *message* against all rules and return an assessment."""
        score = 0.0
        reasons: List[str] = []

        for rule in self._rules:
            if rule.match(message):
                score += rule.weight
                reasons.append(rule.description)

        level = self._classify(score)
        return ThreatAssessment(level=level, score=score, reasons=reasons)

    def add_rule(self, rule: Rule) -> None:
        """Add a custom *rule* to the detector."""
        self._rules.append(rule)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _classify(self, score: float) -> ThreatLevel:
        if score >= self.block_threshold:
            return ThreatLevel.HIGH
        if score >= 2.0:
            return ThreatLevel.MEDIUM
        if score > 0:
            return ThreatLevel.LOW
        return ThreatLevel.NONE
