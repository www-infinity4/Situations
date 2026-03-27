"""Tests for nexus.ai.threat_detector."""

import pytest

from nexus.ai.threat_detector import (
    ThreatDetector,
    ThreatLevel,
    InjectionPatternRule,
    OversizedPayloadRule,
    ReplayRule,
    UnknownTypeRule,
)


class TestThreatDetector:
    def setup_method(self):
        self.detector = ThreatDetector(block_threshold=4.0)

    # Clean messages
    def test_clean_hello(self):
        msg = {"type": "hello", "node_id": "abc"}
        result = self.detector.inspect(msg)
        assert result.level == ThreatLevel.NONE
        assert not result.is_blocked

    def test_clean_ping(self):
        result = self.detector.inspect({"type": "ping", "nonce": "unique-1"})
        assert result.level == ThreatLevel.NONE

    # Unknown type → LOW threat
    def test_unknown_type_is_low(self):
        result = self.detector.inspect({"type": "unknown_exotic"})
        assert result.level == ThreatLevel.LOW
        assert any("unknown" in r for r in result.reasons)

    # Injection pattern → HIGH / blocked
    def test_injection_pattern_rm(self):
        msg = {"type": "hello", "payload": "normal; rm -rf /"}
        result = self.detector.inspect(msg)
        assert result.is_blocked

    def test_injection_pattern_script(self):
        msg = {"type": "hello", "payload": "<script>alert(1)</script>"}
        result = self.detector.inspect(msg)
        assert result.is_blocked

    # Replay attack
    def test_replay_attack_blocked(self):
        msg = {"type": "ping", "nonce": "repeated-nonce"}
        self.detector.inspect(msg)  # first time: fine
        result = self.detector.inspect(msg)  # second time: replay
        assert result.is_blocked

    # Oversized payload
    def test_oversized_payload(self):
        msg = {"type": "push", "payload": "x" * (1_048_576 + 1)}
        result = self.detector.inspect(msg)
        assert result.score >= OversizedPayloadRule.weight

    # Custom rule
    def test_custom_rule(self):
        from nexus.ai.threat_detector import Rule

        class BadWordRule(Rule):
            weight = 5.0
            description = "bad word"

            def match(self, message: dict) -> bool:
                return "badword" in str(message)

        self.detector.add_rule(BadWordRule())
        msg = {"type": "hello", "data": "contains badword here"}
        result = self.detector.inspect(msg)
        assert result.is_blocked


class TestThreatAssessment:
    def test_is_blocked_high(self):
        from nexus.ai.threat_detector import ThreatAssessment

        a = ThreatAssessment(level=ThreatLevel.HIGH, score=5.0, reasons=["x"])
        assert a.is_blocked

    def test_not_blocked_medium(self):
        from nexus.ai.threat_detector import ThreatAssessment

        a = ThreatAssessment(level=ThreatLevel.MEDIUM, score=2.5)
        assert not a.is_blocked
