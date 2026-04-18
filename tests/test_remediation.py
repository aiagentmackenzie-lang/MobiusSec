"""Tests for remediation engine."""

import tempfile
from pathlib import Path

import pytest

from mobiussec.remediation import RemediationEngine, STATIC_REMEDIATIONS, CATEGORY_REMEDIATIONS, SEVERITY_PRIORITY
from mobiussec.models import Finding, Severity, Platform


class TestRemediationEngine:
    def test_static_remediations_exist(self):
        assert len(STATIC_REMEDIATIONS) >= 5
        assert "AND-001" in STATIC_REMEDIATIONS
        assert "IOS-ATS-NSAllowsArbitraryLoads" in STATIC_REMEDIATIONS

    def test_category_remediations(self):
        assert len(CATEGORY_REMEDIATIONS) == 8
        assert "STORAGE" in CATEGORY_REMEDIATIONS
        assert "CRYPTO" in CATEGORY_REMEDIATIONS

    def test_severity_priority_mapping(self):
        assert "P0" in SEVERITY_PRIORITY[Severity.CRITICAL]
        assert "P1" in SEVERITY_PRIORITY[Severity.HIGH]

    def test_static_fix_retrieval(self):
        engine = RemediationEngine()
        finding = Finding(
            id="AND-001",
            title="App is debuggable",
            description="test",
            severity=Severity.HIGH,
            masvs_category="RESILIENCE",
            platform=Platform.ANDROID,
        )
        result = engine.get_remediation(finding)
        assert "static_fix" in result
        assert "code_sample" in result

    def test_category_guidance_retrieval(self):
        engine = RemediationEngine()
        finding = Finding(
            id="CUSTOM-001",
            title="Custom finding",
            description="test",
            severity=Severity.MEDIUM,
            masvs_category="CRYPTO",
            platform=Platform.ANDROID,
        )
        result = engine.get_remediation(finding)
        assert "category_guidance" in result
        assert result["category_guidance"]["title"] == "Cryptographic Best Practices"

    def test_priority_summary(self):
        engine = RemediationEngine()
        findings = [
            Finding(id="1", title="a", description="a", severity=Severity.CRITICAL, masvs_category="STORAGE"),
            Finding(id="2", title="b", description="b", severity=Severity.HIGH, masvs_category="CRYPTO"),
            Finding(id="3", title="c", description="c", severity=Severity.LOW, masvs_category="CODE"),
        ]
        summary = engine.get_priority_summary(findings)
        assert len(summary["P0"]) == 1
        assert len(summary["P1"]) == 1
        assert len(summary["P3"]) == 1