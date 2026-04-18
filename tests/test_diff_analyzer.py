"""Tests for diff analyzer."""

import pytest

from mobiussec.diff_analyzer import DiffAnalyzer
from mobiussec.models import Finding, ScanResult, MASVSResult, Severity, Platform


class TestDiffAnalyzer:
    def _make_result(self, findings=None, version="1.0.0") -> ScanResult:
        return ScanResult(
            app_path="/test/app.apk",
            platform=Platform.ANDROID,
            package_name="com.test.app",
            app_name="TestApp",
            version=version,
            findings=findings or [],
        )

    def test_no_changes(self):
        r1 = self._make_result(version="1.0.0")
        r2 = self._make_result(version="1.0.0")
        analyzer = DiffAnalyzer(r1, r2)
        result = analyzer.diff()
        assert "UNCHANGED" in result["verdict"]

    def test_new_critical_finding(self):
        r1 = self._make_result(version="1.0.0")
        r2 = self._make_result(
            findings=[Finding(id="NEW-001", title="Critical issue", description="test", severity=Severity.CRITICAL, masvs_category="STORAGE")],
            version="2.0.0",
        )
        analyzer = DiffAnalyzer(r1, r2)
        result = analyzer.diff()
        assert len(result["added"]) == 1
        assert "REGRESSION" in result["verdict"]

    def test_finding_resolved(self):
        r1 = self._make_result(
            findings=[Finding(id="FIX-001", title="Fixed issue", description="test", severity=Severity.HIGH, masvs_category="CRYPTO")],
            version="1.0.0",
        )
        r2 = self._make_result(version="2.0.0")
        analyzer = DiffAnalyzer(r1, r2)
        result = analyzer.diff()
        assert len(result["removed"]) == 1
        assert "IMPROVED" in result["verdict"]

    def test_summary_delta(self):
        r1 = self._make_result(
            findings=[Finding(id="1", title="a", description="a", severity=Severity.HIGH, masvs_category="STORAGE")],
            version="1.0.0",
        )
        r2 = self._make_result(
            findings=[
                Finding(id="1", title="a", description="a", severity=Severity.HIGH, masvs_category="STORAGE"),
                Finding(id="2", title="b", description="b", severity=Severity.MEDIUM, masvs_category="CODE"),
            ],
            version="2.0.0",
        )
        analyzer = DiffAnalyzer(r1, r2)
        result = analyzer.diff()
        assert result["summary"]["delta"]["total"] == 1