"""Tests for report generators."""

import pytest

from mobiussec.reports import generate_html_report, generate_sarif_report, generate_markdown_report
from mobiussec.models import Finding, ScanResult, Severity, Platform


class TestReportGenerators:
    def _make_result(self, findings=None) -> ScanResult:
        return ScanResult(
            app_path="/test/app.apk",
            platform=Platform.ANDROID,
            package_name="com.test.app",
            app_name="TestApp",
            version="1.0.0",
            findings=findings or [],
        )

    def test_html_report_empty(self):
        result = self._make_result()
        html = generate_html_report(result)
        assert "MobiusSec" in html
        assert "TestApp" in html
        assert "<!DOCTYPE html>" in html

    def test_html_report_with_findings(self):
        findings = [
            Finding(id="TEST-001", title="Test issue", description="A test finding", severity=Severity.HIGH, masvs_category="CRYPTO"),
        ]
        result = self._make_result(findings=findings)
        html = generate_html_report(result)
        assert "TEST-001" in html
        assert "HIGH" in html
        assert "Test issue" in html

    def test_sarif_report(self):
        findings = [
            Finding(id="TEST-001", title="Test issue", description="A test finding", severity=Severity.HIGH, masvs_category="CRYPTO", file="Config.java", line=10),
        ]
        result = self._make_result(findings=findings)
        sarif = generate_sarif_report(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["ruleId"] == "TEST-001"

    def test_markdown_report(self):
        findings = [
            Finding(id="TEST-001", title="Test issue", description="A test finding", severity=Severity.MEDIUM, masvs_category="STORAGE"),
        ]
        result = self._make_result(findings=findings)
        md = generate_markdown_report(result)
        assert "# MobiusSec" in md
        assert "TEST-001" in md
        assert "MEDIUM" in md