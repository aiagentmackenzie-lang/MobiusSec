"""Tests for STIX 2.1 export."""

import pytest

from mobiussec.stix_export import export_stix, export_stix_json
from mobiussec.models import Finding, ScanResult, Severity, Platform


class TestSTIXExport:
    def _make_result(self, findings=None) -> ScanResult:
        return ScanResult(
            app_path="/test/app.apk",
            platform=Platform.ANDROID,
            package_name="com.test.app",
            app_name="TestApp",
            version="1.0.0",
            findings=findings or [],
        )

    def test_empty_export(self):
        result = self._make_result()
        stix = export_stix(result)
        assert stix["type"] == "bundle"
        assert "objects" in stix
        # Should have: identity, software, grouping, report
        types = [o["type"] for o in stix["objects"]]
        assert "identity" in types
        assert "software" in types
        assert "grouping" in types
        assert "report" in types

    def test_export_with_findings(self):
        findings = [
            Finding(id="VULN-001", title="Test vulnerability", description="A test vuln", severity=Severity.HIGH, masvs_category="CRYPTO"),
            Finding(id="VULN-002", title="Another issue", description="Another vuln", severity=Severity.MEDIUM, masvs_category="STORAGE"),
        ]
        result = self._make_result(findings=findings)
        stix = export_stix(result)
        types = [o["type"] for o in stix["objects"]]
        assert types.count("vulnerability") == 2
        assert types.count("relationship") == 2

    def test_json_export(self):
        result = self._make_result()
        json_str = export_stix_json(result)
        assert isinstance(json_str, str)
        import json
        parsed = json.loads(json_str)
        assert parsed["type"] == "bundle"

    def test_stix_ids_are_valid(self):
        result = self._make_result(findings=[
            Finding(id="T-001", title="t", description="t", severity=Severity.LOW, masvs_category="CODE"),
        ])
        stix = export_stix(result)
        for obj in stix["objects"]:
            assert "--" in obj["id"], f"Invalid STIX ID: {obj['id']}"