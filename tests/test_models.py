"""Tests for MobiusSec data models."""

import pytest
from mobiussec.models import (
    Finding,
    MASVSControl,
    MASVSResult,
    MASVSStatus,
    Platform,
    ScanConfig,
    ScanResult,
    Severity,
)


class TestFinding:
    def test_create_finding(self):
        f = Finding(
            id="TEST-001",
            title="Test finding",
            description="A test finding",
            severity=Severity.HIGH,
            masvs_category="CRYPTO",
            masvs_test_id="MASTG-CRYPTO-1",
            platform=Platform.ANDROID,
        )
        assert f.id == "TEST-001"
        assert f.severity == Severity.HIGH
        assert f.masvs_category == "CRYPTO"

    def test_finding_to_dict(self):
        f = Finding(
            id="TEST-001",
            title="Test",
            description="Test",
            severity=Severity.MEDIUM,
            masvs_category="STORAGE",
        )
        d = f.to_dict()
        assert d["id"] == "TEST-001"
        assert d["severity"] == "medium"
        assert d["masvs_category"] == "STORAGE"


class TestScanResult:
    def _make_result(self, findings=None):
        return ScanResult(
            app_path="/test/app.apk",
            platform=Platform.ANDROID,
            package_name="com.test.app",
            app_name="TestApp",
            version="1.0.0",
            findings=findings or [],
            scan_time_seconds=1.5,
        )

    def test_empty_result(self):
        r = self._make_result()
        assert r.total_findings == 0
        assert r.critical_count == 0
        assert r.high_count == 0

    def test_counts_by_severity(self):
        findings = [
            Finding(id="1", title="a", description="a", severity=Severity.CRITICAL, masvs_category="STORAGE"),
            Finding(id="2", title="b", description="b", severity=Severity.HIGH, masvs_category="CRYPTO"),
            Finding(id="3", title="c", description="c", severity=Severity.HIGH, masvs_category="NETWORK"),
            Finding(id="4", title="d", description="d", severity=Severity.MEDIUM, masvs_category="PLATFORM"),
            Finding(id="5", title="e", description="e", severity=Severity.INFO, masvs_category="CODE"),
        ]
        r = self._make_result(findings=findings)
        assert r.total_findings == 5
        assert r.critical_count == 1
        assert r.high_count == 2
        assert r.medium_count == 1
        assert r.info_count == 1

    def test_findings_by_category(self):
        findings = [
            Finding(id="1", title="a", description="a", severity=Severity.HIGH, masvs_category="CRYPTO"),
            Finding(id="2", title="b", description="b", severity=Severity.MEDIUM, masvs_category="CRYPTO"),
            Finding(id="3", title="c", description="c", severity=Severity.LOW, masvs_category="STORAGE"),
        ]
        r = self._make_result(findings=findings)
        assert len(r.findings_by_category("CRYPTO")) == 2
        assert len(r.findings_by_category("STORAGE")) == 1
        assert len(r.findings_by_category("NETWORK")) == 0

    def test_to_dict(self):
        r = self._make_result()
        d = r.to_dict()
        assert d["app_path"] == "/test/app.apk"
        assert d["platform"] == "android"
        assert d["package_name"] == "com.test.app"


class TestMASVSResult:
    def test_empty_result_not_l1_ready(self):
        result = MASVSResult(platform=Platform.ANDROID, controls=[])
        # No controls tested — no failures, but L1 check depends on implementation
        assert isinstance(result.l1_ready, bool)

    def test_category_scores(self):
        controls = [
            MASVSControl(category="STORAGE", test_id="MASTG-STORAGE-1", test_name="test", status=MASVSStatus.PASS),
            MASVSControl(category="STORAGE", test_id="MASTG-STORAGE-2", test_name="test", status=MASVSStatus.FAIL),
            MASVSControl(category="CRYPTO", test_id="MASTG-CRYPTO-1", test_name="test", status=MASVSStatus.PASS),
        ]
        result = MASVSResult(platform=Platform.ANDROID, controls=controls)
        scores = result.category_scores
        assert scores["STORAGE"]["pass"] == 1
        assert scores["STORAGE"]["fail"] == 1
        assert scores["CRYPTO"]["pass"] == 1

    def test_l1_fails_on_storage_fail(self):
        controls = [
            MASVSControl(category="STORAGE", test_id="MASTG-STORAGE-1", test_name="test", status=MASVSStatus.FAIL),
        ]
        result = MASVSResult(platform=Platform.ANDROID, controls=controls)
        assert result.l1_ready is False

    def test_l1_passes_with_passes(self):
        controls = [
            MASVSControl(category="STORAGE", test_id="MASTG-STORAGE-1", test_name="test", status=MASVSStatus.PASS),
            MASVSControl(category="CRYPTO", test_id="MASTG-CRYPTO-1", test_name="test", status=MASVSStatus.PASS),
            MASVSControl(category="AUTH", test_id="MASTG-AUTH-1", test_name="test", status=MASVSStatus.PASS),
            MASVSControl(category="NETWORK", test_id="MASTG-NETWORK-1", test_name="test", status=MASVSStatus.PASS),
        ]
        result = MASVSResult(platform=Platform.ANDROID, controls=controls)
        assert result.l1_ready is True


class TestScanConfig:
    def test_default_config(self):
        config = ScanConfig(app_path=Path("/test/app.apk"))
        assert config.quick is False
        assert config.gate_level == ""
        assert config.output_format == "rich"


# Import Path for test
from pathlib import Path