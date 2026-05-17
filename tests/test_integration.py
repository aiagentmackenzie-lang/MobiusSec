"""End-to-end integration tests for MobiusSec scanner pipeline."""

from __future__ import annotations

from pathlib import Path

from mobiussec.models import Platform, ScanConfig, Severity
from mobiussec.scanner import Scanner
from mobiussec.diff_analyzer import DiffAnalyzer
from mobiussec.reports import generate_html_report, generate_sarif_report, generate_markdown_report


def _get_fixture(name: str) -> Path:
    return Path(__file__).parent / "fixtures" / name


class TestIntegrationAPK:
    """Full APK scan pipeline integration tests."""

    def test_full_apk_scan_pipeline(self) -> None:
        apk = _get_fixture("vulnerable_test.apk")
        config = ScanConfig(app_path=apk)
        scanner = Scanner(config)
        result = scanner.scan()

        assert result.platform == Platform.ANDROID
        assert result.package_name == "com.test.vulnerableapp"
        assert result.version == "1.0"
        assert result.total_findings > 0
        assert any(f.id == "AND-001" for f in result.findings)
        assert any(f.id == "AND-NET-001" for f in result.findings)
        assert any(f.id == "AND-NET-002" for f in result.findings)
        assert any(f.id == "AND-BACKUP-001" for f in result.findings)
        assert any(f.id.startswith("SECRET-") for f in result.findings)
        assert any(f.masvs_category == "PRIVACY" for f in result.findings)
        assert result.masvs_result is not None
        assert not result.masvs_result.l1_ready
        assert len(result.errors) == 0

    def test_quick_mode_filters_correctly(self) -> None:
        apk = _get_fixture("vulnerable_test.apk")
        config = ScanConfig(app_path=apk, quick=True)
        scanner = Scanner(config)
        result = scanner.scan()

        assert result.total_findings > 0
        for f in result.findings:
            assert f.severity in (Severity.CRITICAL, Severity.HIGH)

    def test_gate_check_fails_on_vulnerable_app(self) -> None:
        apk = _get_fixture("vulnerable_test.apk")
        config = ScanConfig(app_path=apk, gate_level="L1")
        scanner = Scanner(config)
        result = scanner.scan()
        assert scanner.check_gate(result) == 1

    def test_report_generation_from_scan(self) -> None:
        apk = _get_fixture("vulnerable_test.apk")
        config = ScanConfig(app_path=apk)
        scanner = Scanner(config)
        result = scanner.scan()

        html = generate_html_report(result)
        assert "MobiusSec Security Report" in html
        assert result.app_name in html or result.package_name in html

        sarif = generate_sarif_report(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) > 0

        md = generate_markdown_report(result)
        assert "# MobiusSec Security Report" in md
        assert "AND-001" in md

    def test_diff_between_vulnerable_and_clean(self) -> None:
        vulnerable = _get_fixture("vulnerable_test.apk")
        clean = _get_fixture("clean_test.apk")

        config1 = ScanConfig(app_path=vulnerable)
        result1 = Scanner(config1).scan()

        config2 = ScanConfig(app_path=clean)
        result2 = Scanner(config2).scan()

        diff = DiffAnalyzer(result1, result2).diff()
        assert diff["verdict"] in ("REGRESSION", "WARNING", "CHANGED", "IMPROVED") or "IMPROVED" in diff["verdict"]
        assert len(diff["added"]) > 0 or len(diff["removed"]) > 0


class TestIntegrationIPA:
    """Full IPA scan pipeline integration tests."""

    def test_full_ipa_scan_pipeline(self) -> None:
        ipa = _get_fixture("vulnerable_test.ipa")
        config = ScanConfig(app_path=ipa)
        scanner = Scanner(config)
        result = scanner.scan()

        assert result.platform == Platform.IOS
        assert result.total_findings > 0
        assert any("ATS" in f.id for f in result.findings)
        assert any(f.masvs_category == "PRIVACY" for f in result.findings)
        assert result.masvs_result is not None
        assert len(result.errors) == 0

    def test_ipa_masvs_result_exists(self) -> None:
        ipa = _get_fixture("vulnerable_test.ipa")
        config = ScanConfig(app_path=ipa)
        scanner = Scanner(config)
        result = scanner.scan()
        assert result.masvs_result is not None
        assert not result.masvs_result.l1_ready or not result.masvs_result.l2_ready
