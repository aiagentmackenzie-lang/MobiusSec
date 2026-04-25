"""Tests for CLI commands — integration tests using Typer CliRunner."""

import pytest
import tempfile
import zipfile
from pathlib import Path

from typer.testing import CliRunner
from mobiussec.cli import app


runner = CliRunner()


def _create_fake_apk(tmp_path: Path) -> Path:
    """Create a minimal fake APK (ZIP) with AndroidManifest.xml."""
    apk_path = tmp_path / "test.apk"
    manifest_content = b'<?xml version="1.0" encoding="utf-8"?>\n<manifest package="com.test.app"/>\n'
    with zipfile.ZipFile(str(apk_path), "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest_content)
    return apk_path


def _create_fake_ipa(tmp_path: Path) -> Path:
    """Create a minimal fake IPA with Info.plist."""
    ipa_path = tmp_path / "test.ipa"
    import plistlib
    plist_data = plistlib.dumps({
        "CFBundleIdentifier": "com.test.iosapp",
        "CFBundleShortVersionString": "1.0.0",
        "CFBundleName": "TestApp",
    })
    with zipfile.ZipFile(str(ipa_path), "w") as zf:
        zf.writestr("Payload/TestApp.app/Info.plist", plist_data)
    return ipa_path


class TestCLIScan:
    def test_scan_help(self):
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan an Android APK" in result.output

    def test_scan_nonexistent_file(self):
        result = runner.invoke(app, ["scan", "/nonexistent/app.apk"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_scan_unknown_extension(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"test")
            result = runner.invoke(app, ["scan", f.name])
            assert result.exit_code == 1
            assert "unsupported" in result.output.lower()

    def test_scan_apk_quick_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = _create_fake_apk(Path(tmp))
            result = runner.invoke(app, ["scan", str(apk), "--quick"])
            # Should run without crashing (exit 0 since no critical findings expected)
            assert result.exit_code == 0

    def test_scan_apk_json_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = _create_fake_apk(Path(tmp))
            result = runner.invoke(app, ["scan", str(apk), "--format", "json"])
            assert result.exit_code == 0


class TestCLIMasvs:
    def test_masvs_help(self):
        result = runner.invoke(app, ["masvs", "--help"])
        assert result.exit_code == 0
        assert "MASVS" in result.output

    def test_masvs_has_quick_flag(self):
        """Bug fix: masvs command should now accept --quick flag."""
        result = runner.invoke(app, ["masvs", "--help"])
        assert "--quick" in result.output

    def test_masvs_has_gate_flag(self):
        """Bug fix: masvs command should now accept --gate flag."""
        result = runner.invoke(app, ["masvs", "--help"])
        assert "--gate" in result.output

    def test_masvs_has_fail_on_flag(self):
        """Bug fix: masvs command should now accept --fail-on flag."""
        result = runner.invoke(app, ["masvs", "--help"])
        assert "--fail-on" in result.output


class TestCLIOtherCommands:
    def test_version_command(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_deploy_help(self):
        result = runner.invoke(app, ["deploy", "--help"])
        assert result.exit_code == 0

    def test_cicd_help(self):
        result = runner.invoke(app, ["cicd", "--help"])
        assert result.exit_code == 0

    def test_bridge_help(self):
        result = runner.invoke(app, ["bridge", "--help"])
        assert result.exit_code == 0

    def test_diff_help(self):
        result = runner.invoke(app, ["diff", "--help"])
        assert result.exit_code == 0

    def test_fix_help(self):
        result = runner.invoke(app, ["fix", "--help"])
        assert result.exit_code == 0

    def test_report_help(self):
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0

    def test_privacy_help(self):
        result = runner.invoke(app, ["privacy", "--help"])
        assert result.exit_code == 0

    def test_sbom_help(self):
        result = runner.invoke(app, ["sbom", "--help"])
        assert result.exit_code == 0

    def test_stix_help(self):
        result = runner.invoke(app, ["stix", "--help"])
        assert result.exit_code == 0

    def test_main_help_lists_all_commands(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for cmd in ["scan", "masvs", "diff", "fix", "report", "privacy", "sbom", "stix", "cicd", "deploy", "bridge", "version"]:
            assert cmd in result.output, f"Command '{cmd}' not listed in --help"