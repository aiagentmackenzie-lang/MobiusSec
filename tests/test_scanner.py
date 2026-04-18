"""Tests for the scanner orchestrator."""

import pytest
import tempfile
from pathlib import Path

from mobiussec.models import ScanConfig, Platform
from mobiussec.scanner import Scanner


class TestScanner:
    def test_scan_config_creation(self):
        config = ScanConfig(app_path=Path("/test/app.apk"))
        assert config.quick is False
        assert config.gate_level == ""

    def test_scan_nonexistent_file(self):
        config = ScanConfig(app_path=Path("/nonexistent/app.apk"))
        scanner = Scanner(config)
        result = scanner.scan()
        assert len(result.errors) > 0

    def test_gate_check_l1(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = ScanConfig(
                app_path=Path("/test/app.apk"),
                gate_level="L1",
            )
            scanner = Scanner(config)
            # Without a real scan, just test the logic
            from mobiussec.models import ScanResult, MASVSResult
            result = ScanResult(
                app_path="/test",
                platform=Platform.ANDROID,
                masvs_result=MASVSResult(platform=Platform.ANDROID, controls=[]),
            )
            # Empty controls = no failures = L1 passes
            assert scanner.check_gate(result) == 0

    def test_gate_check_l2(self):
        config = ScanConfig(
            app_path=Path("/test/app.apk"),
            gate_level="L2",
        )
        scanner = Scanner(config)
        from mobiussec.models import ScanResult, MASVSResult, MASVSControl, MASVSStatus
        result = ScanResult(
            app_path="/test",
            platform=Platform.IOS,
            masvs_result=MASVSResult(
                platform=Platform.IOS,
                controls=[
                    MASVSControl(
                        category="STORAGE",
                        test_id="MASTG-STORAGE-1",
                        test_name="test",
                        status=MASVSStatus.PASS,
                    ),
                ],
            ),
        )
        # L1 and L2 should pass with no failures
        assert scanner.check_gate(result) == 0