"""Tests for Android analyzer."""

import pytest
import tempfile
from pathlib import Path
from lxml import etree

from mobiussec.android_analyzer import AndroidAnalyzer, DANGEROUS_PERMISSIONS, INSECURE_CRYPTO_PATTERNS


class TestAndroidAnalyzer:
    def _create_manifest(self, content: str, tmp_dir: Path) -> Path:
        """Helper to create a test AndroidManifest.xml."""
        manifest = tmp_dir / "AndroidManifest.xml"
        manifest.write_text(content)
        return manifest

    def test_analyzer_instantiation(self):
        analyzer = AndroidAnalyzer(Path("/tmp/test"))
        assert analyzer.extracted_dir == Path("/tmp/test")
        assert analyzer.findings == []

    def test_dangerous_permissions_list(self):
        assert "android.permission.READ_SMS" in DANGEROUS_PERMISSIONS
        assert "android.permission.CAMERA" in DANGEROUS_PERMISSIONS
        assert len(DANGEROUS_PERMISSIONS) >= 20

    def test_insecure_crypto_patterns(self):
        assert len(INSECURE_CRYPTO_PATTERNS) >= 8
        # All patterns should be valid regex
        import re
        for pattern, desc in INSECURE_CRYPTO_PATTERNS:
            re.compile(pattern)  # Should not raise

    def test_manifest_security_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app"
    android:debuggable="true">
    <application android:allowBackup="true" android:usesCleartextTraffic="true">
    </application>
</manifest>"""
            self._create_manifest(manifest_content, tmp_path)
            # Also create res/values directory for app_name
            (tmp_path / "res" / "values").mkdir(parents=True)

            analyzer = AndroidAnalyzer(tmp_path)
            findings = analyzer.analyze()

            # Should find debuggable flag
            debuggable_findings = [f for f in findings if "debuggable" in f.title.lower()]
            assert len(debuggable_findings) > 0
            assert debuggable_findings[0].severity == Severity.HIGH

    def test_package_name_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest_content = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.myapp">
    <application />
</manifest>"""
            self._create_manifest(manifest_content, tmp_path)
            (tmp_path / "res" / "values").mkdir(parents=True)

            analyzer = AndroidAnalyzer(tmp_path)
            analyzer._parse_manifest()
            assert analyzer.package_name == "com.example.myapp"


# Need Severity for the test
from mobiussec.models import Severity