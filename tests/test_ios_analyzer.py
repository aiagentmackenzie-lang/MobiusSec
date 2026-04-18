"""Tests for iOS analyzer."""

import plistlib
import pytest
import tempfile
from pathlib import Path

from mobiussec.ios_analyzer import iOSAnalyzer, ATS_RISK_KEYS, INSECURE_KEYCHAIN_CLASSES


class TestIOSAnalyzer:
    def _create_ipa_structure(self, tmp_dir: Path, plist_data: dict | None = None) -> Path:
        """Helper to create a minimal .app bundle structure."""
        app_dir = tmp_dir / "Payload" / "TestApp.app"
        app_dir.mkdir(parents=True)

        if plist_data is None:
            plist_data = {
                "CFBundleIdentifier": "com.test.app",
                "CFBundleDisplayName": "TestApp",
                "CFBundleShortVersionString": "1.0.0",
                "CFBundleName": "TestApp",
            }

        plist_path = app_dir / "Info.plist"
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        return app_dir

    def test_analyzer_instantiation(self):
        analyzer = iOSAnalyzer(Path("/tmp/test"))
        assert analyzer.extracted_dir == Path("/tmp/test")
        assert analyzer.findings == []

    def test_ats_risk_keys(self):
        assert "NSAllowsArbitraryLoads" in ATS_RISK_KEYS
        assert "NSAllowsArbitraryLoadsInWebContent" in ATS_RISK_KEYS

    def test_insecure_keychain_classes(self):
        assert "kSecAttrAccessibleAlways" in INSECURE_KEYCHAIN_CLASSES
        assert len(INSECURE_KEYCHAIN_CLASSES) >= 4

    def test_ats_configuration_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plist_data = {
                "CFBundleIdentifier": "com.test.app",
                "CFBundleDisplayName": "TestApp",
                "CFBundleShortVersionString": "1.0.0",
                "CFBundleName": "TestApp",
                "NSAppTransportSecurity": {
                    "NSAllowsArbitraryLoads": True,
                    "NSAllowsArbitraryLoadsInWebContent": True,
                },
            }
            app_dir = self._create_ipa_structure(tmp_path, plist_data)

            analyzer = iOSAnalyzer(app_dir)
            findings = analyzer.analyze()

            ats_findings = [f for f in findings if "ATS" in f.id or "ats" in f.title.lower()]
            assert len(ats_findings) >= 2  # Both NSAllowsArbitraryLoads and InWebContent

    def test_bundle_id_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            app_dir = self._create_ipa_structure(tmp_path)

            analyzer = iOSAnalyzer(app_dir)
            analyzer._load_plist()
            assert analyzer.bundle_id == "com.test.app"

    def test_url_scheme_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plist_data = {
                "CFBundleIdentifier": "com.test.app",
                "CFBundleDisplayName": "TestApp",
                "CFBundleShortVersionString": "1.0.0",
                "CFBundleName": "TestApp",
                "CFBundleURLTypes": [
                    {
                        "CFBundleURLName": "com.test.app",
                        "CFBundleURLSchemes": ["myapp", "myapp-oauth"],
                    }
                ],
            }
            app_dir = self._create_ipa_structure(tmp_path, plist_data)

            analyzer = iOSAnalyzer(app_dir)
            findings = analyzer.analyze()

            url_findings = [f for f in findings if "URL scheme" in f.title or "url scheme" in f.title.lower()]
            assert len(url_findings) >= 2  # Both schemes

    def test_background_modes_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            plist_data = {
                "CFBundleIdentifier": "com.test.app",
                "CFBundleDisplayName": "TestApp",
                "CFBundleShortVersionString": "1.0.0",
                "CFBundleName": "TestApp",
                "UIBackgroundModes": ["location", "audio"],
            }
            app_dir = self._create_ipa_structure(tmp_path, plist_data)

            analyzer = iOSAnalyzer(app_dir)
            findings = analyzer.analyze()

            bg_findings = [f for f in findings if "Background mode" in f.title]
            assert len(bg_findings) >= 2