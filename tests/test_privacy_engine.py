"""Tests for privacy engine."""

import plistlib
import tempfile
from pathlib import Path

import pytest

from mobiussec.privacy_engine import PrivacyEngine, TRACKING_SDKS, PRIVACY_REGULATIONS
from mobiussec.models import Platform, Severity


class TestPrivacyEngine:
    def test_tracking_sdks_catalog(self):
        assert "analytics" in TRACKING_SDKS
        assert "ad_networks" in TRACKING_SDKS
        assert "social" in TRACKING_SDKS
        assert len(TRACKING_SDKS) >= 5

    def test_privacy_regulations(self):
        assert "lgpd" in PRIVACY_REGULATIONS
        assert "gdpr" in PRIVACY_REGULATIONS
        assert "ccpa" in PRIVACY_REGULATIONS
        assert "key_requirements" in PRIVACY_REGULATIONS["lgpd"]

    def test_empty_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engine = PrivacyEngine(tmp_path, Platform.ANDROID)
            report = engine.analyze()
            assert "privacy_score" in report
            assert report["privacy_score"] == 100  # No data = perfect privacy

    def test_privacy_score_drops_with_tracking(self):
        engine = PrivacyEngine(Path("/tmp/test"), Platform.ANDROID)
        # Manually set data to simulate findings
        engine.data_collected = [{"type": "CAMERA", "description": "Camera", "source": "manifest"}]
        engine.detected_sdks = [{"id": "com.google.firebase.analytics", "description": "Firebase", "category": "analytics"}]
        engine.compliance_gaps = [{"regulation": "lgpd", "name": "LGPD", "gaps": ["test"]}]
        score = engine._calculate_privacy_score()
        assert score < 100

    def test_ios_privacy_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            app_dir = tmp_path / "Payload" / "TestApp.app"
            app_dir.mkdir(parents=True)

            plist_data = {
                "CFBundleIdentifier": "com.test.app",
                "CFBundleDisplayName": "TestApp",
                "CFBundleShortVersionString": "1.0.0",
                "CFBundleName": "TestApp",
                "NSCameraUsageDescription": "We need camera for photos",
                "NSLocationWhenInUseUsageDescription": "We need location",
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            }

            with open(app_dir / "Info.plist", "wb") as f:
                plistlib.dump(plist_data, f)

            engine = PrivacyEngine(app_dir, Platform.IOS)
            report = engine.analyze()
            assert len(report["data_collected"]) >= 2  # Camera + Location