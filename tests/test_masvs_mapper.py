"""Tests for MASVS mapper."""

import pytest
from mobiussec.masvs_mapper import MASVSMapper, MASVS_TESTS
from mobiussec.models import Finding, MASVSStatus, Platform, Severity


class TestMASVSMapper:
    def test_map_empty_findings(self):
        mapper = MASVSMapper(Platform.ANDROID)
        result = mapper.map_findings([])
        # All controls should be SKIP (no analysis performed)
        assert all(c.status == MASVSStatus.SKIP for c in result.controls)

    def test_map_findings_with_fail(self):
        findings = [
            Finding(
                id="AND-CRYPTO-001",
                title="Insecure crypto",
                description="Test",
                severity=Severity.HIGH,
                masvs_category="CRYPTO",
                masvs_test_id="MASTG-CRYPTO-2",
                platform=Platform.ANDROID,
            ),
        ]
        mapper = MASVSMapper(Platform.ANDROID)
        result = mapper.map_findings(findings)
        # Should find a FAIL for the matching control
        crypto_controls = [c for c in result.controls if c.category == "CRYPTO" and c.test_id == "MASTG-CRYPTO-2"]
        assert len(crypto_controls) == 1
        assert crypto_controls[0].status == MASVSStatus.FAIL

    def test_map_findings_with_warn(self):
        findings = [
            Finding(
                id="TEST-001",
                title="Low severity",
                description="Test",
                severity=Severity.LOW,
                masvs_category="PLATFORM",
                masvs_test_id="MASTG-PLATFORM-6",
                platform=Platform.ANDROID,
            ),
        ]
        mapper = MASVSMapper(Platform.ANDROID)
        result = mapper.map_findings(findings)
        platform_controls = [c for c in result.controls if c.test_id == "MASTG-PLATFORM-6"]
        assert len(platform_controls) == 1
        assert platform_controls[0].status == MASVSStatus.WARN

    def test_all_categories_present(self):
        mapper = MASVSMapper(Platform.IOS)
        result = mapper.map_findings([])
        categories = set(c.category for c in result.controls)
        expected = set(MASVS_TESTS.keys())
        assert expected.issubset(categories)

    def test_get_category_tests(self):
        tests = MASVSMapper.get_category_tests("CRYPTO")
        assert len(tests) > 0
        assert all(t["id"].startswith("MASTG-CRYPTO") for t in tests)