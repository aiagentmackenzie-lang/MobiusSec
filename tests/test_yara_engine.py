"""Tests for YARA engine."""

import tempfile
from pathlib import Path

import pytest

from mobiussec.yara_engine import YARAEngine, ANDROID_YARA_RULES, IOS_YARA_RULES
from mobiussec.models import Platform


class TestYARAEngine:
    def test_android_yara_rules_exist(self):
        assert len(ANDROID_YARA_RULES) > 100  # Should have substantial rules
        assert "android_packer_dexguard" in ANDROID_YARA_RULES
        assert "android_sms_stealer" in ANDROID_YARA_RULES

    def test_ios_yara_rules_exist(self):
        assert len(IOS_YARA_RULES) > 50
        assert "ios_jailbreak_detection" in IOS_YARA_RULES

    def test_empty_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            engine = YARAEngine(tmp_path, Platform.ANDROID)
            findings = engine.scan()
            assert isinstance(findings, list)

    def test_regex_fallback_android(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Create a smali file with root detection
            smali_dir = tmp_path / "smali"
            smali_dir.mkdir()
            (smali_dir / "RootCheck.smali").write_text('''
.class public Lcom/example/RootCheck;
.method public isDeviceRooted()Z
    const-string v0, "su"
    return v1
.end method
''')
            engine = YARAEngine(tmp_path, Platform.ANDROID)
            # Will use regex fallback if yara-python is not available
            findings = engine.scan()
            root_findings = [f for f in findings if "root" in f.title.lower() or "Root" in f.title]
            assert len(root_findings) > 0

    def test_regex_fallback_ios(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Create a Swift file with jailbreak detection
            swift_file = tmp_path / "SecurityCheck.swift"
            swift_file.write_text('''
func isJailbroken() -> Bool {
    if FileManager.default.fileExists(atPath: "/Applications/Cydia.app") {
        return true
    }
    return false
}
''')
            engine = YARAEngine(tmp_path, Platform.IOS)
            findings = engine.scan()
            jb_findings = [f for f in findings if "jailbreak" in f.title.lower() or "Jailbreak" in f.title]
            assert len(jb_findings) > 0