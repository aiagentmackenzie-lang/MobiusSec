"""Tests for cross-platform analyzer."""

import tempfile
from pathlib import Path

import pytest

from mobiussec.cross_platform import CrossPlatformAnalyzer, FLUTTER_PATTERNS, REACT_NATIVE_PATTERNS
from mobiussec.models import Platform


class TestCrossPlatformAnalyzer:
    def test_flutter_patterns_exist(self):
        assert len(FLUTTER_PATTERNS) >= 10
        assert any("SharedPreferences" in p[0] for p in FLUTTER_PATTERNS)

    def test_react_native_patterns_exist(self):
        assert len(REACT_NATIVE_PATTERNS) >= 10
        assert any("AsyncStorage" in p[0] for p in REACT_NATIVE_PATTERNS)

    def test_empty_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            analyzer = CrossPlatformAnalyzer(tmp_path, Platform.ANDROID)
            findings = analyzer.analyze()
            assert isinstance(findings, list)
            assert len(analyzer.detected_frameworks) == 0

    def test_flutter_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Create Flutter markers
            assets = tmp_path / "flutter_assets"
            assets.mkdir()
            (assets / "kernel_blob.bin").write_text("flutter")

            # Create Dart file with SharedPreferences
            dart_dir = tmp_path / "lib"
            dart_dir.mkdir()
            (dart_dir / "storage.dart").write_text('''
import 'package:shared_preferences/shared_preferences.dart';

class Storage {
  Future<String?> getToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString('auth_token');
  }
}
''')
            analyzer = CrossPlatformAnalyzer(tmp_path, Platform.ANDROID)
            findings = analyzer.analyze()
            assert "flutter" in analyzer.detected_frameworks
            # Should find SharedPreferences finding
            sp_findings = [f for f in findings if "SharedPreferences" in f.title]
            assert len(sp_findings) >= 1

    def test_react_native_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Create React Native markers
            (tmp_path / "index.android.bundle").write_text("// RN bundle")

            # Create JS file with AsyncStorage
            (tmp_path / "storage.js").write_text('''
import AsyncStorage from '@react-native-async-storage/async-storage';

const getToken = async () => {
  return await AsyncStorage.getItem('auth_token');
};
''')
            analyzer = CrossPlatformAnalyzer(tmp_path, Platform.ANDROID)
            findings = analyzer.analyze()
            assert "react_native" in analyzer.detected_frameworks