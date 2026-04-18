"""Tests for SBOM generator."""

import tempfile
from pathlib import Path

import pytest

from mobiussec.sbom_generator import SBOMGenerator, ANDROID_LIB_SIGNATURES, IOS_LIB_SIGNATURES
from mobiussec.models import Platform


class TestSBOMGenerator:
    def test_android_lib_signatures(self):
        assert len(ANDROID_LIB_SIGNATURES) >= 20
        # Check a few key libraries
        assert "com.google.firebase" in ANDROID_LIB_SIGNATURES
        assert "okhttp3" in ANDROID_LIB_SIGNATURES
        assert "retrofit2" in ANDROID_LIB_SIGNATURES

    def test_ios_lib_signatures(self):
        assert len(IOS_LIB_SIGNATURES) >= 15
        assert "Alamofire" in IOS_LIB_SIGNATURES
        assert "Kingfisher" in IOS_LIB_SIGNATURES

    def test_empty_android_sbom(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            gen = SBOMGenerator(tmp_path, Platform.ANDROID)
            sbom = gen.generate()

            assert sbom["bomFormat"] == "CycloneDX"
            assert "components" in sbom
            assert "metadata" in sbom

    def test_empty_ios_sbom(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            gen = SBOMGenerator(tmp_path, Platform.IOS)
            sbom = gen.generate()

            assert sbom["specVersion"] == "1.6"
            assert "components" in sbom

    def test_sbom_with_android_smali(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Create a fake smali tree with Firebase
            firebase_dir = tmp_path / "smali" / "com" / "google" / "firebase"
            firebase_dir.mkdir(parents=True)
            (firebase_dir / "FirebaseApp.smali").write_text(".class public FirebaseApp")

            okhttp_dir = tmp_path / "smali" / "okhttp3"
            okhttp_dir.mkdir(parents=True)
            (okhttp_dir / "OkHttpClient.smali").write_text(".class public OkHttpClient")

            gen = SBOMGenerator(tmp_path, Platform.ANDROID)
            sbom = gen.generate()

            component_names = [c["name"] for c in sbom["components"]]
            assert "Firebase" in component_names
            assert "OkHttp" in component_names