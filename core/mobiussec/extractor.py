"""APK and IPA extraction and parsing."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

import plistlib  # noqa: F401 — used at runtime


class Extractor:
    """Extracts and parses mobile app files (APK/IPA)."""

    def __init__(self, app_path: Path, work_dir: Path | None = None) -> None:
        self.app_path = app_path
        self.work_dir = work_dir or Path(tempfile.mkdtemp(prefix="mobiussec_"))
        self.extracted_dir: Path | None = None
        self._platform: str | None = None

    @property
    def platform(self) -> str:
        """Detect platform from file extension."""
        if self._platform:
            return self._platform
        name = self.app_path.name.lower()
        if name.endswith(".apk"):
            self._platform = "android"
        elif name.endswith(".ipa"):
            self._platform = "ios"
        else:
            self._platform = "unknown"
        return self._platform

    def extract(self) -> Path:
        """Extract the app file and return the extraction directory."""
        if self.platform == "android":
            return self._extract_apk()
        elif self.platform == "ios":
            return self._extract_ipa()
        else:
            raise ValueError(f"Unsupported file type: {self.app_path.suffix}")

    def _extract_apk(self) -> Path:
        """Extract APK using apktool (preferred) or fallback to zipfile."""
        output_dir = self.work_dir / "apk_extracted"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Try apktool first for better decompilation
        if shutil.which("apktool"):
            try:
                result = subprocess.run(
                    ["apktool", "d", "-f", "-o", str(output_dir), str(self.app_path)],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode == 0:
                    self.extracted_dir = output_dir
                    return output_dir
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Fallback: treat APK as ZIP
        return self._extract_zip(self.app_path, output_dir)

    def _extract_ipa(self) -> Path:
        """Extract IPA (which is a ZIP file) and locate the .app bundle."""
        output_dir = self.work_dir / "ipa_extracted"
        output_dir.mkdir(parents=True, exist_ok=True)

        self._extract_zip(self.app_path, output_dir)

        # Find the .app bundle inside Payload/
        payload_dir = output_dir / "Payload"
        if payload_dir.exists():
            app_bundles = list(payload_dir.glob("*.app"))
            if app_bundles:
                self.extracted_dir = app_bundles[0]
                return app_bundles[0]

        self.extracted_dir = output_dir
        return output_dir

    def _extract_zip(self, archive: Path, dest: Path) -> Path:
        """Extract a ZIP/APK/IPA file."""
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(dest)
        self.extracted_dir = dest
        return dest

    def get_android_manifest(self) -> Path | None:
        """Get path to AndroidManifest.xml."""
        if not self.extracted_dir:
            return None
        manifest = self.extracted_dir / "AndroidManifest.xml"
        return manifest if manifest.exists() else None

    def get_info_plist(self) -> Path | None:
        """Get path to Info.plist from extracted iOS app."""
        if not self.extracted_dir:
            return None
        plist = self.extracted_dir / "Info.plist"
        if plist.exists():
            return plist
        # Sometimes in a subdirectory
        for p in self.extracted_dir.rglob("Info.plist"):
            return p
        return None

    def get_entitlements_plist(self) -> Path | None:
        """Get path to embedded entitlements plist."""
        if not self.extracted_dir:
            return None
        for name in ["embedded.mobileprovision", "Entitlements.plist"]:
            for p in self.extracted_dir.rglob(name):
                return p
        return None

    def get_binary_path(self) -> Path | None:
        """Get the main executable binary from extracted app."""
        if not self.extracted_dir:
            return None
        if self.platform == "ios":
            # Main binary has same name as .app bundle (without .app)
            app_name = self.extracted_dir.stem if self.extracted_dir.suffix == ".app" else ""
            if app_name:
                binary = self.extracted_dir / app_name
                if binary.exists() and not binary.is_dir():
                    return binary
            # Search for Mach-O binaries
            for child in self.extracted_dir.iterdir():
                if not child.is_dir() and not child.suffix:
                    return child
        elif self.platform == "android":
            # Look for DEX files or lib directory
            classes_dex = self.extracted_dir / "classes.dex"
            if classes_dex.exists():
                return classes_dex
            lib_dir = self.extracted_dir / "lib"
            if lib_dir.exists():
                return lib_dir
        return None

    def get_resource_files(self) -> list[Path]:
        """Get all resource/layout XML files (Android) or nib/storyboard files (iOS)."""
        if not self.extracted_dir:
            return []
        if self.platform == "android":
            res_dir = self.extracted_dir / "res"
            if res_dir.exists():
                return list(res_dir.rglob("*.xml"))
        return []

    def get_source_files(self) -> list[Path]:
        """Get decompiled source files."""
        if not self.extracted_dir:
            return []
        sources: list[Path] = []
        for pattern in ["*.java", "*.smali", "*.kt", "*.swift", "*.m", "*.h"]:
            sources.extend(self.extracted_dir.rglob(pattern))
        return sources

    def cleanup(self) -> None:
        """Remove extraction directory."""
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)

    def parse_plist(self, plist_path: Path) -> dict:
        """Parse a plist file and return as dict."""
        try:
            with open(plist_path, "rb") as f:
                return plistlib.loads(f.read())
        except Exception:
            # Try biplist for binary plists
            try:
                import biplist
                return biplist.readPlist(str(plist_path))
            except ImportError:
                return {}

    def parse_xml(self, xml_path: Path) -> object:
        """Parse an XML file using lxml (falls back to stdlib xml.etree)."""
        try:
            from lxml import etree as _etree
            return _etree.parse(str(xml_path))
        except ImportError:
            # Fallback to stdlib xml.etree.ElementTree
            import xml.etree.ElementTree as ET
            try:
                return ET.parse(str(xml_path))
            except Exception:
                return None
        except Exception:
            return None