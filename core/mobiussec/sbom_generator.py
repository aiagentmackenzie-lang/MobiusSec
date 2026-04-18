"""SBOM generator — Software Bill of Materials from mobile binaries."""

from __future__ import annotations

import re
import plistlib
import json
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

from mobiussec import MASVS_CODE
from mobiussec.models import Finding, Severity, Platform


# Known library signatures for Android (from classes.dex, JARs, AARs)
ANDROID_LIB_SIGNATURES: dict[str, dict[str, str]] = {
    "com.google.firebase": {"name": "Firebase", "category": "analytics", "ecosystem": "maven"},
    "com.google.android.gms": {"name": "Google Play Services", "category": "platform", "ecosystem": "maven"},
    "com.google.android.material": {"name": "Material Design", "category": "ui", "ecosystem": "maven"},
    "androidx.appcompat": {"name": "AndroidX AppCompat", "category": "ui", "ecosystem": "maven"},
    "androidx.core": {"name": "AndroidX Core", "category": "ui", "ecosystem": "maven"},
    "androidx.constraintlayout": {"name": "ConstraintLayout", "category": "ui", "ecosystem": "maven"},
    "androidx.recyclerview": {"name": "RecyclerView", "category": "ui", "ecosystem": "maven"},
    "androidx.viewpager": {"name": "ViewPager", "category": "ui", "ecosystem": "maven"},
    "androidx.lifecycle": {"name": "Lifecycle", "category": "architecture", "ecosystem": "maven"},
    "androidx.room": {"name": "Room", "category": "database", "ecosystem": "maven"},
    "androidx.work": {"name": "WorkManager", "category": "background", "ecosystem": "maven"},
    "androidx.navigation": {"name": "Navigation", "category": "architecture", "ecosystem": "maven"},
    "io.reactivex": {"name": "RxJava", "category": "async", "ecosystem": "maven"},
    "io.reactivex.rxjava3": {"name": "RxJava 3", "category": "async", "ecosystem": "maven"},
    "okhttp3": {"name": "OkHttp", "category": "network", "ecosystem": "maven"},
    "okio": {"name": "OkIO", "category": "network", "ecosystem": "maven"},
    "retrofit2": {"name": "Retrofit", "category": "network", "ecosystem": "maven"},
    "com.squareup.picasso": {"name": "Picasso", "category": "image", "ecosystem": "maven"},
    "com.squareup.leakcanary": {"name": "LeakCanary", "category": "debug", "ecosystem": "maven"},
    "com.github.bumptech.glide": {"name": "Glide", "category": "image", "ecosystem": "maven"},
    "io.coil": {"name": "Coil", "category": "image", "ecosystem": "maven"},
    "dagger": {"name": "Dagger", "category": "di", "ecosystem": "maven"},
    "dagger.hilt": {"name": "Hilt", "category": "di", "ecosystem": "maven"},
    "org.jetbrains.kotlin": {"name": "Kotlin Stdlib", "category": "language", "ecosystem": "maven"},
    "kotlinx.coroutines": {"name": "Kotlin Coroutines", "category": "async", "ecosystem": "maven"},
    "kotlinx.serialization": {"name": "Kotlin Serialization", "category": "serialization", "ecosystem": "maven"},
    "com.google.code.gson": {"name": "Gson", "category": "serialization", "ecosystem": "maven"},
    "com.fasterxml.jackson": {"name": "Jackson", "category": "serialization", "ecosystem": "maven"},
    "io.ktor": {"name": "Ktor", "category": "network", "ecosystem": "maven"},
    "org.greenrobot.eventbus": {"name": "EventBus", "category": "event", "ecosystem": "maven"},
    "com.jakewharton": {"name": "JakeWharton Libraries", "category": "utility", "ecosystem": "maven"},
    "io.objectbox": {"name": "ObjectBox", "category": "database", "ecosystem": "maven"},
    "io.realm": {"name": "Realm", "category": "database", "ecosystem": "maven"},
    "net.sqlcipher": {"name": "SQLCipher", "category": "database", "ecosystem": "maven"},
    "org.chromium": {"name": "Chromium WebView", "category": "webview", "ecosystem": "maven"},
}

# Known library signatures for iOS (from frameworks, dylibs)
IOS_LIB_SIGNATURES: dict[str, dict[str, str]] = {
    "Alamofire": {"name": "Alamofire", "category": "network", "ecosystem": "cocoapods"},
    "Kingfisher": {"name": "Kingfisher", "category": "image", "ecosystem": "cocoapods"},
    "SwiftyJSON": {"name": "SwiftyJSON", "category": "serialization", "ecosystem": "cocoapods"},
    "SnapKit": {"name": "SnapKit", "category": "ui", "ecosystem": "cocoapods"},
    "RxSwift": {"name": "RxSwift", "category": "async", "ecosystem": "cocoapods"},
    "RxCocoa": {"name": "RxCocoa", "category": "ui", "ecosystem": "cocoapods"},
    "Moya": {"name": "Moya", "category": "network", "ecosystem": "cocoapods"},
    "MBProgressHUD": {"name": "MBProgressHUD", "category": "ui", "ecosystem": "cocoapods"},
    "SVProgressHUD": {"name": "SVProgressHUD", "category": "ui", "ecosystem": "cocoapods"},
    "AFNetworking": {"name": "AFNetworking", "category": "network", "ecosystem": "cocoapods"},
    "SDWebImage": {"name": "SDWebImage", "category": "image", "ecosystem": "cocoapods"},
    "Lottie": {"name": "Lottie", "category": "animation", "ecosystem": "cocoapods"},
    "Charts": {"name": "Charts", "category": "ui", "ecosystem": "cocoapods"},
    "FirebaseAnalytics": {"name": "Firebase Analytics", "category": "analytics", "ecosystem": "cocoapods"},
    "FirebaseCore": {"name": "Firebase Core", "category": "analytics", "ecosystem": "cocoapods"},
    "Crashlytics": {"name": "Crashlytics", "category": "crash", "ecosystem": "cocoapods"},
    "Sentry": {"name": "Sentry", "category": "crash", "ecosystem": "cocoapods"},
    "GoogleSignIn": {"name": "Google Sign-In", "category": "auth", "ecosystem": "cocoapods"},
    "FBSDKCoreKit": {"name": "Facebook SDK", "category": "social", "ecosystem": "cocoapods"},
    "FBSDKLoginKit": {"name": "Facebook Login", "category": "social", "ecosystem": "cocoapods"},
    "RealmSwift": {"name": "Realm", "category": "database", "ecosystem": "cocoapods"},
    "SQLCipher": {"name": "SQLCipher", "category": "database", "ecosystem": "cocoapods"},
    "CryptoSwift": {"name": "CryptoSwift", "category": "crypto", "ecosystem": "cocoapods"},
    "KeychainAccess": {"name": "KeychainAccess", "category": "storage", "ecosystem": "cocoapods"},
    "SwiftKeychainWrapper": {"name": "SwiftKeychainWrapper", "category": "storage", "ecosystem": "cocoapods"},
    "Reachability": {"name": "Reachability", "category": "network", "ecosystem": "cocoapods"},
    "SwiftyStoreKit": {"name": "SwiftyStoreKit", "category": "payment", "ecosystem": "cocoapods"},
    "RevenueCat": {"name": "RevenueCat", "category": "payment", "ecosystem": "cocoapods"},
    "WebKit": {"name": "WebKit", "category": "webview", "ecosystem": "system"},
}

# Version extraction patterns
VERSION_PATTERNS = [
    r"version[\"':\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    r"v([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    r"_([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
]


class SBOMGenerator:
    """Generates a Software Bill of Materials from mobile app binaries."""

    def __init__(self, extracted_dir: Path, platform: Platform) -> None:
        self.extracted_dir = extracted_dir
        self.platform = platform
        self.components: list[dict[str, Any]] = []
        self.findings: list[Finding] = []

    def generate(self) -> dict[str, Any]:
        """Generate SBOM and return as dict (CycloneDX-compatible)."""
        self.components = []
        self.findings = []

        if self.platform == Platform.ANDROID:
            self._scan_android()
        elif self.platform == Platform.IOS:
            self._scan_ios()

        sbom = self._build_cyclonedx()
        return sbom

    def _scan_android(self) -> None:
        """Scan Android APK for third-party libraries."""
        # 1. Scan smali directories for package references
        smali_dirs = list(self.extracted_dir.glob("smali*"))
        for smali_dir in smali_dirs:
            self._scan_smali_tree(smali_dir)

        # 2. Scan lib/ for native libraries
        lib_dir = self.extracted_dir / "lib"
        if lib_dir.exists():
            self._scan_native_libs(lib_dir)

        # 3. Scan for JAR/AAR files
        for ext in ["*.jar", "*.aar"]:
            for f in self.extracted_dir.rglob(ext):
                self._add_component(
                    name=f.stem,
                    version="",
                    category="library",
                    ecosystem="maven",
                    path=str(f.relative_to(self.extracted_dir)),
                )

        # 4. Check assets/ for bundled resources
        assets_dir = self.extracted_dir / "assets"
        if assets_dir.exists():
            self._scan_assets(assets_dir)

    def _scan_smali_tree(self, smali_dir: Path) -> None:
        """Scan smali directories for known library packages."""
        found_packages: set[str] = set()

        for dir_path in smali_dir.rglob("*"):
            if not dir_path.is_dir():
                continue
            # Convert directory path to package name (e.g., com/google/firebase -> com.google.firebase)
            rel = dir_path.relative_to(smali_dir)
            parts = list(rel.parts)
            package = ".".join(parts)

            for sig, info in ANDROID_LIB_SIGNATURES.items():
                if package.startswith(sig) and sig not in found_packages:
                    found_packages.add(sig)
                    version = self._find_version_for_package(dir_path)
                    self._add_component(
                        name=info["name"],
                        version=version,
                        category=info["category"],
                        ecosystem=info["ecosystem"],
                        path=str(dir_path.relative_to(self.extracted_dir)),
                        purl=f"pkg:{info['ecosystem']}/{sig.replace('.', '/')}/{info['name']}@{version}" if version else f"pkg:{info['ecosystem']}/{sig.replace('.', '/')}/{info['name']}",
                    )

    def _scan_native_libs(self, lib_dir: Path) -> None:
        """Scan native .so libraries."""
        for arch_dir in lib_dir.iterdir():
            if not arch_dir.is_dir():
                continue
            for so_file in arch_dir.glob("*.so"):
                self._add_component(
                    name=so_file.stem,
                    version=self._extract_version_from_binary(so_file),
                    category="native",
                    ecosystem="native",
                    path=str(so_file.relative_to(self.extracted_dir)),
                )

    def _scan_assets(self, assets_dir: Path) -> None:
        """Scan assets for bundled content."""
        for f in assets_dir.rglob("*"):
            if f.is_file() and f.suffix in (".js", ".json", ".html"):
                # Check for known JS libraries
                try:
                    content = f.read_text(errors="ignore")[:10_000]
                    js_libs = {
                        "react-native": "React Native",
                        "cordova": "Apache Cordova",
                        "capacitor": "Capacitor (Ionic)",
                        "flutter.js": "Flutter Web",
                    }
                    for sig, name in js_libs.items():
                        if sig in content.lower():
                            already = any(c["name"] == name for c in self.components)
                            if not already:
                                self._add_component(
                                    name=name,
                                    version="",
                                    category="framework",
                                    ecosystem="npm",
                                    path=str(f.relative_to(self.extracted_dir)),
                                )
                except Exception:
                    continue

    def _scan_ios(self) -> None:
        """Scan iOS .app bundle for frameworks and libraries."""
        # 1. Scan Frameworks/ directory
        frameworks_dir = self.extracted_dir / "Frameworks"
        if frameworks_dir.exists():
            for framework in frameworks_dir.glob("*.framework"):
                name = framework.stem
                version = self._extract_version_from_framework(framework)

                # Match against known signatures
                lib_info = IOS_LIB_SIGNATURES.get(name, {"category": "library", "ecosystem": "cocoapods"})
                self._add_component(
                    name=name,
                    version=version,
                    category=lib_info.get("category", "library"),
                    ecosystem=lib_info.get("ecosystem", "cocoapods"),
                    path=str(framework.relative_to(self.extracted_dir)),
                    purl=f"pkg:cocoapods/{name}@{version}" if version else f"pkg:cocoapods/{name}",
                )

            # Also scan for .dylib files
            for dylib in frameworks_dir.glob("*.dylib"):
                self._add_component(
                    name=dylib.stem,
                    version="",
                    category="library",
                    ecosystem="native",
                    path=str(dylib.relative_to(self.extracted_dir)),
                )

        # 2. Scan for Swift dylibs (Xcode bundled)
        swift_dir = self.extracted_dir / "Frameworks" / "libswift"
        if not swift_dir.exists():
            # Check for swift libs in the app itself
            for child in self.extracted_dir.iterdir():
                if child.name.startswith("libswift") and child.suffix == ".dylib":
                    self._add_component(
                        name=child.stem,
                        version="",
                        category="language",
                        ecosystem="system",
                        path=str(child.relative_to(self.extracted_dir)),
                    )

        # 3. Check for CocoaPods acknowledgement file
        pods_file = self.extracted_dir / "Pods-acknowledgements.plist"
        if pods_file.exists():
            self._parse_cocoapods_ack(pods_file)

    def _parse_cocoapods_ack(self, plist_path: Path) -> None:
        """Parse CocoaPods acknowledgements plist for library list."""
        try:
            with open(plist_path, "rb") as f:
                data = plistlib.loads(f.read())
            prefs = data.get("PreferenceSpecifiers", [])
            for pref in prefs:
                title = pref.get("Title", "")
                if title and not any(c["name"] == title for c in self.components):
                    self._add_component(
                        name=title,
                        version="",
                        category="library",
                        ecosystem="cocoapods",
                        path="Pods-acknowledgements.plist",
                    )
        except Exception:
            pass

    def _find_version_for_package(self, package_dir: Path) -> str:
        """Try to find version string for a package from smali files."""
        for smali_file in package_dir.rglob("*.smali"):
            try:
                content = smali_file.read_text(errors="ignore")[:5_000]
                for pattern in VERSION_PATTERNS:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        return match.group(1)
            except Exception:
                continue
        return ""

    def _extract_version_from_binary(self, binary_path: Path) -> str:
        """Try to extract version from a binary using strings."""
        import subprocess
        try:
            result = subprocess.run(
                ["strings", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    for pattern in VERSION_PATTERNS:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match and any(kw in line.lower() for kw in ["version", "ver", "release"]):
                            return match.group(1)
        except Exception:
            pass
        return ""

    def _extract_version_from_framework(self, framework_path: Path) -> str:
        """Extract version from iOS framework."""
        # Check Info.plist inside framework
        plist = framework_path / "Info.plist"
        if plist.exists():
            try:
                with open(plist, "rb") as f:
                    data = plistlib.loads(f.read())
                return data.get("CFBundleShortVersionString", data.get("CFBundleVersion", ""))
            except Exception:
                pass
        return ""

    def _add_component(
        self,
        name: str,
        version: str,
        category: str,
        ecosystem: str,
        path: str,
        purl: str = "",
    ) -> None:
        """Add a component to the SBOM."""
        component = {
            "name": name,
            "version": version,
            "category": category,
            "ecosystem": ecosystem,
            "path": path,
            "purl": purl,
        }
        self.components.append(component)

    def _build_cyclonedx(self) -> dict[str, Any]:
        """Build a CycloneDX-format SBOM."""
        components = []
        for comp in self.components:
            c: dict[str, Any] = {
                "type": "library",
                "name": comp["name"],
                "version": comp["version"] or "unknown",
            }
            if comp["purl"]:
                c["purl"] = comp["purl"]
            if comp["ecosystem"]:
                c["group"] = comp["ecosystem"]
            components.append(c)

        sbom = {
            "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "serialNumber": f"urn:uuid:{self._generate_uuid()}",
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "MobiusSec",
                        "name": "mobiussec",
                        "version": "0.1.0",
                    }
                ],
                "component": {
                    "type": "application",
                    "name": "scanned-app",
                },
            },
            "components": components,
        }

        return sbom

    @staticmethod
    def _generate_uuid() -> str:
        """Generate a UUID4 string."""
        import uuid
        return str(uuid.uuid4())