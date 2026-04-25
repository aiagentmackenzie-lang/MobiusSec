"""Cross-platform framework analysis — Flutter, React Native, Kotlin Multiplatform."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from mobiussec import MASVS_CODE, MASVS_PLATFORM, MASVS_RESILIENCE
from mobiussec.models import Finding, Severity, Platform


# Flutter/Dart security patterns
FLUTTER_PATTERNS = [
    (r"SharedPreferences", "SharedPreferences usage — data stored in plain XML on Android", Severity.MEDIUM, "STORAGE"),
    (r"flutter_secure_storage", "flutter_secure_storage used — verify encryption key management", Severity.INFO, "STORAGE"),
    (r"\.getString\(", "getString call — may read from unencrypted SharedPreferences", Severity.LOW, "STORAGE"),
    (r"http\.get\(|http\.post\(", "HTTP request — verify TLS enforcement (no HTTP URLs)", Severity.MEDIUM, "NETWORK"),
    (r"http://", "HTTP URL in source — no TLS, vulnerable to MITM", Severity.HIGH, "NETWORK"),
    (r"Dio\(\)", "Dio HTTP client — verify TLS configuration and certificate pinning", Severity.INFO, "NETWORK"),
    (r"dart:io.*Platform", "Platform detection — verify no conditional insecure behavior", Severity.LOW, "PLATFORM"),
    (r"SystemChrome\.setApplicationSwitchesDescription", "App switcher content — may leak sensitive data in recents", Severity.LOW, "STORAGE"),
    (r"Clipboard\.setData\(", "Clipboard write — data accessible to other apps", Severity.MEDIUM, "STORAGE"),
    (r"WebView\(", "WebView usage — verify JavaScript is disabled if not needed", Severity.MEDIUM, "PLATFORM"),
    (r"evalJavaScript\(|evaluateJavascript\(", "JavaScript evaluation in WebView — XSS risk", Severity.HIGH, "PLATFORM"),
    (r"print\(", "Debug print statement — may leak sensitive data", Severity.INFO, "CODE"),
    (r"debugPrint\(", "Debug print — should be stripped in release builds", Severity.INFO, "CODE"),
    (r"InsecureWebSocket\(", "Insecure WebSocket — no TLS, vulnerable to MITM", Severity.HIGH, "NETWORK"),
    (r"WebSocket\.connect\(", "WebSocket connection — verify wss:// protocol is used", Severity.MEDIUM, "NETWORK"),
]

# React Native security patterns
REACT_NATIVE_PATTERNS = [
    (r"AsyncStorage\.getItem\(", "AsyncStorage read — data stored unencrypted on device", Severity.MEDIUM, "STORAGE"),
    (r"AsyncStorage\.setItem\(", "AsyncStorage write — data stored unencrypted on device", Severity.MEDIUM, "STORAGE"),
    (r"SensitiveInfo", "react-native-sensitive-info used — good, but verify keychain/keystore usage", Severity.INFO, "STORAGE"),
    (r"fetch\([\"']http://", "HTTP fetch — no TLS, vulnerable to MITM", Severity.HIGH, "NETWORK"),
    (r"XMLHttpRequest", "XMLHttpRequest — verify TLS enforcement", Severity.MEDIUM, "NETWORK"),
    (r"__DEV__", "DEV mode flag — should be false in production builds", Severity.LOW, "RESILIENCE"),
    (r"console\.log\(|console\.warn\(|console\.error\(", "Console logging — should be stripped in production", Severity.INFO, "CODE"),
    (r"react-native-webview", "WebView component — verify JavaScript is disabled if not needed", Severity.MEDIUM, "PLATFORM"),
    (r"injectedJavaScript", "JavaScript injection in WebView — XSS risk", Severity.HIGH, "PLATFORM"),
    (r"allowFileAccessFromFileURLs", "File URL access in WebView — local file theft risk", Severity.HIGH, "PLATFORM"),
    (r"Clipboard\.getString\(|Clipboard\.setString\(", "Clipboard access — data accessible to other apps", Severity.MEDIUM, "STORAGE"),
    (r"PermissionsAndroid\.request\(", "Android permission request — verify minimal permissions", Severity.LOW, "PRIVACY"),
    (r"Geolocation\.getCurrentPosition\(", "Location access — verify user consent and necessity", Severity.MEDIUM, "PRIVACY"),
    (r"CameraRoll\.", "Camera/media access — verify user consent", Severity.MEDIUM, "PRIVACY"),
    (r"Linking\.openURL\(", "Deep link handling — verify URL validation", Severity.MEDIUM, "PLATFORM"),
]

# Framework detection markers
FRAMEWORK_MARKERS = {
    "flutter": {
        "android": ["libflutter.so", "flutter_assets/", "kernel_blob.bin", "app.flx"],
        "ios": ["Flutter.framework", "App.framework", "flutter_assets/"],
        "source": [".dart"],
    },
    "react_native": {
        "android": ["libreactnativejni.so", "react_native/", "index.android.bundle"],
        "ios": ["React.framework", "index.ios.bundle", "main.jsbundle"],
        "source": [".jsx", ".tsx"],
    },
    "kotlin_multiplatform": {
        "android": ["kotlinx/", "kotlinx-coroutines"],
        "ios": [],
        "source": [],
    },
}


class CrossPlatformAnalyzer:
    """Analyze cross-platform frameworks (Flutter, React Native, Kotlin Multiplatform)."""

    def __init__(self, extracted_dir: Path, platform: Platform) -> None:
        self.extracted_dir = extracted_dir
        self.platform = platform
        self.findings: list[Finding] = []
        self.detected_frameworks: list[str] = []

    def analyze(self) -> list[Finding]:
        """Detect and analyze cross-platform frameworks."""
        self.findings = []
        self.detected_frameworks = []

        self._detect_frameworks()
        self._analyze_framework_code()

        return self.findings

    def _detect_frameworks(self) -> None:
        """Detect which cross-platform framework is used."""
        platform_key = self.platform.value

        for framework, markers in FRAMEWORK_MARKERS.items():
            platform_markers = markers.get(platform_key, [])
            source_markers = markers.get("source", [])

            # Check for binary/asset markers
            for marker in platform_markers:
                for f in self.extracted_dir.rglob("*"):
                    if marker in str(f):
                        self.detected_frameworks.append(framework)
                        break

            # Check for source markers
            for ext in source_markers:
                if any(self.extracted_dir.rglob(f"*{ext}")):
                    if framework not in self.detected_frameworks:
                        self.detected_frameworks.append(framework)

    def _analyze_framework_code(self) -> None:
        """Run framework-specific security analysis."""
        if "flutter" in self.detected_frameworks:
            self._analyze_flutter()
        if "react_native" in self.detected_frameworks:
            self._analyze_react_native()

    def _analyze_flutter(self) -> None:
        """Analyze Flutter/Dart source for security issues."""
        source_files = list(self.extracted_dir.rglob("*.dart"))

        if source_files:
            self.findings.append(Finding(
                id="XPLAT-FLUTTER-001",
                title="Flutter framework detected",
                description="App is built with Flutter. Cross-platform apps may have framework-specific security considerations.",
                severity=Severity.INFO,
                masvs_category=MASVS_CODE,
                platform=self.platform,
                remediation="Ensure Flutter security best practices are followed. Use flutter_secure_storage for sensitive data.",
            ))

        seen_ids: set[str] = set()
        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))

                for pattern, desc, severity, category in FLUTTER_PATTERNS:
                    if re.search(pattern, content):
                        # Generate unique ID using pattern + relative path hash
                        unique_hash = hashlib.md5(f"{pattern}:{rel_path}".encode()).hexdigest()[:8]
                        finding_id = f"FLUTTER-{pattern[:10].replace('(', '').replace('.', '-')}-{unique_hash}"
                        if finding_id in seen_ids:
                            continue
                        seen_ids.add(finding_id)
                        self.findings.append(Finding(
                            id=finding_id,
                            title=f"Flutter: {desc}",
                            description=f"Found in {rel_path}. {desc}.",
                            severity=severity,
                            masvs_category=category,
                            masvs_test_id=f"MASTG-{category}-1",
                            platform=self.platform,
                            file=rel_path,
                            remediation=self._get_flutter_remediation(pattern),
                        ))
                        break  # One finding per file per pattern type
            except Exception:
                continue

    def _analyze_react_native(self) -> None:
        """Analyze React Native source for security issues."""
        source_files = (
            list(self.extracted_dir.rglob("*.js"))
            + list(self.extracted_dir.rglob("*.jsx"))
            + list(self.extracted_dir.rglob("*.ts"))
            + list(self.extracted_dir.rglob("*.tsx"))
        )

        self.findings.append(Finding(
            id="XPLAT-RN-001",
            title="React Native framework detected",
            description="App is built with React Native. JavaScript bundle can be extracted and analyzed.",
            severity=Severity.MEDIUM,
            masvs_category=MASVS_RESILIENCE,
            masvs_test_id="MASTG-RESILIENCE-5",
            platform=self.platform,
            remediation="Enable Hermes engine with code obfuscation. Strip console logs in production. Use react-native-sensitive-info for secure storage.",
        ))

        seen_ids: set[str] = set()
        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))

                for pattern, desc, severity, category in REACT_NATIVE_PATTERNS:
                    if re.search(pattern, content):
                        unique_hash = hashlib.md5(f"{pattern}:{rel_path}".encode()).hexdigest()[:8]
                        finding_id = f"RN-{pattern[:10].replace('(', '').replace('.', '-')}-{unique_hash}"
                        if finding_id in seen_ids:
                            continue
                        seen_ids.add(finding_id)
                        self.findings.append(Finding(
                            id=finding_id,
                            title=f"React Native: {desc}",
                            description=f"Found in {rel_path}. {desc}.",
                            severity=severity,
                            masvs_category=category,
                            masvs_test_id=f"MASTG-{category}-1",
                            platform=self.platform,
                            file=rel_path,
                            remediation=self._get_rn_remediation(pattern),
                        ))
                        break
            except Exception:
                continue

    @staticmethod
    def _get_flutter_remediation(pattern: str) -> str:
        """Get Flutter-specific remediation."""
        remedies = {
            "SharedPreferences": "Use flutter_secure_storage instead of shared_preferences for sensitive data.",
            "http://": "Use HTTPS for all network communication. Configure proper TLS.",
            "Clipboard": "Avoid copying sensitive data to clipboard. Use in-app secure pasteboard.",
            "WebView": "Disable JavaScript if not needed. Never allow file:// URLs in WebView.",
            "evalJavaScript": "Validate all JavaScript before evaluation. Use allow-list for allowed functions.",
            "print(": "Remove debug prints in release builds. Use kReleaseMode conditional.",
        }
        for key, remedy in remedies.items():
            if key in pattern:
                return remedy
        return "Review Flutter security best practices at https://docs.flutter.dev/security/overview"

    @staticmethod
    def _get_rn_remediation(pattern: str) -> str:
        """Get React Native-specific remediation."""
        remedies = {
            "AsyncStorage": "Use react-native-sensitive-info or expo-secure-store for sensitive data.",
            "http://": "Use HTTPS for all fetch/XMLHttpRequest calls.",
            "console.": "Use babel-plugin-transform-remove-console to strip console logs in production.",
            "injectedJavaScript": "Validate and sanitize all injected JavaScript. Never inject user-controlled content.",
            "Clipboard": "Avoid clipboard for sensitive data. Implement in-app copy if needed.",
            "__DEV__": "Ensure __DEV__ is false in production builds. Verify Metro bundler configuration.",
        }
        for key, remedy in remedies.items():
            if key in pattern:
                return remedy
        return "Review React Native security best practices at https://reactnative.dev/docs/security"