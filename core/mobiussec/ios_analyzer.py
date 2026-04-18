"""iOS static analysis module."""

from __future__ import annotations

import plistlib
import re
import subprocess
import shutil
from pathlib import Path
from typing import Any

from mobiussec import (
    MASVS_STORAGE,
    MASVS_CRYPTO,
    MASVS_NETWORK,
    MASVS_PLATFORM,
    MASVS_AUTH,
    MASVS_CODE,
    MASVS_RESILIENCE,
    MASVS_PRIVACY,
)
from mobiussec.models import Finding, Severity, Platform


# ATS (App Transport Security) risk indicators
ATS_RISK_KEYS = {
    "NSAllowsArbitraryLoads": "Allows all HTTP connections — no TLS enforcement",
    "NSAllowsArbitraryLoadsInWebContent": "Allows HTTP in web content — mixed content risk",
    "NSAllowsLocalNetworking": "Allows local network HTTP — man-in-the-middle risk on shared networks",
    "NSAllowsArbitraryLoadsForMedia": "Allows HTTP for media — unencrypted media streams",
    "NSAllowsArbitraryLoadsForImage": "Allows HTTP for images — unencrypted image loading",
}

# Insecure Keychain protection classes
INSECURE_KEYCHAIN_CLASSES = {
    "kSecAttrAccessibleAlways": "Keychain accessible always — even with device locked",
    "kSecAttrAccessibleAlwaysThisDeviceOnly": "Accessible always (device-only) — still accessible when locked",
    "kSecAttrAccessibleAfterFirstUnlock": "Accessible after first unlock — available in background",
    "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly": "After first unlock (device-only) — available in background",
}

# Required privacy description keys (iOS 10+)
PRIVACY_DESCRIPTION_KEYS = {
    "NSCameraUsageDescription": "Camera access",
    "NSMicrophoneUsageDescription": "Microphone access",
    "NSLocationWhenInUseUsageDescription": "Location (when in use)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Location (always + when in use)",
    "NSLocationAlwaysUsageDescription": "Location (always) — deprecated, use WhenInUse + AlwaysAndWhenInUse",
    "NSPhotoLibraryUsageDescription": "Photo library access",
    "NSContactsUsageDescription": "Contacts access",
    "NSCalendarsUsageDescription": "Calendar access",
    "NSRemindersUsageDescription": "Reminders access",
    "NSAppleMusicUsageDescription": "Apple Music access",
    "NSMotionUsageDescription": "Motion/fitness data",
    "NSHealthClinicalHealthRecordsShareDescription": "Health records sharing",
    "NSHealthShareDescription": "Health data sharing",
    "NSHealthUpdateDescription": "Health data updates",
    "NSHomeKitUsageDescription": "HomeKit access",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth (always)",
    "NSBluetoothPeripheralUsageDescription": "Bluetooth peripheral",
    "NSSiriUsageDescription": "Siri access",
    "NSSpeechRecognitionUsageDescription": "Speech recognition",
    "NSVideoSubscriberUsageDescription": "TV provider access",
    "NFCReaderUsageDescription": "NFC reading",
}

# Hardcoded secret patterns (Swift/ObjC)
SECRET_PATTERNS_IOS = [
    (r'(?i)(apiKey|api_key|apikey)\s*[=:]\s*["\'][^"\']{8,}', "Potential API key hardcoded"),
    (r'(?i)(secret|token|password|passwd)\s*[=:]\s*["\'][^"\']{8,}', "Potential secret/token hardcoded"),
    (r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*["\'][^"\']+', "AWS credentials hardcoded"),
    (r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', "Private key embedded in source"),
    (r'(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*', "Bearer token hardcoded"),
]

# Insecure crypto patterns (Swift/ObjC)
INSECURE_CRYPTO_IOS = [
    (r'CCAlgorithm\(kCCAlgorithmDES\)', "DES encryption — insecure, use AES"),
    (r'CCAlgorithm\(kCCAlgorithmRC[24]\)', "RC2/RC4 — insecure stream cipher"),
    (r'kCCAlgorithmRC4', "RC4 encryption — insecure"),
    (r'kCCModeECB', "ECB mode — deterministic, no diffusion"),
    (r'CCDigestAlgorithm\(kCCDigestMD5\)', "MD5 hash — cryptographically broken"),
    (r'CCDigestAlgorithm\(kCCDigestSHA1\)', "SHA-1 hash — vulnerable to collisions"),
    (r'\.md5\b', "MD5 used — cryptographically broken"),
    (r'\.sha1\b', "SHA-1 used — vulnerable to collisions"),
]

# Pasteboard (clipboard) risk patterns
PASTEBOARD_PATTERNS = [
    (r'UIPasteboard\.general', "General pasteboard used — sensitive data may leak to other apps"),
    (r'generalPasteboard\(\)', "General pasteboard accessed — clipboard data is shared system-wide"),
]

# Biometric auth risk patterns
BIOMETRIC_PATTERNS = [
    (r'LAContext\(\)', "Local Authentication used — verify biometric fallback is secure"),
    (r'evaluatePolicy\(.+LAPolicyDeviceOwnerAuthenticationWithBiometrics', "Biometric auth — ensure no weak PIN fallback"),
    (r'canEvaluatePolicy\(.+LAPolicyDeviceOwnerAuthenticationWithBiometrics', "Biometric check — ensure fallback is not insecure"),
    (r'kSecAccessControlTouchIDAny', "Touch ID access control — ensure proper fallback"),
    (r'kSecAccessControlTouchIDCurrentSet', "Touch ID current set — ensure proper fallback"),
]

# WebView risk patterns (iOS)
WEBVIEW_IOS_PATTERNS = [
    (r'WKWebView\(.*javaScriptEnabled.*true', "JavaScript enabled in WKWebView — XSS risk"),
    (r'UIWebView', "UIWebView is deprecated — use WKWebView"),
    (r'evaluateJavaScript\(', "JavaScript evaluation in WebView — potential injection point"),
    (r'loadFileURL\(', "File URL loaded in WebView — local file access risk"),
    (r'allowFileAccessFromFileURLs', "File URL access allowed in WebView — cross-origin risk"),
]


class iOSAnalyzer:
    """Static analysis for iOS IPA files."""

    def __init__(self, extracted_dir: Path) -> None:
        self.extracted_dir = extracted_dir
        self.findings: list[Finding] = []
        self._info_plist: dict[str, Any] = {}
        self._entitlements: dict[str, Any] = {}

    def analyze(self) -> list[Finding]:
        """Run all iOS analysis checks."""
        self.findings = []

        self._load_plist()
        self._check_ats_configuration()
        self._check_url_schemes()
        self._check_background_modes()
        self._check_privacy_descriptions()
        self._check_hardcoded_secrets()
        self._check_crypto_misuse()
        self._check_webview_issues()
        self._check_pasteboard_usage()
        self._check_biometric_auth()
        self._check_binary_strings()
        self._check_keychain_protection()
        self._check_entitlements()

        return self.findings

    def _load_plist(self) -> None:
        """Load Info.plist from extracted app."""
        plist_path = self._find_plist("Info.plist")
        if plist_path:
            self._info_plist = self._parse_plist(plist_path)

        # Load entitlements
        ent_path = self._find_plist("embedded.mobileprovision")
        if ent_path:
            self._entitlements = self._parse_embedded_provision(ent_path)

    def _find_plist(self, name: str) -> Path | None:
        """Find a plist file in the extracted directory."""
        for p in self.extracted_dir.rglob(name):
            return p
        return None

    def _parse_plist(self, path: Path) -> dict[str, Any]:
        """Parse a plist file."""
        try:
            with open(path, "rb") as f:
                return plistlib.loads(f.read())
        except Exception:
            try:
                import biplist
                return biplist.readPlist(str(path))
            except Exception:
                return {}

    def _parse_embedded_provision(self, path: Path) -> dict[str, Any]:
        """Parse entitlements from embedded.mobileprovision."""
        try:
            content = path.read_text(errors="ignore")
            # Extract the plist XML from the provisioning profile
            start = content.find("<?xml")
            end = content.find("</plist>") + len("</plist>")
            if start >= 0 and end > start:
                import io
                plist_data = plistlib.loads(content[start:end].encode())
                return plist_data.get("Entitlements", {})
        except Exception:
            pass
        return {}

    def _add_finding(
        self,
        id: str,
        title: str,
        description: str,
        severity: Severity,
        masvs_category: str,
        masvs_test_id: str = "",
        file: str = "",
        remediation: str = "",
    ) -> None:
        self.findings.append(Finding(
            id=id,
            title=title,
            description=description,
            severity=severity,
            masvs_category=masvs_category,
            masvs_test_id=masvs_test_id,
            platform=Platform.IOS,
            file=file,
            remediation=remediation,
        ))

    def _check_ats_configuration(self) -> None:
        """Check App Transport Security configuration."""
        ats = self._info_plist.get("NSAppTransportSecurity", {})
        if not ats:
            return

        for key, desc in ATS_RISK_KEYS.items():
            if ats.get(key, False):
                severity = Severity.HIGH if key == "NSAllowsArbitraryLoads" else Severity.MEDIUM
                self._add_finding(
                    f"IOS-ATS-{key}",
                    f"ATS bypass: {key}",
                    f"{desc}. This weakens TLS enforcement for network connections.",
                    severity,
                    MASVS_NETWORK,
                    "MASTG-NETWORK-1",
                    "Info.plist",
                    f"Remove {key} or restrict to specific domains using NSExceptionDomains.",
                )

        # Check for per-domain exceptions
        exception_domains = ats.get("NSExceptionDomains", {})
        for domain, config in exception_domains.items():
            if isinstance(config, dict):
                if config.get("NSExceptionAllowsInsecureHTTPLoads", False):
                    self._add_finding(
                        f"IOS-ATS-DOM-{domain[:20]}",
                        f"ATS exception for domain: {domain}",
                        f"Domain {domain} allows insecure HTTP loads.",
                        Severity.MEDIUM,
                        MASVS_NETWORK,
                        "MASTG-NETWORK-2",
                        "Info.plist",
                        "Remove domain exceptions. Use HTTPS for all domains.",
                    )
                if config.get("NSExceptionMinimumTLSVersion", "") in ("TLSv1.0", "TLSv1.1"):
                    self._add_finding(
                        f"IOS-ATS-TLS-{domain[:20]}",
                        f"Weak TLS version for domain: {domain}",
                        f"Domain {domain} allows TLS 1.0/1.1 — deprecated and insecure.",
                        Severity.HIGH,
                        MASVS_NETWORK,
                        "MASTG-NETWORK-3",
                        "Info.plist",
                        "Require TLS 1.2 or higher for all domains.",
                    )

    def _check_url_schemes(self) -> None:
        """Check for custom URL scheme risks."""
        url_types = self._info_plist.get("CFBundleURLTypes", [])
        if not url_types:
            return

        for url_type in url_types:
            schemes = url_type.get("CFBundleURLSchemes", [])
            name = url_type.get("CFBundleURLName", "unknown")
            for scheme in schemes:
                if isinstance(scheme, str):
                    severity = Severity.MEDIUM
                    # OAuth/callback schemes are higher risk
                    if any(kw in scheme.lower() for kw in ["oauth", "auth", "callback", "login", "token"]):
                        severity = Severity.HIGH

                    self._add_finding(
                        f"IOS-URL-{scheme[:15]}",
                        f"Custom URL scheme: {scheme}://",
                        f"App registers {scheme}:// — URL schemes can be hijacked by other apps. No ownership verification exists.",
                        severity,
                        MASVS_PLATFORM,
                        "MASTG-PLATFORM-1",
                        "Info.plist",
                        "Use universal links (associated domains) instead of custom URL schemes for sensitive flows. Validate all incoming URL data.",
                    )

    def _check_background_modes(self) -> None:
        """Check for background mode risks."""
        bg_modes = self._info_plist.get("UIBackgroundModes", [])
        if not bg_modes:
            return

        risky_modes = {
            "location": "Background location — app tracks location when not in use",
            "voip": "Background VoIP — app maintains persistent network connection",
            "bluetooth-central": "Background Bluetooth central — can scan for devices",
            "bluetooth-peripheral": "Background Bluetooth peripheral — can advertise",
            "fetch": "Background fetch — app wakes periodically",
            "processing": "Background processing — app can run extended tasks",
            "audio": "Background audio — app can record audio in background",
        }

        for mode in bg_modes:
            if mode in risky_modes:
                self._add_finding(
                    f"IOS-BG-{mode[:10]}",
                    f"Background mode: {mode}",
                    f"App uses background mode '{mode}' — {risky_modes[mode]}.",
                    Severity.LOW,
                    MASVS_PLATFORM,
                    "MASTG-PLATFORM-2",
                    "Info.plist",
                    f"Remove '{mode}' background mode if not essential. Document justification for App Store review.",
                )

    def _check_privacy_descriptions(self) -> None:
        """Check for missing privacy usage descriptions."""
        for key, desc in PRIVACY_DESCRIPTION_KEYS.items():
            # Check if the app uses the capability but is missing the description
            if key not in self._info_plist:
                # Only flag if there are indicators the feature is used
                # (e.g., framework references or entitlements)
                continue  # Can't reliably detect usage from static analysis alone

            description_text = self._info_plist.get(key, "")
            if not description_text:
                self._add_finding(
                    f"IOS-PRIV-{key[:15]}",
                    f"Empty privacy description: {key}",
                    f"Privacy key {key} ({desc}) is present but empty. App Store will reject.",
                    Severity.HIGH,
                    MASVS_PRIVACY,
                    "MASTG-PRIVACY-1",
                    "Info.plist",
                    f"Provide a clear, user-facing description for {key} explaining why {desc} is needed.",
                )

    def _check_hardcoded_secrets(self) -> None:
        """Search source files for hardcoded secrets."""
        source_files = (
            list(self.extracted_dir.rglob("*.swift"))
            + list(self.extracted_dir.rglob("*.m"))
            + list(self.extracted_dir.rglob("*.h"))
        )

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in SECRET_PATTERNS_IOS:
                    if re.search(pattern, content):
                        self._add_finding(
                            f"IOS-SEC-{src_file.stem[:10]}",
                            f"Hardcoded secret: {desc}",
                            f"Found in {rel_path}. Secrets should never be embedded in source code.",
                            Severity.HIGH,
                            MASVS_CRYPTO,
                            "MASTG-CRYPTO-1",
                            rel_path,
                            "Move secrets to the iOS Keychain or a secure configuration management system.",
                        )
                        break
            except Exception:
                continue

    def _check_crypto_misuse(self) -> None:
        """Check for insecure cryptographic usage."""
        source_files = (
            list(self.extracted_dir.rglob("*.swift"))
            + list(self.extracted_dir.rglob("*.m"))
        )

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in INSECURE_CRYPTO_IOS:
                    if re.search(pattern, content):
                        self._add_finding(
                            f"IOS-CRYPTO-{src_file.stem[:8]}",
                            f"Insecure crypto: {desc}",
                            f"Found in {rel_path}.",
                            Severity.HIGH,
                            MASVS_CRYPTO,
                            "MASTG-CRYPTO-2",
                            rel_path,
                            "Use AES-GCM for encryption, SHA-256+ for hashing. Use CryptoKit (Swift) or CommonCrypto with secure modes.",
                        )
                        break
            except Exception:
                continue

    def _check_webview_issues(self) -> None:
        """Check for insecure WebView configurations."""
        source_files = (
            list(self.extracted_dir.rglob("*.swift"))
            + list(self.extracted_dir.rglob("*.m"))
        )

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in WEBVIEW_IOS_PATTERNS:
                    if re.search(pattern, content):
                        severity = Severity.HIGH if "UIWebView" in pattern else Severity.MEDIUM
                        self._add_finding(
                            f"IOS-WEBVIEW-{src_file.stem[:8]}",
                            f"WebView risk: {desc}",
                            f"Found in {rel_path}.",
                            severity,
                            MASVS_PLATFORM,
                            "MASTG-PLATFORM-3",
                            rel_path,
                            "Use WKWebView (not UIWebView). Disable JavaScript if not needed. Never allow file:// URLs.",
                        )
                        break
            except Exception:
                continue

    def _check_pasteboard_usage(self) -> None:
        """Check for UIPasteboard (clipboard) usage — data leakage risk."""
        source_files = (
            list(self.extracted_dir.rglob("*.swift"))
            + list(self.extracted_dir.rglob("*.m"))
        )

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in PASTEBOARD_PATTERNS:
                    if re.search(pattern, content):
                        self._add_finding(
                            f"IOS-CLIP-{src_file.stem[:8]}",
                            f"Clipboard access: {desc}",
                            f"Found in {rel_path}. Any app can read the system pasteboard.",
                            Severity.MEDIUM,
                            MASVS_STORAGE,
                            "MASTG-STORAGE-1",
                            rel_path,
                            "Avoid copying sensitive data to clipboard. Use secure in-app pasteboard if needed.",
                        )
                        break
            except Exception:
                continue

    def _check_biometric_auth(self) -> None:
        """Check for weak biometric authentication implementation."""
        source_files = (
            list(self.extracted_dir.rglob("*.swift"))
            + list(self.extracted_dir.rglob("*.m"))
        )

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in BIOMETRIC_PATTERNS:
                    if re.search(pattern, content):
                        # Check if fallback to passcode exists (good practice)
                        has_fallback = "LAPolicyDeviceOwnerAuthentication" in content
                        severity = Severity.MEDIUM if has_fallback else Severity.HIGH

                        self._add_finding(
                            f"IOS-BIO-{src_file.stem[:8]}",
                            f"Biometric auth: {desc}",
                            f"Found in {rel_path}. Verify biometric fallback is secure and not bypassable.",
                            severity,
                            MASVS_AUTH,
                            "MASTG-AUTH-1",
                            rel_path,
                            "Use LAPolicyDeviceOwnerAuthenticationWithBiometrics with a secure fallback. Never store secrets accessible without biometric verification.",
                        )
                        break
            except Exception:
                continue

    def _check_binary_strings(self) -> None:
        """Check binary for hardcoded URLs, keys, and suspicious strings."""
        binary_path = self._get_main_binary()
        if not binary_path:
            return

        try:
            # Use `strings` command to extract strings from binary
            result = subprocess.run(
                ["strings", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return

            lines = result.stdout.split("\n")
            suspicious: list[str] = []

            url_pattern = re.compile(r"https?://[^\s\"']+")
            key_patterns = [
                re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*\S{8,}"),
                re.compile(r"-----BEGIN.*PRIVATE KEY-----"),
            ]

            found_urls: set[str] = set()

            for line in lines:
                urls = url_pattern.findall(line)
                for url in urls:
                    # Filter out Apple/SDK URLs
                    if not any(domain in url for domain in ["apple.com", "icloud.com", "mzstatic.com"]):
                        found_urls.add(url)

                for kp in key_patterns:
                    if kp.search(line):
                        suspicious.append(line[:100])

            # Report hardcoded URLs
            for url in sorted(found_urls)[:20]:
                is_http = url.startswith("http://")
                severity = Severity.HIGH if is_http else Severity.INFO
                self._add_finding(
                    f"IOS-URL-{url[:15].replace('/', '-')}",
                    f"Hardcoded URL: {url[:60]}",
                    f"{'HTTP' if is_http else 'HTTPS'} URL found in binary. HTTP URLs are unencrypted.",
                    severity,
                    MASVS_NETWORK,
                    "MASTG-NETWORK-4",
                    "Main binary",
                    "Move URLs to configuration. Use HTTPS only.",
                )

            # Report suspicious strings
            for s in suspicious[:10]:
                self._add_finding(
                    "IOS-BIN-SECRET",
                    "Suspicious string in binary",
                    f"Potentially sensitive string found: {s[:80]}",
                    Severity.MEDIUM,
                    MASVS_CRYPTO,
                    "MASTG-CRYPTO-3",
                    "Main binary",
                    "Remove secrets from source code. Use Keychain for storage.",
                )

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _check_keychain_protection(self) -> None:
        """Check for insecure Keychain access patterns in source."""
        source_files = (
            list(self.extracted_dir.rglob("*.swift"))
            + list(self.extracted_dir.rglob("*.m"))
        )

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for klass, desc in INSECURE_KEYCHAIN_CLASSES.items():
                    if klass in content:
                        self._add_finding(
                            f"IOS-KEYCHAIN-{src_file.stem[:8]}",
                            f"Insecure Keychain: {klass}",
                            f"Found in {rel_path}. {desc}. Data is accessible when it shouldn't be.",
                            Severity.HIGH,
                            MASVS_STORAGE,
                            "MASTG-STORAGE-2",
                            rel_path,
                            "Use kSecAttrAccessibleWhenUnlocked or kSecAttrAccessibleWhenUnlockedThisDeviceOnly for sensitive data.",
                        )
                        break
            except Exception:
                continue

    def _check_entitlements(self) -> None:
        """Check for risky entitlements."""
        if not self._entitlements:
            return

        risky_entitlements = {
            "com.apple.developer.kernel.extended-virtual-addressing": "Extended virtual addressing",
            "com.apple.developer.kernel.increased-memory-limit": "Increased memory limit",
            "com.apple.security.app-sandbox": "App sandbox — verify it's enabled",
            "com.apple.security.network.server": "Network server — app accepts incoming connections",
            "com.apple.security.files.user-selected.read-write": "User-selected file access — verify scope",
            "com.apple.security.device.usb": "USB device access",
            "com.apple.security.automation.apple-events": "Apple Events automation — can control other apps",
        }

        for key, desc in risky_entitlements.items():
            if key in self._entitlements:
                if key == "com.apple.security.app-sandbox":
                    # Sandbox is good if enabled
                    if not self._entitlements.get(key):
                        self._add_finding(
                            "IOS-SANDBOX-001",
                            "App Sandbox disabled",
                            "App sandbox is not enabled — app has unrestricted filesystem access.",
                            Severity.HIGH,
                            MASVS_PLATFORM,
                            "MASTG-PLATFORM-4",
                            "embedded.mobileprovision",
                            "Enable App Sandbox for all macOS/iOS apps.",
                        )
                elif key == "com.apple.security.network.server":
                    self._add_finding(
                        "IOS-ENT-NETSRV",
                        "Network server entitlement",
                        f"App has network.server entitlement — accepts incoming connections. {desc}.",
                        Severity.MEDIUM,
                        MASVS_NETWORK,
                        "MASTG-NETWORK-5",
                        "embedded.mobileprovision",
                        "Remove if incoming network connections are not required.",
                    )

    def _get_main_binary(self) -> Path | None:
        """Find the main executable binary in the .app bundle."""
        # Binary has same name as .app bundle without extension
        if self.extracted_dir.suffix == ".app":
            binary_name = self.extracted_dir.stem
            binary_path = self.extracted_dir / binary_name
            if binary_path.exists() and not binary_path.is_dir():
                return binary_path

        # Fallback: search for Mach-O
        for child in self.extracted_dir.iterdir():
            if not child.is_dir() and not child.suffix and child.stat().st_size > 1000:
                return child
        return None

    @property
    def bundle_id(self) -> str:
        """Extract bundle identifier from Info.plist."""
        return self._info_plist.get("CFBundleIdentifier", "unknown")

    @property
    def app_name(self) -> str:
        """Extract app display name."""
        return self._info_plist.get("CFBundleDisplayName", self._info_plist.get("CFBundleName", "unknown"))

    @property
    def version(self) -> str:
        """Extract app version."""
        return self._info_plist.get("CFBundleShortVersionString", "unknown")