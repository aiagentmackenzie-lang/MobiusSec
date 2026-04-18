"""Android static analysis module."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lxml import etree

from mobiussec import (
    MASVS_STORAGE,
    MASVS_CRYPTO,
    MASVS_NETWORK,
    MASVS_PLATFORM,
    MASVS_CODE,
    MASVS_RESILIENCE,
)
from mobiussec.models import Finding, Severity, Platform, MASVSStatus


# Dangerous permission categories
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": "Reads contact data",
    "android.permission.WRITE_CONTACTS": "Writes contact data",
    "android.permission.READ_CALENDAR": "Reads calendar data",
    "android.permission.WRITE_CALENDAR": "Writes calendar data",
    "android.permission.READ_CALL_LOG": "Reads call log",
    "android.permission.WRITE_CALL_LOG": "Writes call log",
    "android.permission.READ_PHONE_STATE": "Reads phone state",
    "android.permission.CALL_PHONE": "Makes phone calls",
    "android.permission.READ_SMS": "Reads SMS messages",
    "android.permission.SEND_SMS": "Sends SMS messages",
    "android.permission.RECEIVE_SMS": "Receives SMS messages",
    "android.permission.READ_EXTERNAL_STORAGE": "Reads external storage",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Writes external storage",
    "android.permission.ACCESS_FINE_LOCATION": "Accesses precise location",
    "android.permission.ACCESS_COARSE_LOCATION": "Accesses approximate location",
    "android.permission.CAMERA": "Accesses camera",
    "android.permission.RECORD_AUDIO": "Records audio",
    "android.permission.BODY_SENSORS": "Accesses body sensors",
    "android.permission.READ_PHONE_NUMBERS": "Reads phone numbers",
    "android.permission.ANSWER_PHONE_CALLS": "Answers phone calls",
    "android.permission.ACCEPT_HANDOVER": "Handover from another app",
    "android.permission.ACTIVITY_RECOGNITION": "Activity recognition",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Background location access",
    "android.permission.NEARBY_WIFI_DEVICES": "Nearby WiFi device access",
    "android.permission.POST_NOTIFICATIONS": "Posts notifications",
}

# Insecure crypto algorithm patterns
INSECURE_CRYPTO_PATTERNS = [
    (r"MessageDigest\.getInstance\([\"']MD5", "MD5 hash algorithm — cryptographically broken"),
    (r"MessageDigest\.getInstance\([\"']SHA-?1", "SHA-1 hash algorithm — vulnerable to collisions"),
    (r"Cipher\.getInstance\([\"']DES", "DES encryption — insecure, use AES"),
    (r"Cipher\.getInstance\([\"']DESede", "3DES encryption — deprecated, use AES"),
    (r"Cipher\.getInstance\([\"']RC[24]", "RC2/RC4 encryption — insecure stream cipher"),
    (r"Cipher\.getInstance\([\"']AES/ECB", "AES in ECB mode — deterministic, no diffusion"),
    (r"KeyGenerator\.getInstance\([\"']DES", "DES key generation — insecure"),
    (r"SecretKeySpec\([^\)]*,\s*[\"']AES[\"']\s*\)", "Raw AES key — likely hardcoded"),
    (r"Random\(\)", "java.util.Random — not cryptographically secure, use SecureRandom"),
]

# Hardcoded secret patterns
SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*[\"'][^\"']{8,}", "Potential API key hardcoded"),
    (r"(?i)(secret|token|password|passwd)\s*[=:]\s*[\"'][^\"']{8,}", "Potential secret/token hardcoded"),
    (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*[\"'][^\"']+)", "AWS credentials hardcoded"),
    (r"[A-Za-z0-9]{40}", "Potential high-entropy string (possible key/token)"),
    (r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----", "Private key embedded in source"),
]

# Intent/WebView risk patterns
INTENT_RISK_PATTERNS = [
    (r"Intent\([^)]*\.parseUri\(", "Intent from URI — potential injection (MASTG-PLATFORM-1)"),
    (r"addJavascriptInterface\(", "JavaScript interface added to WebView — potential RCE"),
    (r"setJavaScriptEnabled\(true\)", "JavaScript enabled in WebView — XSS risk"),
    (r"setAllowFileAccess\(true\)", "File access enabled in WebView — local file theft risk"),
    (r"setAllowFileAccessFromFileURLs\(true\)", "File URL access — cross-origin file access"),
    (r"setAllowUniversalAccessFromFileURLs\(true\)", "Universal file URL access — severe cross-origin risk"),
    (r"loadDataWithBaseURL\([^)]*file://", "WebView loads file:// content — LFI risk"),
    (r"WebView\([^)]*\.loadUrl\([\"']http://", "WebView loads HTTP URL — no TLS"),
    (r"startActivity\([^)]*\.setAction\([\"'][^\"']+[\"']\)", "Implicit intent — potential hijacking"),
    (r"PendingIntent\.getActivity\([^)]*,\s*0\b", "PendingIntent with no FLAG_IMMUTABLE — mutable pending intent risk"),
]


class AndroidAnalyzer:
    """Static analysis for Android APK files."""

    def __init__(self, extracted_dir: Path) -> None:
        self.extracted_dir = extracted_dir
        self.manifest_path = extracted_dir / "AndroidManifest.xml"
        self.findings: list[Finding] = []
        self._manifest_tree: etree._ElementTree | None = None
        self._manifest_root: etree._Element | None = None

    def analyze(self) -> list[Finding]:
        """Run all Android analysis checks."""
        self.findings = []

        self._parse_manifest()
        self._check_manifest_security()
        self._check_permissions()
        self._check_exported_components()
        self._check_network_security_config()
        self._check_hardcoded_secrets()
        self._check_crypto_misuse()
        self._check_webview_issues()
        self._check_intent_issues()
        self._check_backup_flag()
        self._check_debuggable_flag()
        self._check_logging()
        self._check_sql_injection()
        self._check_shared_preferences()

        return self.findings

    def _parse_manifest(self) -> None:
        """Parse AndroidManifest.xml."""
        if self.manifest_path.exists():
            try:
                self._manifest_tree = etree.parse(str(self.manifest_path))
                self._manifest_root = self._manifest_tree.getroot()
            except Exception:
                pass

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
            platform=Platform.ANDROID,
            file=file,
            remediation=remediation,
        ))

    def _check_manifest_security(self) -> None:
        """Basic manifest security checks."""
        if self._manifest_root is None:
            return

        ns = {"android": "http://schemas.android.com/apk/res/android"}

        # Check for debuggable
        debuggable = self._manifest_root.get(f"{{{ns['android']}}}debuggable", "")
        if debuggable.lower() == "true":
            self._add_finding(
                "AND-001",
                "App is debuggable",
                "android:debuggable='true' in manifest allows debugging and memory inspection on production builds.",
                Severity.HIGH,
                MASVS_RESILIENCE,
                "MASTG-CODE-4",
                "AndroidManifest.xml",
                "Set android:debuggable='false' or remove it (release builds default to false).",
            )

    def _check_debuggable_flag(self) -> None:
        """Check debuggable attribute (duplicate guard — also caught by manifest security)."""
        # Already handled in _check_manifest_security
        pass

    def _check_permissions(self) -> None:
        """Check for dangerous permissions."""
        if self._manifest_root is None:
            return

        ns = {"android": "http://schemas.android.com/apk/res/android"}
        uses_perms = self._manifest_root.findall(".//uses-permission")

        for perm_elem in uses_perms:
            name = perm_elem.get(f"{{{ns['android']}}}name", "")
            if name in DANGEROUS_PERMISSIONS:
                max_sdk = perm_elem.get(f"{{{ns['android']}}}maxSdkVersion", "")
                # If maxSdkVersion < 23, permission not used on modern Android
                if max_sdk and int(max_sdk) < 23:
                    continue

                severity = Severity.HIGH if name in (
                    "android.permission.READ_SMS",
                    "android.permission.SEND_SMS",
                    "android.permission.READ_CALL_LOG",
                    "android.permission.CALL_PHONE",
                    "android.permission.RECORD_AUDIO",
                    "android.permission.CAMERA",
                ) else Severity.MEDIUM

                self._add_finding(
                    f"AND-PERM-{name.split('.')[-1]}",
                    f"Dangerous permission: {name}",
                    f"App requests {name} — {DANGEROUS_PERMISSIONS[name]}. Review if genuinely needed.",
                    severity,
                    MASVS_PLATFORM,
                    "MASTG-PLATFORM-1",
                    "AndroidManifest.xml",
                    f"Remove {name} if not essential. Use minimal permission principle.",
                )

    def _check_exported_components(self) -> None:
        """Check for exported components without permission protection."""
        if self._manifest_root is None:
            return

        ns = {"android": "http://schemas.android.com/apk/res/android"}
        component_types = [
            ("activity", "Activity"),
            ("service", "Service"),
            ("receiver", "Broadcast Receiver"),
            ("provider", "Content Provider"),
        ]

        for tag, label in component_types:
            for elem in self._manifest_root.findall(f".//{tag}"):
                name = elem.get(f"{{{ns['android']}}}name", "unknown")
                exported = elem.get(f"{{{ns['android']}}}exported", "")
                has_permission = elem.find(f".//{{{ns['android']}}}permission") is not None

                # If exported="true" or has intent-filters (auto-exported on old Android)
                intent_filters = elem.findall(".//intent-filter")
                is_exported = exported.lower() == "true" or (intent_filters and exported != "false")

                if is_exported and not has_permission:
                    severity = Severity.HIGH if tag == "provider" else Severity.MEDIUM
                    self._add_finding(
                        f"AND-EXP-{tag}-{name}",
                        f"Exported {label}: {name}",
                        f"{label} is exported without permission protection — accessible to any app on device.",
                        severity,
                        MASVS_PLATFORM,
                        "MASTG-PLATFORM-2",
                        "AndroidManifest.xml",
                        f"Set android:exported='false' or add a custom permission to protect this {label.lower()}.",
                    )

    def _check_network_security_config(self) -> None:
        """Check for network security config issues."""
        if self._manifest_root is None:
            return

        ns = {"android": "http://schemas.android.com/apk/res/android"}
        app_elem = self._manifest_root.find(".//application")
        if app_elem is None:
            return

        # Check for cleartext traffic
        uses_cleartext = app_elem.get(f"{{{ns['android']}}}usesCleartextTraffic", "")
        if uses_cleartext.lower() == "true":
            self._add_finding(
                "AND-NET-001",
                "Cleartext traffic allowed",
                "android:usesCleartextTraffic='true' — app can send unencrypted HTTP traffic.",
                Severity.HIGH,
                MASVS_NETWORK,
                "MASTG-NETWORK-1",
                "AndroidManifest.xml",
                "Set usesCleartextTraffic='false'. Use HTTPS for all network communication.",
            )

        # Check for network security config file
        net_sec_config = app_elem.get(f"{{{ns['android']}}}networkSecurityConfig", "")
        if net_sec_config:
            config_path = self.extracted_dir / "res" / "xml" / net_sec_config.split("/")[-1]
            if config_path.exists():
                self._parse_network_security_config(config_path)

    def _parse_network_security_config(self, config_path: Path) -> None:
        """Parse network_security_config.xml for insecure settings."""
        try:
            tree = etree.parse(str(config_path))
            root = tree.getroot()
            ns = {}

            # Check for cleartext traffic permitted
            for elem in root.iter():
                if "cleartextTrafficPermitted" in elem.attrib:
                    if elem.get("cleartextTrafficPermitted", "").lower() == "true":
                        self._add_finding(
                            "AND-NET-002",
                            "Network security config allows cleartext",
                            "cleartextTrafficPermitted='true' in network security config.",
                            Severity.HIGH,
                            MASVS_NETWORK,
                            "MASTG-NETWORK-2",
                            str(config_path.relative_to(self.extracted_dir)),
                            "Remove cleartextTrafficPermitted or set to 'false'.",
                        )
                        break
        except Exception:
            pass

    def _check_backup_flag(self) -> None:
        """Check if backup is enabled (data extraction risk)."""
        if self._manifest_root is None:
            return

        ns = {"android": "http://schemas.android.com/apk/res/android"}
        app_elem = self._manifest_root.find(".//application")
        if app_elem is None:
            return

        backup = app_elem.get(f"{{{ns['android']}}}allowBackup", "")
        if backup.lower() == "true":
            self._add_finding(
                "AND-BACKUP-001",
                "Backup enabled — data extraction risk",
                "android:allowBackup='true' — app data can be extracted via adb backup.",
                Severity.MEDIUM,
                MASVS_STORAGE,
                "MASTG-STORAGE-1",
                "AndroidManifest.xml",
                "Set android:allowBackup='false' for apps handling sensitive data. Use android:fullBackupContent for selective backup.",
            )

        full_backup = app_elem.get(f"{{{ns['android']}}}fullBackupContent", "")
        if not full_backup and backup.lower() != "false":
            # No backup restriction at all
            self._add_finding(
                "AND-BACKUP-002",
                "No backup content restrictions",
                "No fullBackupContent specified — all app data included in backups by default.",
                Severity.LOW,
                MASVS_STORAGE,
                "MASTG-STORAGE-2",
                "AndroidManifest.xml",
                "Add android:fullBackupContent to specify which files to exclude from backup.",
            )

    def _check_hardcoded_secrets(self) -> None:
        """Search source files for hardcoded secrets and API keys."""
        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.smali"))
        source_files += list(self.extracted_dir.rglob("*.kt"))

        for src_file in source_files[:200]:  # Limit to avoid excessive scanning
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in SECRET_PATTERNS:
                    matches = re.findall(pattern, content)
                    if matches:
                        self._add_finding(
                            f"AND-SEC-{src_file.stem[:10]}",
                            f"Hardcoded secret detected: {desc}",
                            f"Pattern matched in {rel_path}. Secrets should never be embedded in source code.",
                            Severity.HIGH,
                            MASVS_CRYPTO,
                            "MASTG-CRYPTO-1",
                            rel_path,
                            "Move secrets to environment variables, secure keystore, or a secrets management service.",
                        )
                        break  # One finding per file for secrets
            except Exception:
                continue

    def _check_crypto_misuse(self) -> None:
        """Check for insecure cryptographic usage in source code."""
        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.smali"))
        source_files += list(self.extracted_dir.rglob("*.kt"))

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in INSECURE_CRYPTO_PATTERNS:
                    if re.search(pattern, content):
                        self._add_finding(
                            f"AND-CRYPTO-{src_file.stem[:10]}",
                            f"Insecure cryptography: {desc}",
                            f"Found in {rel_path}. {desc}.",
                            Severity.HIGH,
                            MASVS_CRYPTO,
                            "MASTG-CRYPTO-2",
                            rel_path,
                            "Use AES/GCM/NoPadding for encryption, SHA-256+ for hashing, SecureRandom for random generation.",
                        )
                        break
            except Exception:
                continue

    def _check_webview_issues(self) -> None:
        """Check for insecure WebView configurations."""
        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.kt"))

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in INTENT_RISK_PATTERNS:
                    if "WebView" in content and re.search(pattern, content):
                        self._add_finding(
                            f"AND-WEBVIEW-{src_file.stem[:8]}",
                            f"WebView risk: {desc}",
                            f"Found in {rel_path}. WebView security misconfiguration detected.",
                            Severity.MEDIUM,
                            MASVS_PLATFORM,
                            "MASTG-PLATFORM-3",
                            rel_path,
                            "Disable JavaScript if not needed. Never allow file:// access. Use HTTPS only.",
                        )
                        break
            except Exception:
                continue

    def _check_intent_issues(self) -> None:
        """Check for intent injection and pending intent risks."""
        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.kt"))

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in INTENT_RISK_PATTERNS:
                    if re.search(pattern, content):
                        self._add_finding(
                            f"AND-INTENT-{src_file.stem[:8]}",
                            f"Intent risk: {desc}",
                            f"Found in {rel_path}. Review intent handling for security.",
                            Severity.MEDIUM,
                            MASVS_PLATFORM,
                            "MASTG-PLATFORM-4",
                            rel_path,
                            "Use explicit intents where possible. Add FLAG_IMMUTABLE to PendingIntents.",
                        )
                        break
            except Exception:
                continue

    def _check_logging(self) -> None:
        """Check for sensitive data logging."""
        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.kt"))

        log_patterns = [
            (r"Log\.[dive]\s*\(\s*[\"'][^\"']*(?:password|token|secret|key|auth|credential)[^\"']*", "Sensitive data logged"),
            (r"System\.out\.print(?:ln)?\s*\([^)]*(?:password|token|secret|key|auth)", "Sensitive data printed to stdout"),
        ]

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in log_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self._add_finding(
                            f"AND-LOG-{src_file.stem[:8]}",
                            desc,
                            f"Sensitive data may be logged in {rel_path}. Logs can be read by other apps.",
                            Severity.MEDIUM,
                            MASVS_CODE,
                            "MASTG-CODE-1",
                            rel_path,
                            "Remove sensitive data from log statements. Use ProGuard/R8 to strip Log.d/v calls in release.",
                        )
                        break
            except Exception:
                continue

    def _check_sql_injection(self) -> None:
        """Check for SQL injection vulnerabilities."""
        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.kt"))

        sqli_patterns = [
            (r"rawQuery\s*\(\s*[\"']SELECT.*\+\s", "Raw SQL query with string concatenation — SQL injection risk"),
            (r"execSQL\s*\(\s*[\"'].*\+\s", "execSQL with string concatenation — SQL injection risk"),
            (r"\.query\s*\([^)]*\+\s", "Query with string concatenation — potential SQL injection"),
        ]

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in sqli_patterns:
                    if re.search(pattern, content):
                        self._add_finding(
                            f"AND-SQLI-{src_file.stem[:8]}",
                            f"SQL injection: {desc}",
                            f"Found in {rel_path}. String concatenation in SQL queries allows injection.",
                            Severity.HIGH,
                            MASVS_CODE,
                            "MASTG-CODE-2",
                            rel_path,
                            "Use parameterized queries (selectionArgs) instead of string concatenation.",
                        )
                        break
            except Exception:
                continue

    def _check_shared_preferences(self) -> None:
        """Check for insecure SharedPreferences usage."""
        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.kt"))

        sp_patterns = [
            (r"getSharedPreferences\s*\([^)]*\)\s*\.edit\(\)", "SharedPreferences used — data stored in plain XML"),
            (r"MODE_WORLD_READABLE", "SharedPreferences world-readable — any app can read data"),
            (r"MODE_WORLD_WRITEABLE", "SharedPreferences world-writable — any app can modify data"),
        ]

        for src_file in source_files[:200]:
            try:
                content = src_file.read_text(errors="ignore")
                rel_path = str(src_file.relative_to(self.extracted_dir))
                for pattern, desc in sp_patterns:
                    if re.search(pattern, content):
                        severity = Severity.HIGH if "WORLD" in pattern else Severity.MEDIUM
                        self._add_finding(
                            f"AND-SP-{src_file.stem[:8]}",
                            f"SharedPreferences risk: {desc}",
                            f"Found in {rel_path}. SharedPreferences data is stored as plain XML on disk.",
                            severity,
                            MASVS_STORAGE,
                            "MASTG-STORAGE-3",
                            rel_path,
                            "Use EncryptedSharedPreferences or Android Keystore for sensitive data. Remove MODE_WORLD_READABLE/WRITABLE.",
                        )
                        break
            except Exception:
                continue

    @property
    def package_name(self) -> str:
        """Extract package name from manifest."""
        if self._manifest_root is not None:
            return self._manifest_root.get("package", "unknown")
        return "unknown"

    @property
    def app_name(self) -> str:
        """Try to extract app name from strings resources."""
        strings_xml = self.extracted_dir / "res" / "values" / "strings.xml"
        if strings_xml.exists():
            try:
                tree = etree.parse(str(strings_xml))
                root = tree.getroot()
                for elem in root:
                    if elem.get("name") == "app_name":
                        return elem.text or "unknown"
            except Exception:
                pass
        return "unknown"