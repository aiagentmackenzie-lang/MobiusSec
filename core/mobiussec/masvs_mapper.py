"""OWASP MASVS 2.0 compliance mapping."""

from __future__ import annotations

from mobiussec import MASVS_CATEGORIES
from mobiussec.models import (
    Finding,
    MASVSControl,
    MASVSResult,
    MASVSStatus,
    Platform,
    Severity,
)


# MASVS 2.0 test definitions — each test maps to a category and has a name
MASVS_TESTS: dict[str, list[dict[str, str]]] = {
    "STORAGE": [
        {"id": "MASTG-STORAGE-1", "name": "Data storage encryption at rest"},
        {"id": "MASTG-STORAGE-2", "name": "Keychain/Keystore usage"},
        {"id": "MASTG-STORAGE-3", "name": "SharedPreferences/UserDefaults security"},
        {"id": "MASTG-STORAGE-4", "name": "Log file leakage"},
        {"id": "MASTG-STORAGE-5", "name": "Backup data protection"},
        {"id": "MASTG-STORAGE-6", "name": "Clipboard data exposure"},
        {"id": "MASTG-STORAGE-7", "name": "Memory snapshot protection"},
        {"id": "MASTG-STORAGE-8", "name": "SQLite database encryption"},
    ],
    "CRYPTO": [
        {"id": "MASTG-CRYPTO-1", "name": "Hardcoded cryptographic keys"},
        {"id": "MASTG-CRYPTO-2", "name": "Insecure algorithms usage"},
        {"id": "MASTG-CRYPTO-3", "name": "ECB mode usage"},
        {"id": "MASTG-CRYPTO-4", "name": "Weak key derivation"},
        {"id": "MASTG-CRYPTO-5", "name": "Insecure random number generation"},
        {"id": "MASTG-CRYPTO-6", "name": "Custom crypto implementations"},
    ],
    "AUTH": [
        {"id": "MASTG-AUTH-1", "name": "Biometric authentication bypass"},
        {"id": "MASTG-AUTH-2", "name": "Local authentication fallback"},
        {"id": "MASTG-AUTH-3", "name": "Session management"},
        {"id": "MASTG-AUTH-4", "name": "Token storage security"},
        {"id": "MASTG-AUTH-5", "name": "Password policies"},
    ],
    "NETWORK": [
        {"id": "MASTG-NETWORK-1", "name": "TLS enforcement (ATS/cleartext)"},
        {"id": "MASTG-NETWORK-2", "name": "SSL certificate pinning"},
        {"id": "MASTG-NETWORK-3", "name": "TLS version minimum"},
        {"id": "MASTG-NETWORK-4", "name": "Hardcoded URLs and endpoints"},
        {"id": "MASTG-NETWORK-5", "name": "Network server exposure"},
    ],
    "PLATFORM": [
        {"id": "MASTG-PLATFORM-1", "name": "URL scheme / deep link hijacking"},
        {"id": "MASTG-PLATFORM-2", "name": "Exported component / IPC protection"},
        {"id": "MASTG-PLATFORM-3", "name": "WebView security configuration"},
        {"id": "MASTG-PLATFORM-4", "name": "App sandbox / permissions"},
        {"id": "MASTG-PLATFORM-5", "name": "Intent injection"},
        {"id": "MASTG-PLATFORM-6", "name": "Background mode risks"},
    ],
    "CODE": [
        {"id": "MASTG-CODE-1", "name": "Sensitive data logging"},
        {"id": "MASTG-CODE-2", "name": "SQL injection"},
        {"id": "MASTG-CODE-3", "name": "Input validation"},
        {"id": "MASTG-CODE-4", "name": "Debuggable / development flags"},
        {"id": "MASTG-CODE-5", "name": "Code obfuscation"},
    ],
    "RESILIENCE": [
        {"id": "MASTG-RESILIENCE-1", "name": "Root/jailbreak detection"},
        {"id": "MASTG-RESILIENCE-2", "name": "Anti-debugging controls"},
        {"id": "MASTG-RESILIENCE-3", "name": "Anti-tampering controls"},
        {"id": "MASTG-RESILIENCE-4", "name": "Debuggable flag (Android)"},
        {"id": "MASTG-RESILIENCE-5", "name": "Code obfuscation assessment"},
    ],
    "PRIVACY": [
        {"id": "MASTG-PRIVACY-1", "name": "Privacy usage descriptions (iOS)"},
        {"id": "MASTG-PRIVACY-2", "name": "Permission minimalism"},
        {"id": "MASTG-PRIVACY-3", "name": "Data collection transparency"},
        {"id": "MASTG-PRIVACY-4", "name": "Third-party SDK data sharing"},
        {"id": "MASTG-PRIVACY-5", "name": "Device identifier usage"},
    ],
}

# Mapping from finding IDs to MASVS test IDs
FINDING_TO_MASVS: dict[str, str] = {
    # Android findings
    "AND-001": "MASTG-RESILIENCE-4",
    "AND-PERM-READSMS": "MASTG-PRIVACY-2",
    "AND-PERM-RECORDAUDIO": "MASTG-PRIVACY-2",
    "AND-PERM-CAMERA": "MASTG-PRIVACY-2",
    "AND-NET-001": "MASTG-NETWORK-1",
    "AND-NET-002": "MASTG-NETWORK-1",
    "AND-BACKUP-001": "MASTG-STORAGE-5",
    "AND-BACKUP-002": "MASTG-STORAGE-5",
    # iOS findings
    "IOS-ATS-NSAllowsArbitraryLoads": "MASTG-NETWORK-1",
    "IOS-ATS-NSAllowsArbitraryLoadsInWebContent": "MASTG-NETWORK-1",
    "IOS-ATS-NSAllowsLocalNetworking": "MASTG-NETWORK-1",
    "IOS-KEYCHAIN-kSecAttrAccessibleAlways": "MASTG-STORAGE-2",
}


class MASVSMapper:
    """Maps findings to OWASP MASVS 2.0 compliance status."""

    def __init__(self, platform: Platform) -> None:
        self.platform = platform

    def map_findings(self, findings: list[Finding]) -> MASVSResult:
        """Map a list of findings to MASVS compliance status."""
        # Initialize all controls
        controls: list[MASVSControl] = []
        for category in MASVS_CATEGORIES:
            for test_def in MASVS_TESTS.get(category, []):
                controls.append(MASVSControl(
                    category=category,
                    test_id=test_def["id"],
                    test_name=test_def["name"],
                    status=MASVSStatus.SKIP,  # Default — not tested
                ))

        # Map findings to controls
        finding_test_ids: dict[str, list[Finding]] = {}
        for finding in findings:
            test_id = finding.masvs_test_id
            if test_id:
                if test_id not in finding_test_ids:
                    finding_test_ids[test_id] = []
                finding_test_ids[test_id].append(finding)

        # Update control statuses based on findings
        for ctrl in controls:
            if ctrl.test_id in finding_test_ids:
                ctrl.findings = finding_test_ids[ctrl.test_id]
                # Determine status based on findings
                has_fail = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in ctrl.findings)
                has_warn = any(f.severity in (Severity.MEDIUM, Severity.LOW) for f in ctrl.findings)

                if has_fail:
                    ctrl.status = MASVSStatus.FAIL
                elif has_warn:
                    ctrl.status = MASVSStatus.WARN
                else:
                    ctrl.status = MASVSStatus.PASS
            else:
                # No findings for this control — mark as pass (tested, no issues)
                # Only if we actually performed analysis for this category
                categories_with_findings = {f.masvs_category for f in findings}
                if ctrl.category in categories_with_findings:
                    ctrl.status = MASVSStatus.PASS
                else:
                    ctrl.status = MASVSStatus.SKIP

        return MASVSResult(platform=self.platform, controls=controls)

    @staticmethod
    def get_category_tests(category: str) -> list[dict[str, str]]:
        """Get all test definitions for a MASVS category."""
        return MASVS_TESTS.get(category, [])

    @staticmethod
    def get_all_tests() -> dict[str, list[dict[str, str]]]:
        """Get all MASVS test definitions."""
        return MASVS_TESTS