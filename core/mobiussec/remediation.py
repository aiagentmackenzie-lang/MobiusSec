"""AI-powered remediation engine — local Ollama + optional cloud fallback."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from mobiussec.models import Finding, Severity, Platform, MASVSStatus

# Static remediation database — works without any AI model
STATIC_REMEDIATIONS: dict[str, dict[str, Any]] = {
    # Android
    "AND-001": {
        "fix": "Set android:debuggable='false' in AndroidManifest.xml or remove it entirely (release builds default to false).",
        "code": " <!-- Remove this line from AndroidManifest.xml -->\n <!-- android:debuggable=\"true\" -->",
        "priority": "P0 — Ship blocker",
    },
    "AND-NET-001": {
        "fix": "Remove android:usesCleartextTraffic='true'. Use HTTPS for all network communication.",
        "code": " android:usesCleartextTraffic=\"false\"",
        "priority": "P0 — Security critical",
    },
    "AND-NET-002": {
        "fix": "Remove cleartextTrafficPermitted='true' from network security config.",
        "code": " <?xml version=\"1.0\" encoding=\"utf-8\"?>\n <network-security-config>\n   <base-config cleartextTrafficPermitted=\"false\">\n     <trust-anchors>\n       <certificates src=\"system\" />\n     </trust-anchors>\n   </base-config>\n </network-security-config>",
        "priority": "P0 — Security critical",
    },
    "AND-BACKUP-001": {
        "fix": "Set android:allowBackup='false' for apps handling sensitive data.",
        "code": " android:allowBackup=\"false\"",
        "priority": "P1 — Data protection",
    },
    # iOS
    "IOS-ATS-NSAllowsArbitraryLoads": {
        "fix": "Remove NSAllowsArbitraryLoads from Info.plist. Use HTTPS for all connections.",
        "code": " <key>NSAppTransportSecurity</key>\n <dict>\n   <!-- Remove NSAllowsArbitraryLoads -->\n </dict>",
        "priority": "P0 — Security critical",
    },
    "IOS-KEYCHAIN-kSecAttrAccessibleAlways": {
        "fix": "Change to kSecAttrAccessibleWhenUnlocked or kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
        "code": " // Swift\n let access = kSecAttrAccessibleWhenUnlockedThisDeviceOnly\n\n // Objective-C\n [query setObject:(__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly\n            forKey:(__bridge id)kSecAttrAccessible];",
        "priority": "P0 — Data protection",
    },
}

# Category-level remediation guidance
CATEGORY_REMEDIATIONS: dict[str, dict[str, str]] = {
    "STORAGE": {
        "title": "Secure Data Storage",
        "guidance": "Use platform-specific secure storage: Android Keystore / EncryptedSharedPreferences, iOS Keychain. Never store sensitive data in SharedPreferences, UserDefaults, or plain files. Encrypt SQLite databases with SQLCipher.",
        "references": [
            "https://mas.owasp.org/MASVS/controls/MASVS-STORAGE/",
            "https://developer.android.com/training/articles/keystore",
            "https://developer.apple.com/documentation/security/keychain_services",
        ],
    },
    "CRYPTO": {
        "title": "Cryptographic Best Practices",
        "guidance": "Use AES-256 in GCM mode for encryption. Use SHA-256+ for hashing. Generate keys with platform keystore. Never hardcode keys. Use SecureRandom (Android) / SystemRandom (iOS) for random generation.",
        "references": [
            "https://mas.owasp.org/MASVS/controls/MASVS-CRYPTO/",
            "https://developer.android.com/guide/topics/security/cryptography",
        ],
    },
    "AUTH": {
        "title": "Authentication Security",
        "guidance": "Implement biometric authentication with secure fallback. Store tokens in Keychain/Keystore. Use short-lived JWT tokens. Implement proper session management with server-side validation.",
        "references": [
            "https://mas.owasp.org/MASVS/controls/MASVS-AUTH/",
        ],
    },
    "NETWORK": {
        "title": "Network Security",
        "guidance": "Enforce HTTPS everywhere (ATS on iOS, Network Security Config on Android). Implement certificate pinning for critical APIs. Never allow cleartext traffic. Validate all server certificates.",
        "references": [
            "https://mas.owasp.org/MASVS/controls/MASVS-NETWORK/",
        ],
    },
    "PLATFORM": {
        "title": "Platform Security",
        "guidance": "Set android:exported='false' for non-public components. Use explicit intents. Validate all URL scheme data. Disable JavaScript in WebViews unless necessary. Never allow file:// access in WebViews.",
        "references": [
            "https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM/",
        ],
    },
    "CODE": {
        "title": "Code-Level Security",
        "guidance": "Use parameterized queries for all SQL operations. Remove sensitive logging in release builds. Validate all user inputs. Use ProGuard/R8 for code obfuscation. Strip debug symbols from release builds.",
        "references": [
            "https://mas.owasp.org/MASVS/controls/MASVS-CODE/",
        ],
    },
    "RESILIENCE": {
        "title": "App Resilience",
        "guidance": "Implement root/jailbreak detection. Add anti-debugging controls. Use code obfuscation (ProGuard/R8, SwiftShield). Implement tamper detection. Check app signature integrity at runtime.",
        "references": [
            "https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE/",
        ],
    },
    "PRIVACY": {
        "title": "Privacy Controls",
        "guidance": "Request minimal permissions. Implement consent dialogs before data collection. Provide data deletion capability. Disclose all third-party SDK data practices. Comply with LGPD/GDPR/CCPA as applicable.",
        "references": [
            "https://mas.owasp.org/MASVS/controls/MASVS-PRIVACY/",
        ],
    },
}

# Severity → priority mapping for fix ordering
SEVERITY_PRIORITY = {
    Severity.CRITICAL: "P0 — Fix immediately (ship blocker)",
    Severity.HIGH: "P1 — Fix before release",
    Severity.MEDIUM: "P2 — Fix in next sprint",
    Severity.LOW: "P3 — Backlog",
    Severity.INFO: "P4 — Optional improvement",
}

# Ollama model for AI remediation
DEFAULT_OLLAMA_MODEL = "llama3.2:latest"


class RemediationEngine:
    """AI-powered remediation suggestions for security findings."""

    def __init__(self, use_ai: bool = False, model: str = DEFAULT_OLLAMA_MODEL) -> None:
        self.use_ai = use_ai
        self.model = model
        self._ollama_available: bool | None = None

    def get_remediation(self, finding: Finding) -> dict[str, Any]:
        """Get remediation guidance for a finding."""
        result: dict[str, Any] = {
            "finding_id": finding.id,
            "title": finding.title,
            "priority": SEVERITY_PRIORITY.get(finding.severity, "P3 — Backlog"),
            "category_guidance": CATEGORY_REMEDIATIONS.get(finding.masvs_category, {}),
        }

        # Check static remediation first
        if finding.id in STATIC_REMEDIATIONS:
            result["static_fix"] = STATIC_REMEDIATIONS[finding.id]
            result["fix"] = STATIC_REMEDIATIONS[finding.id]["fix"]
            result["code_sample"] = STATIC_REMEDIATIONS[finding.id]["code"]
            return result

        # Use inline remediation from the finding itself
        if finding.remediation:
            result["fix"] = finding.remediation
        else:
            result["fix"] = CATEGORY_REMEDIATIONS.get(finding.masvs_category, {}).get("guidance", "Review and address this finding according to OWASP MASVS guidelines.")

        # AI-powered remediation (if enabled and Ollama available)
        if self.use_ai and self._check_ollama():
            ai_fix = self._get_ai_remediation(finding)
            if ai_fix:
                result["ai_fix"] = ai_fix

        return result

    def get_all_remediations(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Get remediation guidance for all findings, sorted by priority."""
        remediations = [self.get_remediation(f) for f in findings]
        # Sort by severity (critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        remediations.sort(key=lambda r: severity_order.get(
            next((f.severity for f in findings if f.id == r["finding_id"]), Severity.INFO),
            4,
        ))
        return remediations

    def get_priority_summary(self, findings: list[Finding]) -> dict[str, list[str]]:
        """Group findings by priority level."""
        summary: dict[str, list[str]] = {
            "P0": [],
            "P1": [],
            "P2": [],
            "P3": [],
            "P4": [],
        }
        for f in findings:
            priority = SEVERITY_PRIORITY.get(f.severity, "P3 — Backlog")
            level = priority.split(" — ")[0]
            if level in summary:
                summary[level].append(f"{f.id}: {f.title}")
        return summary

    def _check_ollama(self) -> bool:
        """Check if Ollama is available."""
        if self._ollama_available is not None:
            return self._ollama_available

        import shutil
        if not shutil.which("ollama"):
            self._ollama_available = False
            return False

        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._ollama_available = result.returncode == 0
        except Exception:
            self._ollama_available = False

        return self._ollama_available

    def _get_ai_remediation(self, finding: Finding) -> str | None:
        """Get AI-powered fix suggestion via Ollama."""
        prompt = f"""You are a mobile security expert. Provide a concise, actionable fix for this security finding:

Title: {finding.title}
Description: {finding.description}
Platform: {finding.platform.value}
MASVS Category: {finding.masvs_category}
Severity: {finding.severity.value}
File: {finding.file or 'unknown'}

Provide:
1. A one-line fix summary
2. A code snippet showing the fix (in the app's language)
3. A brief explanation of why this matters

Keep it under 200 words. Be specific, not generic."""

        try:
            result = subprocess.run(
                ["ollama", "run", self.model, prompt],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

        return None