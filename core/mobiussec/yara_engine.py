"""YARA integration — APKiD rules + custom malware detection rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mobiussec import MASVS_RESILIENCE, MASVS_CODE
from mobiussec.models import Finding, Severity, Platform


# Built-in YARA rules for Android packer/malware detection
# These are embedded so the tool works without external YARA rule files
ANDROID_YARA_RULES = r"""
rule android_packer_dexguard {
    meta:
        description = "DexGuard packer detected"
        severity = "info"
        category = "RESILIENCE"
    strings:
        $s1 = "com.dexguard" ascii
        $s2 = "DexGuard" ascii
    condition:
        any of them
}

rule android_packer_proguard {
    meta:
        description = "ProGuard obfuscation detected"
        severity = "info"
        category = "RESILIENCE"
    strings:
        $s1 = "proguard" ascii nocase
        $s2 = "a.a.a" ascii
        $s3 = "b.b.b" ascii
    condition:
        $s1 or (#s2 > 5) or (#s3 > 5)
}

rule android_packer_apkprotect {
    meta:
        description = "APKProtect packer detected"
        severity = "medium"
        category = "RESILIENCE"
    strings:
        $s1 = "com.apkprotect" ascii
        $s2 = "APKProtect" ascii
    condition:
        any of them
}

rule android_packer_bangcle {
    meta:
        description = "Bangcle packer detected"
        severity = "medium"
        category = "RESILIENCE"
    strings:
        $s1 = "com.bangcle" ascii
        $s2 = "bangcle" ascii nocase
    condition:
        any of them
}

rule android_packer_ijiami {
    meta:
        description = "ijiami packer detected"
        severity = "medium"
        category = "RESILIENCE"
    strings:
        $s1 = "ijiami" ascii nocase
    condition:
        $s1
}

rule android_packer_360jiagu {
    meta:
        description = "360 Jiagu packer detected"
        severity = "medium"
        category = "RESILIENCE"
    strings:
        $s1 = "com.stub" ascii
        $s2 = "jiagu" ascii nocase
        $s3 = "360" ascii
    condition:
        $s1 or ($s2 and $s3)
}

rule android_packer_tencent_legu {
    meta:
        description = "Tencent Legu packer detected"
        severity = "medium"
        category = "RESILIENCE"
    strings:
        $s1 = "tencent" ascii nocase
        $s2 = "legu" ascii nocase
        $s3 = "com.tencent.bugly" ascii
    condition:
        ($s1 and $s2) or $s3
}

rule android_root_detection {
    meta:
        description = "Root detection implementation found"
        severity = "info"
        category = "RESILIENCE"
    strings:
        $s1 = "su" ascii
        $s2 = "/system/app/Superuser.apk" ascii
        $s3 = "isDeviceRooted" ascii
        $s4 = "checkRoot" ascii
        $s5 = "RootBeer" ascii
    condition:
        (#s1 > 3) or any of ($s2, $s3, $s4, $s5)
}

rule android_debug_detection {
    meta:
        description = "Anti-debug implementation found"
        severity = "info"
        category = "RESILIENCE"
    strings:
        $s1 = "android.os.Debug" ascii
        $s2 = "isDebuggerConnected" ascii
        $s3 = "TracerPid" ascii
    condition:
        any of them
}

rule android_emulator_detection {
    meta:
        description = "Emulator detection found"
        severity = "info"
        category = "RESILIENCE"
    strings:
        $s1 = "goldfish" ascii
        $s2 = "sdk" ascii nocase
        $s3 = "generic" ascii
        $s4 = "EmulatorDetector" ascii
        $s5 = "isEmulator" ascii
    condition:
        any of ($s4, $s5) or (#s1 > 0 and #s2 > 0)
}

rule android_sms_stealer {
    meta:
        description = "Potential SMS-stealing malware behavior"
        severity = "high"
        category = "CODE"
    strings:
        $s1 = "READ_SMS" ascii
        $s2 = "SEND_SMS" ascii
        $s3 = "RECEIVE_SMS" ascii
        $s4 = "abortBroadcast" ascii
        $s5 = "android.telephony.SmsMessage" ascii
    condition:
        ($s1 or $s3) and $s5 and $s4
}

rule android_accessibility_malware {
    meta:
        description = "Accessibility service abuse — potential overlay/banking malware"
        severity = "high"
        category = "CODE"
    strings:
        $s1 = "AccessibilityService" ascii
        $s2 = "performGlobalAction" ascii
        $s3 = "dispatchGesture" ascii
        $s4 = "onAccessibilityEvent" ascii
    condition:
        $s1 and ($s2 or $s3) and $s4
}

rule android_device_admin_abuse {
    meta:
        description = "Device admin abuse — potential ransomware/lockware"
        severity = "high"
        category = "CODE"
    strings:
        $s1 = "DeviceAdminReceiver" ascii
        $s2 = "DevicePolicyManager" ascii
        $s3 = "lockNow" ascii
        $s4 = "wipeData" ascii
        $s5 = "resetPassword" ascii
    condition:
        $s1 and $s2 and ($s3 or $s4 or $s5)
}

rule android_clipboard_malware {
    meta:
        description = "Clipboard monitoring — potential crypto wallet address replacement"
        severity = "medium"
        category = "CODE"
    strings:
        $s1 = "ClipboardManager" ascii
        $s2 = "OnPrimaryClipChangedListener" ascii
        $s3 = "setPrimaryClip" ascii
    condition:
        $s1 and $s2
}
"""

# iOS YARA rules
IOS_YARA_RULES = r"""
rule ios_jailbreak_detection {
    meta:
        description = "Jailbreak detection implementation found"
        severity = "info"
        category = "RESILIENCE"
    strings:
        $s1 = "/Applications/Cydia.app" ascii
        $s2 = "/usr/sbin/sshd" ascii
        $s3 = "/bin/bash" ascii
        $s4 = "cydia://" ascii
        $s5 = "isJailbroken" ascii
        $s6 = "checkJailbreak" ascii
    condition:
        any of ($s5, $s6) or (#s1 > 0 and #s2 > 0)
}

rule ios_anti_debug {
    meta:
        description = "Anti-debug implementation found"
        severity = "info"
        category = "RESILIENCE"
    strings:
        $s1 = "ptrace" ascii
        $s2 = "PT_DENY_ATTACH" ascii
        $s3 = "sysctl" ascii
    condition:
        $s1 or ($s2 and $s3)
}

rule ios_spyware_indicator {
    meta:
        description = "Potential spyware indicators"
        severity = "high"
        category = "CODE"
    strings:
        $s1 = "CTTelephonyCenterGetDefault" ascii
        $s2 = "kCTRegistrationDataStatus" ascii
        $s3 = "IOKit" ascii
        $s4 = "MobileGestalt" ascii
    condition:
        ($s1 and $s2) or (#s3 > 5 and #s4 > 5)
}

rule ios_keychain_dumper {
    meta:
        description = "Keychain dumping functionality detected"
        severity = "high"
        category = "CODE"
    strings:
        $s1 = "SecItemCopyMatching" ascii
        $s2 = "kSecClass" ascii
        $s3 = "kSecMatchLimitAll" ascii
    condition:
        $s1 and $s2 and $s3
}
"""


class YARAEngine:
    """YARA-based pattern matching for mobile security analysis."""

    def __init__(self, extracted_dir: Path, platform: Platform) -> None:
        self.extracted_dir = extracted_dir
        self.platform = platform
        self.findings: list[Finding] = []
        self._yara_available = False
        self._rules = None

        # Try to import yara
        try:
            import yara
            self._yara_available = True
            self._yara = yara
        except ImportError:
            self._yara_available = False

    def scan(self) -> list[Finding]:
        """Run YARA rules against the extracted app."""
        self.findings = []

        if not self._yara_available:
            # Fallback: use regex-based pattern matching
            return self._scan_with_regex()

        return self._scan_with_yara()

    def _scan_with_yara(self) -> list[Finding]:
        """Scan using yara-python library."""
        import yara

        # Compile rules
        rules_text = ANDROID_YARA_RULES if self.platform == Platform.ANDROID else IOS_YARA_RULES

        try:
            rules = yara.compile(source=rules_text)
        except yara.Error:
            return self._scan_with_regex()

        # Scan extracted directory
        for file_path in self.extracted_dir.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip large files and binary blobs
            try:
                if file_path.stat().st_size > 10_000_000:  # 10MB limit
                    continue
            except OSError:
                continue

            try:
                matches = rules.match(str(file_path), timeout=30)
                for match in matches:
                    severity_str = match.meta.get("severity", "info")
                    severity = self._parse_severity(severity_str)
                    category = match.meta.get("category", "CODE")

                    self.findings.append(Finding(
                        id=f"YARA-{match.rule[:20]}",
                        title=match.meta.get("description", match.rule),
                        description=f"YARA rule '{match.rule}' matched in {file_path.name}",
                        severity=severity,
                        masvs_category=category,
                        masvs_test_id=f"MASTG-{category}-5",
                        platform=self.platform,
                        file=str(file_path.relative_to(self.extracted_dir)),
                        confidence="medium",
                    ))
            except Exception:
                continue

        return self.findings

    def _scan_with_regex(self) -> list[Finding]:
        """Fallback: scan using regex when yara-python is not available."""
        import re

        # Parse YARA rules into simplified regex patterns
        if self.platform == Platform.ANDROID:
            rule_text = ANDROID_YARA_RULES
        else:
            rule_text = IOS_YARA_RULES

        # Extract rule definitions
        rule_pattern = re.compile(
            r'rule\s+(\w+)\s*\{[^}]*?meta:[^}]*?description\s*=\s*"([^"]+)"[^}]*?severity\s*=\s*"([^"]+)"[^}]*?category\s*=\s*"([^"]+)"[^}]*?strings:[^}]*?\$s\d+\s*=\s*"([^"]+)"[^}]*?condition:[^}]*?\}',
            re.DOTALL,
        )

        # Get all file content (capped)
        all_content = self._get_all_content()

        # Simple pattern matching against known bad strings
        patterns = {
            "android": {
                "com.dexguard": ("DexGuard packer detected", "info", "RESILIENCE"),
                "DexGuard": ("DexGuard packer detected", "info", "RESILIENCE"),
                "isDeviceRooted": ("Root detection found", "info", "RESILIENCE"),
                "RootBeer": ("Root detection library (RootBeer)", "info", "RESILIENCE"),
                "isDebuggerConnected": ("Anti-debug check found", "info", "RESILIENCE"),
                "abortBroadcast": ("SMS broadcast abort — potential SMS malware", "high", "CODE"),
                "AccessibilityService": ("Accessibility service — potential malware", "medium", "CODE"),
                "lockNow": ("Device lock — potential ransomware behavior", "high", "CODE"),
                "ClipboardManager": ("Clipboard access detected", "medium", "CODE"),
            },
            "ios": {
                "Cydia.app": ("Jailbreak check — Cydia reference", "info", "RESILIENCE"),
                "isJailbroken": ("Jailbreak detection found", "info", "RESILIENCE"),
                "PT_DENY_ATTACH": ("Anti-debug (ptrace deny)", "info", "RESILIENCE"),
                "SecItemCopyMatching": ("Keychain access — bulk query possible", "medium", "CODE"),
            },
        }

        platform_patterns = patterns.get(self.platform.value, {})
        for pattern, (desc, severity_str, category) in platform_patterns.items():
            if pattern.lower() in all_content.lower():
                severity = self._parse_severity(severity_str)
                self.findings.append(Finding(
                    id=f"YARA-{pattern[:15].replace(' ', '-')}",
                    title=desc,
                    description=f"Pattern '{pattern}' found in app content. {desc}.",
                    severity=severity,
                    masvs_category=category,
                    masvs_test_id=f"MASTG-{category}-5",
                    platform=self.platform,
                    confidence="low",
                ))

        return self.findings

    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to Severity enum."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(severity_str.lower(), Severity.INFO)

    def _get_all_content(self, max_size: int = 1_000_000) -> str:
        """Get concatenated text content from extracted app (capped)."""
        chunks: list[str] = []
        total = 0

        text_patterns = ["*.xml", "*.java", "*.kt", "*.smali", "*.swift", "*.m", "*.h", "*.plist", "*.json"]
        for pattern in text_patterns:
            for f in self.extracted_dir.rglob(pattern):
                try:
                    content = f.read_text(errors="ignore")
                    remaining = max_size - total
                    if remaining <= 0:
                        break
                    chunks.append(content[:remaining])
                    total += len(content[:remaining])
                except Exception:
                    continue
            if total >= max_size:
                break

        return "\n".join(chunks)