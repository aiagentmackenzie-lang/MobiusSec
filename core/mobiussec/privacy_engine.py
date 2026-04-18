"""Privacy engine — automated data collection mapping and SDK tracking."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from mobiussec import (
    MASVS_PRIVACY,
    MASVS_STORAGE,
    MASVS_NETWORK,
    MASVS_PLATFORM,
)
from mobiussec.models import Finding, Severity, Platform


# Known data-harvesting SDKs by category
TRACKING_SDKS: dict[str, dict[str, str]] = {
    "analytics": {
        "com.google.firebase.analytics": "Firebase Analytics — collects usage data, device info",
        "com.google.android.gms.analytics": "Google Analytics — collects usage data",
        "com.flurry": "Flurry Analytics — collects usage data, device info",
        "com.mixpanel": "Mixpanel — collects user behavior data",
        "com.amplitude": "Amplitude — collects user behavior data",
        "com.appsflyer": "AppsFlyer — attribution + tracking SDK",
        "com.adjust": "Adjust — attribution + tracking SDK",
        "com.branch": "Branch — deep linking + tracking",
        "io.fabric": "Fabric (Crashlytics) — collects crash + usage data",
        "com.sentry": "Sentry — collects crash + error data",
        "com.umeng": "Umeng — Chinese analytics SDK, known data collection",
        "com.tencent.bugly": "Bugly — Chinese crash reporting, data collection",
    },
    "ad_networks": {
        "com.google.android.gms.ads": "Google AdMob — advertising + tracking",
        "com.facebook.ads": "Facebook Audience Network — advertising + tracking",
        "com.mopub": "MoPub — advertising + tracking",
        "com.inmobi": "InMobi — advertising + tracking",
        "com.chartboost": "Chartboost — gaming ad network + tracking",
        "com.unity3d.ads": "Unity Ads — advertising + tracking",
        "com.ironsrc": "ironSource — advertising + tracking",
        "com.applovin": "AppLovin — advertising + tracking",
        "com.vungle": "Vungle — advertising + tracking",
        "com.adcolony": "AdColony — advertising + tracking",
    },
    "social": {
        "com.facebook": "Facebook SDK — extensive tracking + data collection",
        "com.facebook.login": "Facebook Login — identity tracking",
        "com.facebook.share": "Facebook Share — social graph tracking",
        "com.twitter": "Twitter SDK — tracking + data collection",
        "com.snap": "Snapchat SDK — tracking + data collection",
        "com.tencent.mm": "WeChat SDK — Chinese super-app, extensive data access",
        "io.wechat": "WeChat SDK — extensive data access",
    },
    "push": {
        "com.google.firebase.messaging": "Firebase Cloud Messaging — push notifications",
        "com.pushwoosh": "Pushwoosh — push notifications + tracking",
        "com.onesignal": "OneSignal — push notifications + analytics",
        "com.urbanairship": "Urban Airship — push notifications + location",
    },
    "payment": {
        "com.stripe": "Stripe — payment processing",
        "com.braintree": "Braintree — payment processing",
        "com.paypal": "PayPal — payment processing",
        "com.mercadopago": "Mercado Pago — LATAM payment processing",
    },
}

# Data types that apps can collect
DATA_TYPES = {
    # Android
    "android.permission.ACCESS_FINE_LOCATION": "Precise location (GPS)",
    "android.permission.ACCESS_COARSE_LOCATION": "Approximate location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Background location",
    "android.permission.READ_CONTACTS": "Contact list",
    "android.permission.READ_CALL_LOG": "Call history",
    "android.permission.READ_SMS": "SMS messages",
    "android.permission.CAMERA": "Camera access",
    "android.permission.RECORD_AUDIO": "Microphone access",
    "android.permission.READ_PHONE_STATE": "Phone state / device ID",
    "android.permission.READ_PHONE_NUMBERS": "Phone number",
    "android.permission.READ_CALENDAR": "Calendar data",
    "android.permission.BODY_SENSORS": "Health / body sensor data",
    "android.permission.ACTIVITY_RECOGNITION": "Activity / movement",
    "android.permission.READ_EXTERNAL_STORAGE": "File access (read)",
    # iOS equivalents (mapped from plist keys)
    "NSCameraUsageDescription": "Camera access",
    "NSMicrophoneUsageDescription": "Microphone access",
    "NSLocationWhenInUseUsageDescription": "Location (when in use)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Location (always)",
    "NSContactsUsageDescription": "Contact list",
    "NSCalendarsUsageDescription": "Calendar data",
    "NSHealthShareDescription": "Health data sharing",
    "NSMotionUsageDescription": "Motion / fitness data",
    "NSPhotoLibraryUsageDescription": "Photo library",
    "NSSpeechRecognitionUsageDescription": "Speech recognition data",
}

# Privacy regulation mappings
PRIVACY_REGULATIONS = {
    "lgpd": {
        "name": "Lei Geral de Proteção de Dados (Brazil)",
        "key_requirements": [
            "Data collection consent required",
            "Purpose limitation — collect only what's needed",
            "Data minimization",
            "Right to data deletion",
            "Data processing transparency",
        ],
    },
    "gdpr": {
        "name": "General Data Protection Regulation (EU)",
        "key_requirements": [
            "Lawful basis for processing",
            "Purpose limitation",
            "Data minimization",
            "Right to erasure",
            "Data Protection Impact Assessment for high-risk processing",
        ],
    },
    "ccpa": {
        "name": "California Consumer Privacy Act (US)",
        "key_requirements": [
            "Right to know what data is collected",
            "Right to delete personal information",
            "Right to opt-out of data selling",
            "Right to non-discrimination",
        ],
    },
}

# Network endpoints that suggest data exfiltration
DATA_EXFIL_ENDPOINTS = [
    (r"api\.mixpanel\.com", "Mixpanel analytics — user behavior data transmitted"),
    (r"api\.amplitude\.com", "Amplitude analytics — user behavior data transmitted"),
    (r"app\.adjust\.com", "Adjust attribution — device/location data transmitted"),
    (r"stats\.pushwoosh\.com", "Pushwoosh — device data transmitted"),
    (r"cdn\.mopub\.com", "MoPub — advertising data transmitted"),
    (r"graph\.facebook\.com", "Facebook Graph API — extensive user data"),
    (r"analytics\.google\.com", "Google Analytics — usage data transmitted"),
    (r"firebaselogging\.googleapis\.com", "Firebase logging — usage data transmitted"),
    (r"config\.firebase\.io", "Firebase config — app data transmitted"),
    (r"crashlytics\.com", "Crashlytics — crash + device data transmitted"),
    (r"umeng\.com", "Umeng — Chinese analytics, known privacy concerns"),
]


class PrivacyEngine:
    """Automated privacy and data-flow analysis for mobile apps."""

    def __init__(self, extracted_dir: Path, platform: Platform) -> None:
        self.extracted_dir = extracted_dir
        self.platform = platform
        self.findings: list[Finding] = []
        self.data_collected: list[dict[str, str]] = []
        self.detected_sdks: list[dict[str, str]] = []
        self.network_endpoints: list[dict[str, str]] = []
        self.compliance_gaps: list[dict[str, Any]] = []

    def analyze(self) -> dict[str, Any]:
        """Run full privacy analysis. Returns comprehensive privacy report."""
        self.findings = []
        self.data_collected = []
        self.detected_sdks = []
        self.network_endpoints = []
        self.compliance_gaps = []

        self._detect_data_collection()
        self._detect_tracking_sdks()
        self._detect_network_endpoints()
        self._check_overprivileged_permissions()
        self._check_consent_gaps()
        self._assess_compliance()

        return {
            "data_collected": self.data_collected,
            "detected_sdks": self.detected_sdks,
            "network_endpoints": self.network_endpoints,
            "compliance_gaps": self.compliance_gaps,
            "findings": self.findings,
            "privacy_score": self._calculate_privacy_score(),
        }

    def _detect_data_collection(self) -> None:
        """Detect what user data the app collects based on permissions and code."""
        if self.platform == Platform.ANDROID:
            self._detect_android_data_collection()
        elif self.platform == Platform.IOS:
            self._detect_ios_data_collection()

    def _detect_android_data_collection(self) -> None:
        """Detect data collection from Android manifest and source code."""
        # Parse manifest for permissions
        manifest_path = self.extracted_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return

        from lxml import etree
        try:
            tree = etree.parse(str(manifest_path))
            root = tree.getroot()
            ns = {"android": "http://schemas.android.com/apk/res/android"}

            for perm in root.findall(".//uses-permission"):
                name = perm.get(f"{{{ns['android']}}}name", "")
                if name in DATA_TYPES:
                    self.data_collected.append({
                        "type": name,
                        "description": DATA_TYPES[name],
                        "source": "manifest",
                    })
        except Exception:
            pass

        # Scan source for additional data access patterns
        data_access_patterns = [
            (r"getLocation\(\)", "Location data accessed programmatically"),
            (r"getDeviceId\(\)", "Device ID accessed programmatically"),
            (r"getSubscriberId\(\)", "Subscriber ID (IMSI) accessed"),
            (r"Settings\.Secure\.getString.*android_id", "Android ID accessed"),
            (r"AdvertisingIdClient", "Advertising ID accessed"),
            (r"\.getEmail\(\)|\.getProfile\(\)", "User email/profile accessed"),
            (r"ClipboardManager|getPrimaryClip", "Clipboard data accessed"),
        ]

        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.kt"))
        for src in source_files[:100]:
            try:
                content = src.read_text(errors="ignore")
                for pattern, desc in data_access_patterns:
                    if re.search(pattern, content):
                        already = any(d["description"] == desc for d in self.data_collected)
                        if not already:
                            self.data_collected.append({
                                "type": pattern,
                                "description": desc,
                                "source": str(src.relative_to(self.extracted_dir)),
                            })
            except Exception:
                continue

    def _detect_ios_data_collection(self) -> None:
        """Detect data collection from iOS Info.plist and source code."""
        import plistlib
        plist_path = None
        for p in self.extracted_dir.rglob("Info.plist"):
            plist_path = p
            break

        if not plist_path:
            return

        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.loads(f.read())

            for key in plist:
                if key in DATA_TYPES:
                    self.data_collected.append({
                        "type": key,
                        "description": DATA_TYPES[key],
                        "source": "Info.plist",
                    })

            # Check for IDFA usage
            if plist.get("NSUserTrackingUsageDescription"):
                self.data_collected.append({
                    "type": "IDFA",
                    "description": "Advertising Identifier (IDFA) — user tracking",
                    "source": "Info.plist",
                })
        except Exception:
            pass

    def _detect_tracking_sdks(self) -> None:
        """Detect known tracking/analytics SDKs in the app."""
        # Scan for SDK references in source, libs, and manifest
        all_content = self._get_all_source_content()

        for category, sdks in TRACKING_SDKS.items():
            for sdk_id, description in sdks.items():
                # Check in source code references
                if sdk_id in all_content or sdk_id.replace(".", "/") in all_content:
                    self.detected_sdks.append({
                        "id": sdk_id,
                        "description": description,
                        "category": category,
                    })

        # Also check for SDK JAR/AAR/framework files
        for ext in ["*.jar", "*.aar", "*.framework", "*.dylib"]:
            for f in self.extracted_dir.rglob(ext):
                name = f.stem.lower()
                for category, sdks in TRACKING_SDKS.items():
                    for sdk_id, description in sdks.items():
                        short_name = sdk_id.split(".")[-1]
                        if short_name in name:
                            already = any(s["id"] == sdk_id for s in self.detected_sdks)
                            if not already:
                                self.detected_sdks.append({
                                    "id": sdk_id,
                                    "description": description,
                                    "category": category,
                                })

        # Generate findings for high-risk SDKs
        high_risk_categories = {"ad_networks", "social", "analytics"}
        for sdk in self.detected_sdks:
            if sdk["category"] in high_risk_categories:
                self.findings.append(Finding(
                    id=f"PRIV-SDK-{sdk['id'].split('.')[-1][:10]}",
                    title=f"Tracking SDK detected: {sdk['id'].split('.')[-1]}",
                    description=sdk["description"],
                    severity=Severity.MEDIUM,
                    masvs_category=MASVS_PRIVACY,
                    masvs_test_id="MASTG-PRIVACY-4",
                    platform=self.platform,
                    remediation="Review SDK data collection practices. Add consent dialogs before SDK initialization. Consider privacy-preserving alternatives.",
                ))

    def _detect_network_endpoints(self) -> None:
        """Detect network endpoints that may transmit user data."""
        all_content = self._get_all_source_content()

        for pattern, desc in DATA_EXFIL_ENDPOINTS:
            if re.search(pattern, all_content):
                self.network_endpoints.append({
                    "pattern": pattern,
                    "description": desc,
                })
                self.findings.append(Finding(
                    id=f"PRIV-NET-{pattern[:15].replace('.', '-')}",
                    title=f"Data transmission endpoint: {pattern}",
                    description=desc,
                    severity=Severity.MEDIUM,
                    masvs_category=MASVS_NETWORK,
                    masvs_test_id="MASTG-PRIVACY-3",
                    platform=self.platform,
                    remediation="Review data sent to this endpoint. Ensure user consent is obtained. Consider local/privacy-preserving alternatives.",
                ))

    def _check_overprivileged_permissions(self) -> None:
        """Check if app requests more permissions than it likely uses."""
        requested = {d["type"] for d in self.data_collected if d["source"] in ("manifest", "Info.plist")}

        # Heuristic: apps requesting 5+ sensitive data types are likely over-privileged
        sensitive_count = sum(1 for d in self.data_collected if d["source"] in ("manifest", "Info.plist"))

        if sensitive_count >= 5:
            self.findings.append(Finding(
                id="PRIV-OVER-001",
                title="App may be over-privileged",
                description=f"App requests access to {sensitive_count} sensitive data types. Review if all are genuinely needed.",
                severity=Severity.HIGH,
                masvs_category=MASVS_PRIVACY,
                masvs_test_id="MASTG-PRIVACY-2",
                platform=self.platform,
                remediation="Apply data minimization — request only permissions essential for core functionality. Remove unused permissions.",
            ))

    def _check_consent_gaps(self) -> None:
        """Check for missing consent mechanisms."""
        if self.platform == Platform.IOS:
            self._check_ios_consent_gaps()
        elif self.platform == Platform.ANDROID:
            self._check_android_consent_gaps()

    def _check_ios_consent_gaps(self) -> None:
        """Check for missing iOS privacy descriptions (required by App Store)."""
        import plistlib
        plist_path = None
        for p in self.extracted_dir.rglob("Info.plist"):
            plist_path = p
            break

        if not plist_path:
            return

        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.loads(f.read())

            # If IDFA is used but no tracking description
            if self.detected_sdks and "NSUserTrackingUsageDescription" not in plist:
                has_ads_sdk = any(s["category"] == "ad_networks" for s in self.detected_sdks)
                if has_ads_sdk:
                    self.findings.append(Finding(
                        id="PRIV-CONSENT-001",
                        title="Missing App Tracking Transparency description",
                        description="App uses advertising SDKs but has no NSUserTrackingUsageDescription. Required by App Store since iOS 14.5.",
                        severity=Severity.HIGH,
                        masvs_category=MASVS_PRIVACY,
                        masvs_test_id="MASTG-PRIVACY-1",
                        platform=Platform.IOS,
                        remediation="Add NSUserTrackingUsageDescription to Info.plist and request user consent before tracking.",
                    ))
        except Exception:
            pass

    def _check_android_consent_gaps(self) -> None:
        """Check for missing Android consent mechanisms."""
        # Check for runtime permission requests
        source_files = list(self.extracted_dir.rglob("*.java")) + list(self.extracted_dir.rglob("*.kt"))
        has_runtime_permissions = False

        for src in source_files[:100]:
            try:
                content = src.read_text(errors="ignore")
                if "requestPermissions" in content or "ActivityResultContracts.RequestPermission" in content:
                    has_runtime_permissions = True
                    break
            except Exception:
                continue

        if self.data_collected and not has_runtime_permissions:
            # App collects data but doesn't show runtime permission flow
            # This is okay for Android since the system handles it, but worth noting
            sensitive_perms = [d for d in self.data_collected if d["source"] == "manifest"]
            if len(sensitive_perms) >= 3:
                self.findings.append(Finding(
                    id="PRIV-CONSENT-002",
                    title="No explicit permission request flow detected",
                    description=f"App requests {len(sensitive_perms)} sensitive permissions. Consider adding explicit consent UI before requesting.",
                    severity=Severity.LOW,
                    masvs_category=MASVS_PRIVACY,
                    masvs_test_id="MASTG-PRIVACY-1",
                    platform=Platform.ANDROID,
                    remediation="Implement a permission request flow that explains why each permission is needed before requesting it.",
                ))

    def _assess_compliance(self) -> None:
        """Assess compliance with privacy regulations."""
        for reg_key, reg_info in PRIVACY_REGULATIONS.items():
            gaps: list[str] = []

            # Check if data collection is transparent
            if not self.data_collected:
                continue  # No data collected = no compliance concern

            # LGPD / GDPR: purpose limitation
            if len(self.data_collected) >= 5:
                gaps.append("Large data collection scope — may violate purpose limitation / data minimization")

            # Check for tracking SDKs
            tracking_sdks = [s for s in self.detected_sdks if s["category"] in ("analytics", "ad_networks", "social")]
            if tracking_sdks:
                gaps.append(f"Tracking SDKs detected ({len(tracking_sdks)}) — consent required before initialization")

            # Check for cross-border data transfer (non-local endpoints)
            if self.network_endpoints:
                gaps.append("Data transmitted to external endpoints — verify cross-border transfer compliance")

            if gaps:
                self.compliance_gaps.append({
                    "regulation": reg_key,
                    "name": reg_info["name"],
                    "gaps": gaps,
                })

                self.findings.append(Finding(
                    id=f"PRIV-{reg_key.upper()}-001",
                    title=f"{reg_info['name']}: potential compliance gaps",
                    description=f"Found {len(gaps)} potential gaps: {'; '.join(gaps[:3])}",
                    severity=Severity.MEDIUM,
                    masvs_category=MASVS_PRIVACY,
                    masvs_test_id="MASTG-PRIVACY-3",
                    platform=self.platform,
                    remediation=f"Review {reg_info['name']} requirements: {'; '.join(reg_info['key_requirements'][:3])}",
                ))

    def _calculate_privacy_score(self) -> int:
        """Calculate a privacy score from 0-100 (100 = best privacy)."""
        score = 100

        # Deductions for data collection
        score -= min(len(self.data_collected) * 5, 30)

        # Deductions for tracking SDKs
        tracking_count = len([s for s in self.detected_sdks if s["category"] in ("analytics", "ad_networks", "social")])
        score -= min(tracking_count * 10, 30)

        # Deductions for compliance gaps
        score -= min(len(self.compliance_gaps) * 10, 20)

        # Deductions for network endpoints
        score -= min(len(self.network_endpoints) * 5, 10)

        return max(score, 0)

    def _get_all_source_content(self) -> str:
        """Get concatenated source content for pattern matching (capped at 500KB)."""
        chunks: list[str] = []
        total_size = 0
        max_size = 500_000

        patterns = ["*.java", "*.kt", "*.swift", "*.m", "*.xml", "*.json", "*.plist"]
        for pattern in patterns:
            for f in self.extracted_dir.rglob(pattern):
                try:
                    content = f.read_text(errors="ignore")
                    if total_size + len(content) > max_size:
                        chunks.append(content[:max_size - total_size])
                        break
                    chunks.append(content)
                    total_size += len(content)
                except Exception:
                    continue
            if total_size >= max_size:
                break

        return "\n".join(chunks)