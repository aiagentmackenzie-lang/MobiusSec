"""Data models for MobiusSec."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from mobiussec import (
    MASVS_CATEGORIES,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    PLATFORM_ANDROID,
    PLATFORM_IOS,
    PLATFORM_UNKNOWN,
)


class Platform(str, Enum):
    ANDROID = PLATFORM_ANDROID
    IOS = PLATFORM_IOS
    UNKNOWN = PLATFORM_UNKNOWN


class Severity(str, Enum):
    CRITICAL = SEVERITY_CRITICAL
    HIGH = SEVERITY_HIGH
    MEDIUM = SEVERITY_MEDIUM
    LOW = SEVERITY_LOW
    INFO = SEVERITY_INFO


class MASVSStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    NA = "na"


@dataclass
class Finding:
    """A single security finding."""

    id: str
    title: str
    description: str
    severity: Severity
    masvs_category: str
    masvs_test_id: str = ""
    platform: Platform = Platform.UNKNOWN
    file: str = ""
    line: int = 0
    code_snippet: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    confidence: str = "high"  # high, medium, low

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "masvs_category": self.masvs_category,
            "masvs_test_id": self.masvs_test_id,
            "platform": self.platform.value,
            "file": self.file,
            "line": self.line,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "references": self.references,
            "confidence": self.confidence,
        }


@dataclass
class MASVSControl:
    """A single MASVS control and its test status."""

    category: str
    test_id: str
    test_name: str
    status: MASVSStatus = MASVSStatus.SKIP
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_passing(self) -> bool:
        return self.status == MASVSStatus.PASS


@dataclass
class MASVSResult:
    """MASVS compliance mapping for a scan."""

    platform: Platform
    controls: list[MASVSControl] = field(default_factory=list)

    @property
    def category_scores(self) -> dict[str, dict[str, int]]:
        """Return pass/fail/warn/skip counts per category."""
        scores: dict[str, dict[str, int]] = {cat: {"pass": 0, "fail": 0, "warn": 0, "skip": 0} for cat in MASVS_CATEGORIES}
        for ctrl in self.controls:
            if ctrl.category in scores:
                scores[ctrl.category][ctrl.status.value] += 1
        return scores

    @property
    def l1_ready(self) -> bool:
        """Check if app passes MASVS L1 requirements."""
        # L1 requires all STORAGE, CRYPTO, AUTH, NETWORK controls to pass
        critical_cats = {"STORAGE", "CRYPTO", "AUTH", "NETWORK"}
        for ctrl in self.controls:
            if ctrl.category in critical_cats and ctrl.status == MASVSStatus.FAIL:
                return False
        return True

    @property
    def l2_ready(self) -> bool:
        """Check if app passes MASVS L2 requirements."""
        if not self.l1_ready:
            return False
        # L2 also requires RESILIENCE and PRIVACY
        for ctrl in self.controls:
            if ctrl.category in {"RESILIENCE", "PRIVACY"} and ctrl.status == MASVSStatus.FAIL:
                return False
        return True


@dataclass
class ScanResult:
    """Complete result of a security scan."""

    app_path: str
    platform: Platform
    package_name: str = ""
    app_name: str = ""
    version: str = ""
    findings: list[Finding] = field(default_factory=list)
    masvs_result: MASVSResult | None = None
    scan_time_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def findings_by_category(self, category: str) -> list[Finding]:
        return [f for f in self.findings if f.masvs_category == category]

    def to_dict(self) -> dict[str, Any]:
        return {
            "app_path": self.app_path,
            "platform": self.platform.value,
            "package_name": self.package_name,
            "app_name": self.app_name,
            "version": self.version,
            "findings": [f.to_dict() for f in self.findings],
            "scan_time_seconds": self.scan_time_seconds,
            "errors": self.errors,
        }


@dataclass
class ScanConfig:
    """Configuration for a scan."""

    app_path: Path
    quick: bool = False
    gate_level: str = ""  # L1, L2, or empty
    fail_on: str = "high"  # critical, high, medium, low, info
    output_format: str = "rich"  # rich, json, sarif
    output_path: Path | None = None
    rules_dir: Path | None = None
    exclude_patterns: list[str] = field(default_factory=lambda: ["*.png", "*.jpg", "*.gif"])
    max_findings: int = 0  # 0 = unlimited