"""STIX 2.1 export — convert MobiusSec findings to STIX objects."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from mobiussec.models import ScanResult, Finding, Severity


def _make_id(stix_type: str) -> str:
    """Generate a STIX 2.1 compliant ID."""
    return f"{stix_type}--{uuid.uuid4()}"


def _severity_to_stix(severity: Severity) -> str:
    """Map MobiusSec severity to STIX 2.1 severity."""
    mapping = {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "none",
    }
    return mapping.get(severity, "none")


def export_stix(result: ScanResult) -> dict[str, Any]:
    """Export scan results as a STIX 2.1 bundle."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    objects: list[dict] = []

    # 1. Identity (MobiusSec as the tool)
    identity_id = _make_id("identity")
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "MobiusSec",
        "identity_class": "system",
        "description": "MobiusSec — Unified Mobile Security Platform",
    }
    objects.append(identity)

    # 2. Software (the app being scanned)
    software_id = _make_id("software")
    software = {
        "type": "software",
        "spec_version": "2.1",
        "id": software_id,
        "created": now,
        "modified": now,
        "name": result.app_name,
        "cpe": f"cpe:2.3:a:*:{result.package_name}:{result.version}",
        "swid": result.package_name,
        "vendor": result.package_name.split(".")[0] if "." in result.package_name else "unknown",
        "version": result.version,
    }
    objects.append(software)

    # 3. Vulnerability objects for each finding
    vulnerability_ids: list[str] = []
    for f in result.findings:
        vuln_id = _make_id("vulnerability")
        vulnerability_ids.append(vuln_id)

        vuln = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "name": f.title,
            "description": f.description,
            "external_references": [
                {
                    "source_name": "OWASP MASVS",
                    "external_id": f.masvs_test_id or f.masvs_category,
                    "url": f"https://mas.owasp.org/MASVS/controls/MASVS-{f.masvs_category}/",
                },
            ],
        }

        # Add CVREP-like severity via extensions
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
            vuln["extensions"] = {
                "extension-definition--2cb3aa60-6c1b-43f3-9c5c-8df6dc3257e4": {
                    "extension_type": "property-extension",
                    "severity": _severity_to_stix(f.severity),
                },
            }

        objects.append(vuln)

    # 4. Grouping (the scan itself)
    grouping_id = _make_id("grouping")
    grouping = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": grouping_id,
        "created_by_ref": identity_id,
        "created": now,
        "modified": now,
        "name": f"MobiusSec Scan: {result.app_name} v{result.version}",
        "description": f"Security scan of {result.app_name} ({result.package_name}) version {result.version}. "
                       f"Found {result.total_findings} findings ({result.critical_count} critical, "
                       f"{result.high_count} high, {result.medium_count} medium).",
        "context": "suspicious-activity",
        "object_refs": vulnerability_ids + [software_id],
    }
    objects.append(grouping)

    # 5. Report
    report_id = _make_id("report")
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created_by_ref": identity_id,
        "created": now,
        "modified": now,
        "name": f"Mobile Security Report — {result.app_name} v{result.version}",
        "published": now,
        "object_refs": [grouping_id, software_id] + vulnerability_ids,
        "confidence": 85,
        "labels": ["mobile-security", "owasp-masvs", result.platform.value],
    }
    objects.append(report)

    # 6. Relationship: vulnerabilities target the software
    for vuln_id in vulnerability_ids:
        rel_id = _make_id("relationship")
        rel = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "relationship_type": "targets",
            "source_ref": vuln_id,
            "target_ref": software_id,
        }
        objects.append(rel)

    # Bundle
    bundle = {
        "type": "bundle",
        "id": _make_id("bundle"),
        "objects": objects,
    }

    return bundle


def export_stix_json(result: ScanResult, indent: int = 2) -> str:
    """Export as STIX 2.1 JSON string."""
    return json.dumps(export_stix(result), indent=indent, default=str)