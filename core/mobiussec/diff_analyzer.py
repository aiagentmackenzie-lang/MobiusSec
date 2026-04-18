"""Diff analysis — compare two scan results across app versions."""

from __future__ import annotations

from typing import Any

from mobiussec.models import Finding, ScanResult, Severity


class DiffAnalyzer:
    """Compare two scan results to identify changes between app versions."""

    def __init__(self, result1: ScanResult, result2: ScanResult) -> None:
        self.result1 = result1  # Earlier version
        self.result2 = result2  # Newer version

    def diff(self) -> dict[str, Any]:
        """Compute the diff between two scan results."""
        findings1 = {f.id: f for f in self.result1.findings}
        findings2 = {f.id: f for f in self.result2.findings}

        ids1 = set(findings1.keys())
        ids2 = set(findings2.keys())

        added_ids = ids2 - ids1
        removed_ids = ids1 - ids2
        common_ids = ids1 & ids2

        added = [findings2[id] for id in added_ids]
        removed = [findings1[id] for id in removed_ids]

        # Check for severity changes in common findings
        severity_changes: list[dict[str, Any]] = []
        for id in common_ids:
            f1 = findings1[id]
            f2 = findings2[id]
            if f1.severity != f2.severity:
                severity_changes.append({
                    "id": id,
                    "title": f1.title,
                    "old_severity": f1.severity.value,
                    "new_severity": f2.severity.value,
                    "direction": "worse" if self._severity_worsened(f1.severity, f2.severity) else "improved",
                })

        # MASVS diff
        masvs_diff = self._diff_masvs()

        # Summary stats
        summary = {
            "v1": {
                "app": self.result1.app_name,
                "version": self.result1.version,
                "total_findings": self.result1.total_findings,
                "critical": self.result1.critical_count,
                "high": self.result1.high_count,
                "medium": self.result1.medium_count,
            },
            "v2": {
                "app": self.result2.app_name,
                "version": self.result2.version,
                "total_findings": self.result2.total_findings,
                "critical": self.result2.critical_count,
                "high": self.result2.high_count,
                "medium": self.result2.medium_count,
            },
            "delta": {
                "total": self.result2.total_findings - self.result1.total_findings,
                "critical": self.result2.critical_count - self.result1.critical_count,
                "high": self.result2.high_count - self.result1.high_count,
            },
        }

        return {
            "added": [self._finding_to_dict(f) for f in added],
            "removed": [self._finding_to_dict(f) for f in removed],
            "severity_changes": severity_changes,
            "masvs_diff": masvs_diff,
            "summary": summary,
            "verdict": self._compute_verdict(added, removed, severity_changes),
        }

    def _diff_masvs(self) -> dict[str, Any]:
        """Compare MASVS compliance between versions."""
        if not self.result1.masvs_result or not self.result2.masvs_result:
            return {}

        scores1 = self.result1.masvs_result.category_scores
        scores2 = self.result2.masvs_result.category_scores

        diff: dict[str, dict[str, int]] = {}
        for cat in scores1:
            s1 = scores1[cat]
            s2 = scores2.get(cat, {"pass": 0, "fail": 0, "warn": 0, "skip": 0})
            total1 = s1["pass"] + s1["fail"] + s1["warn"]
            total2 = s2["pass"] + s2["fail"] + s2["warn"]
            pct1 = (s1["pass"] / total1 * 100) if total1 > 0 else 0
            pct2 = (s2["pass"] / total2 * 100) if total2 > 0 else 0
            diff[cat] = round(pct2 - pct1, 1)

        return diff

    @staticmethod
    def _severity_worsened(old: Severity, new: Severity) -> bool:
        """Check if severity worsened."""
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        return order.get(new, 4) < order.get(old, 4)

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict[str, Any]:
        return {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "masvs_category": f.masvs_category,
            "file": f.file,
        }

    @staticmethod
    def _compute_verdict(
        added: list[Finding],
        removed: list[Finding],
        severity_changes: list[dict[str, Any]],
    ) -> str:
        """Compute an overall verdict for the diff."""
        critical_added = any(f.severity == Severity.CRITICAL for f in added)
        high_added = any(f.severity == Severity.HIGH for f in added)
        worsened = any(c["direction"] == "worse" for c in severity_changes)
        improved = any(c["direction"] == "improved" for c in severity_changes)

        if critical_added:
            return "🔴 REGRESSION — New critical findings introduced"
        if high_added or worsened:
            return "🟠 WARNING — New high findings or severity increases"
        if removed or improved:
            return "🟢 IMPROVED — Findings resolved or severity reduced"
        if not added and not removed and not severity_changes:
            return "⚪ UNCHANGED — No difference in findings"
        return "🟡 MIXED — Some changes, review recommended"