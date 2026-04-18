"""Report generation — HTML, PDF, SARIF, CycloneDX."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mobiussec import MASVS_CATEGORIES
from mobiussec.models import ScanResult, Severity, MASVSStatus


SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def generate_html_report(result: ScanResult) -> str:
    """Generate a full HTML security report."""
    platform_icon = "🤖" if result.platform.value == "android" else "🍎"
    platform_name = "Android" if result.platform.value == "android" else "iOS"

    # Findings table rows
    findings_rows = ""
    for f in sorted(result.findings, key=lambda x: x.severity.value):
        color = SEVERITY_COLORS.get(f.severity.value, "#6b7280")
        icon = SEVERITY_ICONS.get(f.severity.value, "•")
        findings_rows += f"""
        <tr>
          <td><span style="color:{color}">{icon} {f.severity.value.upper()}</span></td>
          <td>{f.id}</td>
          <td>{f.masvs_category}</td>
          <td>{f.title}</td>
          <td><code>{f.file or '—'}</code></td>
          <td>{f.remediation or '—'}</td>
        </tr>"""

    # MASVS compliance table
    masvs_rows = ""
    if result.masvs_result:
        scores = result.masvs_result.category_scores
        for cat in MASVS_CATEGORIES:
            s = scores.get(cat, {"pass": 0, "fail": 0, "warn": 0, "skip": 0})
            total = s["pass"] + s["fail"] + s["warn"]
            pct = f"{(s['pass'] / total * 100):.0f}%" if total > 0 else "N/A"
            bg = "#dcfce7" if total > 0 and s["fail"] == 0 else ("#fef9c3" if s["fail"] <= s["pass"] else "#fee2e2")
            masvs_rows += f"""
          <tr>
            <td><strong>{cat}</strong></td>
            <td>{s['pass']}</td>
            <td>{s['fail']}</td>
            <td>{s['warn']}</td>
            <td>{s['skip']}</td>
            <td style="background:{bg}"><strong>{pct}</strong></td>
          </tr>"""

    l1_status = "✅ PASS" if result.masvs_result and result.masvs_result.l1_ready else "❌ FAIL"
    l2_status = "✅ PASS" if result.masvs_result and result.masvs_result.l2_ready else "❌ FAIL"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MobiusSec Report — {result.app_name}</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    h1 {{ color: #38bdf8; margin-bottom: 0.5rem; }}
    h2 {{ color: #94a3b8; margin: 2rem 0 1rem; border-bottom: 1px solid #1e293b; padding-bottom: 0.5rem; }}
    .meta {{ color: #64748b; margin-bottom: 2rem; }}
    .stats {{ display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }}
    .stat {{ background: #1e293b; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }}
    .stat .number {{ font-size: 2rem; font-weight: bold; }}
    .stat .label {{ color: #64748b; font-size: 0.875rem; }}
    table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
    th {{ text-align: left; padding: 0.75rem; background: #1e293b; color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; }}
    td {{ padding: 0.75rem; border-bottom: 1px solid #1e293b; font-size: 0.875rem; }}
    tr:hover {{ background: #1e293b; }}
    code {{ background: #1e293b; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
    .pass {{ background: #166534; color: #dcfce7; }}
    .fail {{ background: #991b1b; color: #fee2e2; }}
    footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #1e293b; color: #475569; font-size: 0.75rem; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>{platform_icon} MobiusSec Security Report</h1>
    <div class="meta">
      <strong>{result.app_name}</strong> ({result.package_name}) · Version {result.version} · {platform_name}<br>
      Scanned: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · Scan time: {result.scan_time_seconds:.1f}s
    </div>

    <div class="stats">
      <div class="stat"><div class="number" style="color:#dc2626">{result.critical_count}</div><div class="label">Critical</div></div>
      <div class="stat"><div class="number" style="color:#ea580c">{result.high_count}</div><div class="label">High</div></div>
      <div class="stat"><div class="number" style="color:#ca8a04">{result.medium_count}</div><div class="label">Medium</div></div>
      <div class="stat"><div class="number" style="color:#2563eb">{result.low_count}</div><div class="label">Low</div></div>
      <div class="stat"><div class="number" style="color:#6b7280">{result.info_count}</div><div class="label">Info</div></div>
      <div class="stat"><div class="number" style="color:#38bdf8">{result.total_findings}</div><div class="label">Total</div></div>
    </div>

    <h2>OWASP MASVS 2.0 Compliance</h2>
    <table>
      <thead>
        <tr><th>Category</th><th>✅ Pass</th><th>❌ Fail</th><th>⚠️ Warn</th><th>⏭️ Skip</th><th>Score</th></tr>
      </thead>
      <tbody>
        {masvs_rows}
      </tbody>
    </table>
    <p style="margin:1rem 0">MASVS L1: <span class="badge {'pass' if 'PASS' in l1_status else 'fail'}">{l1_status}</span> · MASVS L2: <span class="badge {'pass' if 'PASS' in l2_status else 'fail'}">{l2_status}</span></p>

    <h2>Security Findings</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>ID</th><th>MASVS</th><th>Finding</th><th>File</th><th>Remediation</th></tr>
      </thead>
      <tbody>
        {findings_rows or '<tr><td colspan="6" style="text-align:center;color:#6b7280">No findings — app looks secure! 🎉</td></tr>'}
      </tbody>
    </table>

    <footer>
      Generated by MobiusSec v0.1.0 · <a href="https://github.com/aiagentmackenzie-lang/MobiusSec" style="color:#38bdf8">GitHub</a> · OWASP MASVS 2.0
    </footer>
  </div>
</body>
</html>"""
    return html


def generate_sarif_report(result: ScanResult) -> dict[str, Any]:
    """Generate a SARIF (Static Analysis Results Interchange Format) report."""
    rules: list[dict] = []
    results_list: list[dict] = []
    seen_rules: set[str] = set()

    for f in result.findings:
        if f.id not in seen_rules:
            seen_rules.add(f.id)
            rules.append({
                "id": f.id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": "https://mas.owasp.org/",
                "properties": {"security-severity": f.severity.value},
            })

        level = "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning"
        results_list.append({
            "ruleId": f.id,
            "level": level,
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file or "unknown"},
                    "region": {"startLine": f.line or 1},
                },
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "MobiusSec",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/aiagentmackenzie-lang/MobiusSec",
                    "rules": rules,
                },
            },
            "results": results_list,
        }],
    }


def generate_markdown_report(result: ScanResult) -> str:
    """Generate a Markdown security report."""
    platform_name = "Android" if result.platform.value == "android" else "iOS"
    lines = [
        f"# MobiusSec Security Report",
        f"",
        f"**{result.app_name}** ({result.package_name}) · Version {result.version} · {platform_name}",
        f"Scanned: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {result.critical_count} |",
        f"| 🟠 High | {result.high_count} |",
        f"| 🟡 Medium | {result.medium_count} |",
        f"| 🔵 Low | {result.low_count} |",
        f"| ⚪ Info | {result.info_count} |",
        f"| **Total** | **{result.total_findings}** |",
        f"",
    ]

    if result.masvs_result:
        lines.append("## OWASP MASVS 2.0 Compliance")
        lines.append("")
        lines.append("| Category | Pass | Fail | Warn | Score |")
        lines.append("|----------|------|------|------|-------|")
        scores = result.masvs_result.category_scores
        for cat in MASVS_CATEGORIES:
            s = scores.get(cat, {"pass": 0, "fail": 0, "warn": 0, "skip": 0})
            total = s["pass"] + s["fail"] + s["warn"]
            pct = f"{(s['pass'] / total * 100):.0f}%" if total > 0 else "N/A"
            lines.append(f"| {cat} | {s['pass']} | {s['fail']} | {s['warn']} | {pct} |")
        lines.append("")

    if result.findings:
        lines.append("## Findings")
        lines.append("")
        for f in sorted(result.findings, key=lambda x: x.severity.value):
            icon = SEVERITY_ICONS.get(f.severity.value, "•")
            lines.append(f"### {icon} [{f.severity.value.upper()}] {f.title}")
            lines.append(f"- **ID:** {f.id}")
            lines.append(f"- **MASVS:** {f.masvs_category} ({f.masvs_test_id})")
            lines.append(f"- **File:** `{f.file or 'unknown'}`")
            lines.append(f"- **Description:** {f.description}")
            if f.remediation:
                lines.append(f"- **Fix:** {f.remediation}")
            lines.append("")

    lines.append("---")
    lines.append("*Generated by MobiusSec v0.1.0 · OWASP MASVS 2.0*")
    return "\n".join(lines)