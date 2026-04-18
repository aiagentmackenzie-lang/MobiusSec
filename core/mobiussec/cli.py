"""MobiusSec CLI — Unified Mobile Security Platform."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from mobiussec import MASVS_CATEGORIES
from mobiussec.models import ScanConfig, Severity, MASVSStatus
from mobiussec.scanner import Scanner
from mobiussec.reports import generate_html_report, generate_sarif_report, generate_markdown_report
from mobiussec.diff_analyzer import DiffAnalyzer
from mobiussec.remediation import RemediationEngine

app = typer.Typer(
    name="mobius",
    help="MobiusSec — Unified Mobile Security Platform. One tool. Both platforms. No escape.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _detect_platform(path: Path) -> str:
    """Detect platform from file extension."""
    name = path.name.lower()
    if name.endswith(".apk"):
        return "android"
    elif name.endswith(".ipa"):
        return "ios"
    return "unknown"


@app.command()
def scan(
    app_path: Annotated[str, typer.Argument(help="Path to APK or IPA file")],
    quick: Annotated[bool, typer.Option("--quick", "-q", help="Quick scan — critical/high findings only")] = False,
    gate: Annotated[Optional[str], typer.Option("--gate", "-g", help="MASVS gate level: L1 or L2")] = None,
    fail_on: Annotated[str, typer.Option("--fail-on", help="Fail on severity: critical, high, medium, low")] = "high",
    output: Annotated[Optional[str], typer.Option("--output", "-o", help="Output file path (JSON)")] = None,
    format: Annotated[str, typer.Option("--format", "-f", help="Output format: rich, json")] = "rich",
) -> None:
    """Scan an Android APK or iOS IPA for security vulnerabilities."""

    path = Path(app_path)
    if not path.exists():
        console.print(f"[red]Error: File not found: {app_path}[/red]")
        raise typer.Exit(1)

    platform = _detect_platform(path)
    if platform == "unknown":
        console.print(f"[red]Error: Unsupported file type. Use .apk or .ipa files.[/red]")
        raise typer.Exit(1)

    # Header
    console.print()
    console.print(Panel.fit(
        f"[bold]MobiusSec[/bold] — Unified Mobile Security Platform\n"
        f"[dim]One tool. Both platforms. No escape.[/dim]",
        border_style="bright_blue",
    ))
    console.print(f"\n  📱 Scanning: [bold]{path.name}[/bold]")
    console.print(f"  📲 Platform: [bold]{platform.upper()}[/bold]")
    console.print(f"  ⚡ Mode: {'Quick' if quick else 'Full'}")
    if gate:
        console.print(f"  🚧 Gate: MASVS {gate.upper()}")
    console.print()

    # Configure and run scan
    config = ScanConfig(
        app_path=path,
        quick=quick,
        gate_level=gate or "",
        fail_on=fail_on,
        output_format=format,
        output_path=Path(output) if output else None,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Extracting app...", total=None)
        scanner = Scanner(config)
        result = scanner.scan()

    # Display results
    if format == "json":
        _output_json(result, config)
    else:
        _display_rich(result, config)

    # Gate check
    if gate:
        gate_code = scanner.check_gate(result)
        if gate_code != 0:
            console.print(f"\n[bold red]🚧 MASVS {gate.upper()} gate: FAILED[/bold red]")
            raise typer.Exit(1)
        else:
            console.print(f"\n[bold green]✅ MASVS {gate.upper()} gate: PASSED[/bold green]")


@app.command()
def masvs(
    app_path: Annotated[str, typer.Argument(help="Path to APK or IPA file")],
) -> None:
    """Show OWASP MASVS 2.0 compliance status for an app."""

    path = Path(app_path)
    if not path.exists():
        console.print(f"[red]Error: File not found: {app_path}[/red]")
        raise typer.Exit(1)

    platform = _detect_platform(path)
    if platform == "unknown":
        console.print(f"[red]Error: Unsupported file type.[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(Panel.fit(
        "[bold]MobiusSec MASVS Compliance[/bold]",
        border_style="bright_blue",
    ))

    config = ScanConfig(app_path=path)
    scanner = Scanner(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(description="Scanning...", total=None)
        result = scanner.scan()

    if not result.masvs_result:
        console.print("[red]No MASVS result available.[/red]")
        raise typer.Exit(1)

    # MASVS compliance table
    table = Table(title="OWASP MASVS 2.0 Compliance", show_header=True, header_style="bold cyan")
    table.add_column("Category", style="bold")
    table.add_column("✅ Pass", justify="right")
    table.add_column("❌ Fail", justify="right")
    table.add_column("⚠️ Warn", justify="right")
    table.add_column("⏭️ Skip", justify="right")
    table.add_column("Score", justify="right", style="bold")

    scores = result.masvs_result.category_scores
    for category in MASVS_CATEGORIES:
        s = scores.get(category, {"pass": 0, "fail": 0, "warn": 0, "skip": 0})
        total = s["pass"] + s["fail"] + s["warn"]
        score_pct = f"{(s['pass'] / total * 100):.0f}%" if total > 0 else "N/A"
        score_color = "green" if total > 0 and s["fail"] == 0 else ("yellow" if s["fail"] <= s["pass"] else "red")

        table.add_row(
            category,
            str(s["pass"]),
            str(s["fail"]),
            str(s["warn"]),
            str(s["skip"]),
            f"[{score_color}]{score_pct}[/{score_color}]",
        )

    console.print(table)

    # L1/L2 status
    console.print()
    l1 = "✅ PASS" if result.masvs_result.l1_ready else "❌ FAIL"
    l2 = "✅ PASS" if result.masvs_result.l2_ready else "❌ FAIL"
    console.print(f"  MASVS L1: {l1}")
    console.print(f"  MASVS L2: {l2}")
    console.print()

    # Per-test detail table
    detail_table = Table(title="Per-Test Status", show_header=True, header_style="bold cyan")
    detail_table.add_column("Test ID", style="dim")
    detail_table.add_column("Category")
    detail_table.add_column("Test Name")
    detail_table.add_column("Status", justify="center")

    status_colors = {
        MASVSStatus.PASS: "green",
        MASVSStatus.FAIL: "red",
        MASVSStatus.WARN: "yellow",
        MASVSStatus.SKIP: "dim",
        MASVSStatus.NA: "dim",
    }

    for ctrl in result.masvs_result.controls:
        if ctrl.status != MASVSStatus.SKIP:
            color = status_colors.get(ctrl.status, "white")
            detail_table.add_row(
                ctrl.test_id,
                ctrl.category,
                ctrl.test_name,
                f"[{color}]{ctrl.status.value.upper()}[/{color}]",
            )

    if detail_table.rows:
        console.print(detail_table)


@app.command()
def diff(
    app1: Annotated[str, typer.Argument(help="Path to first APK/IPA (older version)")],
    app2: Annotated[str, typer.Argument(help="Path to second APK/IPA (newer version)")],
) -> None:
    """Compare two app versions for security differences."""
    path1, path2 = Path(app1), Path(app2)
    for p in [path1, path2]:
        if not p.exists():
            console.print(f"[red]Error: File not found: {p}[/red]")
            raise typer.Exit(1)

    console.print()
    console.print(Panel.fit("[bold]MobiusSec Diff Analysis[/bold]", border_style="bright_magenta"))
    console.print(f"  📦 v1: {path1.name}")
    console.print(f"  📦 v2: {path2.name}")
    console.print()

    config1 = ScanConfig(app_path=path1)
    config2 = ScanConfig(app_path=path2)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
        progress.add_task(description="Scanning v1...", total=None)
        scanner1 = Scanner(config1)
        result1 = scanner1.scan()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console, transient=True) as progress:
        progress.add_task(description="Scanning v2...", total=None)
        scanner2 = Scanner(config2)
        result2 = scanner2.scan()

    analyzer = DiffAnalyzer(result1, result2)
    diff_result = analyzer.diff()

    # Verdict
    verdict = diff_result["verdict"]
    console.print(f"  Verdict: {verdict}")
    console.print()

    # Summary
    summary = diff_result["summary"]
    table = Table(title="Version Comparison", show_header=True, header_style="bold cyan")
    table.add_column("Metric")
    table.add_column("v1", justify="right")
    table.add_column("v2", justify="right")
    table.add_column("Delta", justify="right")
    table.add_row("Total findings", str(summary["v1"]["total_findings"]), str(summary["v2"]["total_findings"]), str(summary["delta"]["total"]))
    table.add_row("Critical", str(summary["v1"]["critical"]), str(summary["v2"]["critical"]), str(summary["delta"]["critical"]), style="red" if summary["delta"]["critical"] > 0 else "green")
    table.add_row("High", str(summary["v1"]["high"]), str(summary["v2"]["high"]), str(summary["delta"]["high"]), style="red" if summary["delta"]["high"] > 0 else "green")
    console.print(table)

    # New findings
    added = diff_result["added"]
    if added:
        console.print(f"\n  [red]🆕 {len(added)} new findings:[/red]")
        for f in added[:10]:
            console.print(f"    • [{SEVERITY_COLORS.get(f['severity'], 'white')}]{f['severity'].upper()}[/{SEVERITY_COLORS.get(f['severity'], 'white')}] {f['title']}")

    # Fixed findings
    removed = diff_result["removed"]
    if removed:
        console.print(f"\n  [green]✅ {len(removed)} findings fixed:[/green]")
        for f in removed[:10]:
            console.print(f"    • {f['title']}")

    # Severity changes
    changes = diff_result["severity_changes"]
    if changes:
        console.print(f"\n  [yellow]🔄 {len(changes)} severity changes:[/yellow]")
        for c in changes:
            direction = "⬆️ worsened" if c["direction"] == "worse" else "⬇️ improved"
            console.print(f"    • {c['id']}: {c['old_severity']} → {c['new_severity']} ({direction})")


@app.command()
def fix(
    app_path: Annotated[str, typer.Argument(help="Path to APK or IPA file")],
    finding_id: Annotated[Optional[str], typer.Option("--finding", "-f", help="Specific finding ID to get fix for")] = None,
    ai: Annotated[bool, typer.Option("--ai", help="Use AI (Ollama) for remediation suggestions")] = False,
) -> None:
    """Get AI-powered remediation suggestions for findings."""
    path = Path(app_path)
    if not path.exists():
        console.print(f"[red]Error: File not found: {app_path}[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(Panel.fit("[bold]MobiusSec Remediation Engine[/bold]", border_style="bright_green"))

    config = ScanConfig(app_path=path)
    scanner = Scanner(config)
    result = scanner.scan()

    if not result.findings:
        console.print("  [green]No findings to fix! 🎉[/green]")
        return

    engine = RemediationEngine(use_ai=ai)

    if finding_id:
        # Fix a specific finding
        finding = next((f for f in result.findings if f.id == finding_id), None)
        if not finding:
            console.print(f"[red]Finding {finding_id} not found[/red]")
            raise typer.Exit(1)
        remediation = engine.get_remediation(finding)
        _display_remediation(remediation)
    else:
        # Show all prioritized fixes
        console.print(f"  📋 {result.total_findings} findings to remediate\n")
        remediations = engine.get_all_remediations(result.findings)

        # Priority summary
        priority_summary = engine.get_priority_summary(result.findings)
        for level, items in priority_summary.items():
            if items:
                color = "red" if level in ("P0", "P1") else ("yellow" if level == "P2" else "dim")
                console.print(f"  [{color}]{level}: {len(items)} items[/{color}]")

        console.print()

        # Show top 10 fixes
        for rem in remediations[:10]:
            _display_remediation(rem)


def _display_remediation(rem: dict) -> None:
    """Display a single remediation."""
    console.print(f"  [bold]{rem.get('finding_id', '')}[/bold]: {rem.get('title', '')}")
    console.print(f"    Priority: {rem.get('priority', 'P3')}")
    if rem.get("fix"):
        console.print(f"    Fix: {rem['fix']}")
    if rem.get("code_sample"):
        console.print(f"    [dim]Code: {rem['code_sample'][:100]}...[/dim]")
    if rem.get("ai_fix"):
        console.print(f"    🤖 AI: {rem['ai_fix'][:200]}")
    console.print()


@app.command()
def report(
    app_path: Annotated[str, typer.Argument(help="Path to APK or IPA file")],
    format: Annotated[str, typer.Option("--format", "-f", help="Report format: html, sarif, markdown, json")] = "html",
    output: Annotated[Optional[str], typer.Option("--output", "-o", help="Output file path")] = None,
) -> None:
    """Generate a security report (HTML, SARIF, Markdown, JSON)."""
    path = Path(app_path)
    if not path.exists():
        console.print(f"[red]Error: File not found: {app_path}[/red]")
        raise typer.Exit(1)

    config = ScanConfig(app_path=path)
    scanner = Scanner(config)
    result = scanner.scan()

    if format == "html":
        content = generate_html_report(result)
        out_path = Path(output or "mobiussec-report.html")
        out_path.write_text(content)
    elif format == "sarif":
        sarif = generate_sarif_report(result)
        import json
        content = json.dumps(sarif, indent=2, default=str)
        out_path = Path(output or "mobiussec-report.sarif.json")
        out_path.write_text(content)
    elif format == "markdown":
        content = generate_markdown_report(result)
        out_path = Path(output or "mobiussec-report.md")
        out_path.write_text(content)
    elif format == "json":
        import json
        content = json.dumps(result.to_dict(), indent=2, default=str)
        out_path = Path(output or "mobiussec-report.json")
        out_path.write_text(content)
    else:
        console.print(f"[red]Unknown format: {format}. Use html, sarif, markdown, or json.[/red]")
        raise typer.Exit(1)

    console.print(f"  📄 Report saved to: [bold]{out_path}[/bold]")


@app.command()
def privacy(
    app_path: Annotated[str, typer.Argument(help="Path to APK or IPA file")],
) -> None:
    """Show privacy analysis — data collection, SDK tracking, compliance."""

    path = Path(app_path)
    if not path.exists():
        console.print(f"[red]Error: File not found: {app_path}[/red]")
        raise typer.Exit(1)

    platform = _detect_platform(path)
    if platform == "unknown":
        console.print(f"[red]Error: Unsupported file type.[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(Panel.fit(
        "[bold]MobiusSec Privacy Analysis[/bold]",
        border_style="bright_magenta",
    ))

    config = ScanConfig(app_path=path)
    scanner = Scanner(config)
    result = scanner.scan()

    if not scanner.privacy_report:
        console.print("[red]Privacy analysis not available.[/red]")
        raise typer.Exit(1)

    report = scanner.privacy_report

    # Privacy score
    score = report.get("privacy_score", 0)
    score_color = "green" if score >= 70 else ("yellow" if score >= 40 else "red")
    console.print(f"\n  🔒 Privacy Score: [{score_color}]{score}/100[/{score_color}]")

    # Data collected
    data_collected = report.get("data_collected", [])
    if data_collected:
        table = Table(title="📊 Data Collected", show_header=True, header_style="bold magenta")
        table.add_column("Data Type", max_width=40)
        table.add_column("Description", max_width=40)
        table.add_column("Source", style="dim")
        for d in data_collected[:20]:
            table.add_row(d.get("type", ""), d.get("description", ""), d.get("source", ""))
        console.print(table)
    else:
        console.print("  [green]No sensitive data collection detected.[/green]")

    # Detected SDKs
    detected_sdks = report.get("detected_sdks", [])
    if detected_sdks:
        table = Table(title="🔍 Tracking SDKs", show_header=True, header_style="bold yellow")
        table.add_column("SDK", max_width=30)
        table.add_column("Category", style="dim")
        table.add_column("Description", max_width=50)
        for sdk in detected_sdks:
            cat_color = "red" if sdk["category"] in ("ad_networks", "social") else ("yellow" if sdk["category"] == "analytics" else "dim")
            table.add_row(sdk["id"].split(".")[-1], f"[{cat_color}]{sdk['category']}[/{cat_color}]", sdk["description"]) 
        console.print(table)

    # Network endpoints
    endpoints = report.get("network_endpoints", [])
    if endpoints:
        table = Table(title="🌐 Data Transmission Endpoints", show_header=True, header_style="bold cyan")
        table.add_column("Endpoint")
        table.add_column("Description", max_width=50)
        for ep in endpoints:
            table.add_row(ep["pattern"], ep["description"])
        console.print(table)

    # Compliance gaps
    gaps = report.get("compliance_gaps", [])
    if gaps:
        console.print("\n  [bold red]⚖️ Compliance Gaps:[/bold red]")
        for gap in gaps:
            console.print(f"  [bold]{gap['name']}[/bold]")
            for g in gap["gaps"]:
                console.print(f"    ⚠️  {g}")
    else:
        console.print("\n  [green]✅ No major compliance gaps detected.[/green]")

    # Privacy findings
    privacy_findings = [f for f in result.findings if f.masvs_category == "PRIVACY"]
    if privacy_findings:
        console.print(f"\n  [yellow]⚠️  {len(privacy_findings)} privacy-related findings[/yellow]")


@app.command()
def sbom(
    app_path: Annotated[str, typer.Argument(help="Path to APK or IPA file")],
    output: Annotated[Optional[str], typer.Option("--output", "-o", help="Output file path")] = None,
) -> None:
    """Generate a Software Bill of Materials (CycloneDX format)."""

    path = Path(app_path)
    if not path.exists():
        console.print(f"[red]Error: File not found: {app_path}[/red]")
        raise typer.Exit(1)

    platform = _detect_platform(path)
    if platform == "unknown":
        console.print(f"[red]Error: Unsupported file type.[/red]")
        raise typer.Exit(1)

    console.print()
    console.print(Panel.fit(
        "[bold]MobiusSec SBOM Generator[/bold]",
        border_style="bright_cyan",
    ))

    config = ScanConfig(app_path=path)
    scanner = Scanner(config)
    scanner.scan()  # Need scan to populate SBOM

    if not scanner.sbom:
        console.print("[red]SBOM generation failed.[/red]")
        raise typer.Exit(1)

    components = scanner.sbom.get("components", [])

    # Display components
    table = Table(title="📦 Software Bill of Materials", show_header=True, header_style="bold cyan")
    table.add_column("Component", max_width=30)
    table.add_column("Version", style="dim")
    table.add_column("Category")
    table.add_column("Ecosystem", style="dim")

    for comp in components:
        table.add_row(
            comp.get("name", "unknown"),
            comp.get("version", "—"),
            comp.get("category", "—"),
            comp.get("ecosystem", "—"),
        )

    console.print(table)
    console.print(f"\n  📦 Total components: {len(components)}")

    # Output CycloneDX JSON
    if output:
        import json
        out_path = Path(output)
        out_path.write_text(json.dumps(scanner.sbom, indent=2, default=str))
        console.print(f"  💾 CycloneDX SBOM written to: {out_path}")
    else:
        console.print("  [dim]Use --output to save as CycloneDX JSON[/dim]")


@app.command()
def version() -> None:
    """Show MobiusSec version."""
    from mobiussec import __version__
    console.print(f"MobiusSec v{__version__}")


def _display_rich(result: "ScanResult", config: ScanConfig) -> None:
    """Display scan results in rich terminal format."""
    # Summary panel
    platform_icon = "🤖" if result.platform.value == "android" else "🍎"
    console.print(Panel.fit(
        f"{platform_icon} [bold]{result.app_name}[/bold] [dim]({result.package_name})[/dim]\n"
        f"Version: {result.version} | Platform: {result.platform.value.upper()}\n"
        f"Scan time: {result.scan_time_seconds:.1f}s",
        title="Scan Results",
        border_style="cyan",
    ))

    # Severity summary
    console.print()
    summary = Text()
    summary.append("  Findings: ")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = getattr(result, f"{sev}_count", 0)
        if count:
            summary.append(f"{SEVERITY_ICONS[sev]} {count} {sev.upper()}  ", style=SEVERITY_COLORS[sev])
    console.print(summary)
    console.print()

    if not result.findings:
        console.print("  [bold green]No security issues found! 🎉[/bold green]")
        return

    # Findings table
    table = Table(
        title="Security Findings",
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Severity", width=10)
    table.add_column("ID", style="dim", width=16)
    table.add_column("Category", width=10)
    table.add_column("Title", max_width=50)
    table.add_column("File", style="dim", max_width=30)

    # Sort by severity
    sorted_findings = sorted(result.findings, key=lambda f: f.severity.value)

    for finding in sorted_findings:
        color = SEVERITY_COLORS.get(finding.severity.value, "white")
        icon = SEVERITY_ICONS.get(finding.severity.value, "•")
        table.add_row(
            f"{icon} [{color}]{finding.severity.value.upper()}[/{color}]",
            finding.id,
            finding.masvs_category,
            finding.title,
            finding.file or "—",
        )

    console.print(table)

    # Remediation hints for high/critical
    critical_high = [f for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if critical_high:
        console.print()
        console.print("[bold red]🔧 Priority Fixes:[/bold red]")
        for f in critical_high[:10]:
            console.print(f"  [{SEVERITY_COLORS[f.severity.value]}]• {f.title}[/{SEVERITY_COLORS[f.severity.value]}]")
            if f.remediation:
                console.print(f"    [dim]→ {f.remediation}[/dim]")


def _output_json(result: "ScanResult", config: ScanConfig) -> None:
    """Output results as JSON."""
    data = result.to_dict()
    json_str = json.dumps(data, indent=2, default=str)

    if config.output_path:
        config.output_path.write_text(json_str)
        console.print(f"Results written to {config.output_path}")
    else:
        console.print(json_str)