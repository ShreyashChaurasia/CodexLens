"""Rich rendering helpers for CodexLens command output."""

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from codexlens.models import ScanResult, Severity

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def render_scan_result(console: Console, result: ScanResult) -> None:
    """Render local findings without exposing secret values or source snippets."""

    target_kind = "directory" if result.config.target.is_dir() else "file"
    fix_mode = "requested" if result.config.fix_enabled else "disabled"
    static = result.static

    details = Text(overflow="fold")
    details.append("Target: ", style="bold")
    details.append(str(result.config.target))
    details.append("\nTarget type: ", style="bold")
    details.append(target_kind)
    details.append("\nFix mode: ", style="bold")
    details.append(fix_mode)
    console.print(
        Panel(
            details,
            title="[bold cyan]CodexLens[/bold cyan]",
            border_style="cyan",
        )
    )

    pipeline = Table(title="Security audit pipeline", show_header=True, header_style="bold cyan")
    pipeline.add_column("Pass", style="bold", width=8)
    pipeline.add_column("Purpose")
    pipeline.add_column("Status")
    pipeline.add_row("1", "Static analysis", _static_status(result))
    pipeline.add_row("2", "AI deep scan", "Not run")
    pipeline.add_row("3", "Interactive auto-fix", "Not run")
    console.print(pipeline)

    if static.findings:
        _render_findings(console, result)
    elif static.files_discovered == 0:
        console.print("[yellow]No Python files found in the selected target.[/yellow]")
    else:
        console.print("[green]No static-analysis findings were detected.[/green]")

    if static.diagnostics:
        _render_diagnostics(console, result)

    if result.config.fix_enabled:
        console.print(
            "[yellow]Fix mode was requested, but auto-fix is not available until Pass 3. "
            "No files were changed.[/yellow]"
        )


def _static_status(result: ScanResult) -> str:
    static = result.static
    if static.files_discovered == 0:
        return "Completed: no Python files found"

    summary = (
        f"{static.files_scanned} files scanned, "
        f"{len(static.confirmed_findings)} confirmed, "
        f"{len(static.candidates)} candidates"
    )
    return f"Incomplete: {summary}" if static.diagnostics else f"Completed: {summary}"


def _render_findings(console: Console, result: ScanResult) -> None:
    findings = Table(title="Static-analysis findings", show_header=True, header_style="bold cyan")
    findings.add_column("Rule", style="bold", no_wrap=True)
    findings.add_column("Severity", no_wrap=True)
    findings.add_column("Confidence", no_wrap=True)
    findings.add_column("Location", no_wrap=True)
    findings.add_column("Finding", overflow="fold")

    for finding in result.static.findings:
        findings.add_row(
            finding.rule_id,
            f"[{_SEVERITY_STYLES[finding.severity]}]{finding.severity.value.upper()}[/]",
            finding.confidence.value,
            _location(finding.path, finding.line, result.config.target),
            finding.description,
        )
    console.print(findings)


def _render_diagnostics(console: Console, result: ScanResult) -> None:
    diagnostics = Table(
        title="Incomplete scan diagnostics",
        show_header=True,
        header_style="bold yellow",
    )
    diagnostics.add_column("Location", no_wrap=True)
    diagnostics.add_column("Diagnostic")

    for diagnostic in result.static.diagnostics:
        diagnostics.add_row(
            _location(diagnostic.path, diagnostic.line, result.config.target),
            diagnostic.message,
        )
    console.print(diagnostics)


def _location(path: Path, line: int | None, target: Path) -> str:
    base = target if target.is_dir() else target.parent
    try:
        display_path = path.relative_to(base).as_posix()
    except ValueError:
        display_path = path.name
    return f"{display_path}:{line}" if line is not None else display_path
