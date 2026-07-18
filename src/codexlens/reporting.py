"""Rich rendering helpers for CodexLens command output."""

import json
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from codexlens.auto_fix.models import FixRunResult, PatchProposal, PatchStatus
from codexlens.models import AiScanStatus, ScanResult, Severity

_SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def render_scan_result(console: Console, result: ScanResult) -> None:
    """Render findings without exposing source snippets or raw model output."""

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
    details.append("\nOpenAI model: ", style="bold")
    details.append(result.config.model or "not configured")
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
    pipeline.add_row("2", "AI deep scan", _ai_status(result))
    pipeline.add_row("3", "Interactive auto-fix", _fix_status(result))
    console.print(pipeline)

    if static.findings:
        _render_findings(console, result)
    elif static.files_discovered == 0:
        console.print("[yellow]No Python files found in the selected target.[/yellow]")
    else:
        console.print("[green]No static-analysis findings were detected.[/green]")

    if static.diagnostics:
        _render_diagnostics(console, result)

    if result.ai.findings:
        _render_ai_findings(console, result)

    if result.ai.diagnostics:
        _render_ai_diagnostics(console, result)


def serialize_scan_result(result: ScanResult) -> str:
    """Return a stable, source-free JSON report for CI and other tools."""

    static = result.static
    ai = result.ai
    return json.dumps(
        {
            "schema_version": "codexlens.scan.v1",
            "target": {
                "kind": "directory" if result.config.target.is_dir() else "file",
                "path": _target_path(result.config.target),
            },
            "model": result.config.model,
            "exit_code": result.exit_code,
            "static": {
                "status": "complete" if static.complete and not static.diagnostics else "partial",
                "files_discovered": static.files_discovered,
                "files_scanned": static.files_scanned,
                "findings": [
                    {
                        "rule_id": finding.rule_id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence.value,
                        "description": finding.description,
                        "location": _json_location(
                            finding.path,
                            result.config.target,
                            finding.line,
                            finding.column,
                        ),
                        "cwe": finding.cwe,
                    }
                    for finding in static.findings
                ],
                "diagnostics": [
                    {
                        "kind": diagnostic.kind,
                        "message": diagnostic.message,
                        "location": _json_location(
                            diagnostic.path,
                            result.config.target,
                            diagnostic.line,
                            diagnostic.column,
                        ),
                    }
                    for diagnostic in static.diagnostics
                ],
            },
            "ai": {
                "status": ai.status.value,
                "model": ai.model,
                "summary": ai.summary,
                "units_discovered": ai.units_discovered,
                "units_scanned": ai.units_scanned,
                "findings": [
                    {
                        "category": finding.category,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence.value,
                        "title": finding.title,
                        "description": finding.description,
                        "location": _json_location(
                            finding.path,
                            result.config.target,
                            finding.start_line,
                            None,
                        ),
                        "impact": finding.impact,
                        "recommendation": finding.recommendation,
                        "cwe_ids": list(finding.cwe_ids),
                        "assumptions": list(finding.assumptions),
                    }
                    for finding in ai.findings
                ],
                "diagnostics": [
                    {
                        "kind": diagnostic.kind,
                        "message": diagnostic.message,
                        "path": _json_path(diagnostic.path, result.config.target),
                    }
                    for diagnostic in ai.diagnostics
                ],
            },
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
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


def _ai_status(result: ScanResult) -> str:
    ai = result.ai
    if ai.status is AiScanStatus.SKIPPED:
        return "Skipped: no model configured"

    summary = f"{ai.units_scanned} contexts, {len(ai.findings)} review findings"
    if ai.status is AiScanStatus.COMPLETED:
        return f"Completed: {summary}"
    return f"Incomplete: {summary}; see diagnostics"


def _fix_status(result: ScanResult) -> str:
    if result.config.fix_enabled:
        return "Requested: safe proposals follow"
    return "Not requested"


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


def _render_ai_findings(console: Console, result: ScanResult) -> None:
    findings = Table(
        title="AI-assisted review findings (human review required)",
        show_header=True,
        header_style="bold magenta",
    )
    findings.add_column("Category", style="bold", no_wrap=True)
    findings.add_column("Severity", no_wrap=True)
    findings.add_column("Model confidence", no_wrap=True)
    findings.add_column("Location", no_wrap=True)
    findings.add_column("Finding", overflow="fold")

    for finding in result.ai.findings:
        details = Text()
        details.append(finding.title, style="bold")
        details.append("\n")
        details.append(finding.description)
        details.append("\nImpact: ", style="bold")
        details.append(finding.impact)
        details.append("\nRecommendation: ", style="bold")
        details.append(finding.recommendation)
        findings.add_row(
            Text(finding.category),
            f"[{_SEVERITY_STYLES[finding.severity]}]{finding.severity.value.upper()}[/]",
            finding.confidence.value,
            _location(finding.path, finding.start_line, result.config.target),
            details,
        )
    console.print(findings)


def _render_ai_diagnostics(console: Console, result: ScanResult) -> None:
    diagnostics = Table(
        title="AI deep-scan diagnostics",
        show_header=True,
        header_style="bold yellow",
    )
    diagnostics.add_column("Location", no_wrap=True)
    diagnostics.add_column("Diagnostic")

    for diagnostic in result.ai.diagnostics:
        diagnostics.add_row(
            _location(diagnostic.path, None, result.config.target),
            diagnostic.message,
        )
    console.print(diagnostics)


def render_patch_proposal(console: Console, proposal: PatchProposal) -> None:
    """Show a locally generated, single-file diff before asking for confirmation."""

    details = Text(overflow="fold")
    details.append("Finding: ", style="bold")
    details.append(proposal.candidate.finding.title)
    details.append("\nLocation: ", style="bold")
    details.append(
        f"{proposal.relative_path.as_posix()}:"
        f"{proposal.candidate.finding.start_line}"
    )
    details.append("\nProposed change: ", style="bold")
    details.append(proposal.summary)
    if proposal.verification_notes:
        details.append("\nVerification notes: ", style="bold")
        details.append("; ".join(proposal.verification_notes))
    console.print(
        Panel(
            details,
            title="[bold magenta]Locally validated auto-fix proposal[/bold magenta]",
            border_style="magenta",
        )
    )
    console.print(Syntax(proposal.unified_diff, "diff", word_wrap=True, line_numbers=False))


def render_fix_result(console: Console, result: FixRunResult, target: Path) -> None:
    """Render the final safe outcome of a requested interactive auto-fix run."""

    messages = {
        PatchStatus.SKIPPED: "Auto-fix was skipped; no files were changed.",
        PatchStatus.DECLINED: "No proposed patch was applied.",
        PatchStatus.APPLIED: (
            "Applied one validated patch. Rerun CodexLens before considering any other fix."
        ),
        PatchStatus.REJECTED: "No patch passed CodexLens safety checks; no files were changed.",
        PatchStatus.FAILED: "Auto-fix could not complete safely; no unconfirmed changes were made.",
        PatchStatus.PROPOSED: "A patch proposal is awaiting confirmation.",
    }
    style = "green" if result.status is PatchStatus.APPLIED else "yellow"
    console.print(Text(messages[result.status], style=style))

    if not result.diagnostics:
        return
    diagnostics = Table(
        title="Auto-fix diagnostics",
        show_header=True,
        header_style="bold yellow",
    )
    diagnostics.add_column("Location", no_wrap=True)
    diagnostics.add_column("Diagnostic")
    for diagnostic in result.diagnostics:
        diagnostics.add_row(_patch_location(diagnostic.path, target), diagnostic.message)
    console.print(diagnostics)


def _location(path: Path | None, line: int | None, target: Path) -> str:
    if path is None:
        return "AI service"
    base = target if target.is_dir() else target.parent
    try:
        display_path = path.relative_to(base).as_posix()
    except ValueError:
        display_path = path.name
    return f"{display_path}:{line}" if line is not None else display_path


def _patch_location(path: Path | None, target: Path) -> str:
    if path is None:
        return "Auto-fix"
    if not path.is_absolute():
        return path.as_posix()
    return _location(path, None, target)


def _target_path(target: Path) -> str:
    """Avoid emitting the caller's absolute workspace path in JSON reports."""

    return "." if target.is_dir() else target.name


def _json_location(
    path: Path,
    target: Path,
    line: int | None,
    column: int | None,
) -> dict[str, int | str | None]:
    return {
        "path": _json_path(path, target),
        "line": line,
        "column": column,
    }


def _json_path(path: Path | None, target: Path) -> str | None:
    if path is None:
        return None
    if not path.is_absolute():
        return path.as_posix()

    base = target if target.is_dir() else target.parent
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.name
