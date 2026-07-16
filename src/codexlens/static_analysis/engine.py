"""Orchestrate deterministic, local static analysis for one scan target."""

import ast
import tokenize
from pathlib import Path

from codexlens.models import ScanDiagnostic, StaticScanResult
from codexlens.static_analysis.ast_rules import find_ast_findings
from codexlens.static_analysis.discovery import discover_python_files
from codexlens.static_analysis.secrets import find_secret_findings

MAX_SOURCE_FILE_BYTES = 1_048_576


def run_static_analysis(target: Path) -> StaticScanResult:
    """Run Pass 1 without executing or changing any target source file."""

    discovery = discover_python_files(target)
    findings = []
    diagnostics = list(discovery.diagnostics)
    files_scanned = 0

    for path in discovery.files:
        source = _read_source(path, diagnostics)
        if source is None:
            continue

        files_scanned += 1
        findings.extend(find_secret_findings(path, source))

        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as error:
            diagnostics.append(
                ScanDiagnostic(
                    kind="syntax-error",
                    path=path,
                    message="Python syntax error prevented AST analysis for this file.",
                    line=error.lineno,
                    column=error.offset,
                )
            )
            continue

        findings.extend(find_ast_findings(path, tree))

    findings.sort(
        key=lambda finding: (
            finding.path.as_posix().casefold(),
            finding.line,
            finding.rule_id,
        )
    )
    diagnostics.sort(
        key=lambda diagnostic: (
            diagnostic.path.as_posix().casefold(),
            diagnostic.line or 0,
            diagnostic.kind,
        )
    )
    return StaticScanResult(
        files_discovered=len(discovery.files),
        files_scanned=files_scanned,
        findings=tuple(findings),
        diagnostics=tuple(diagnostics),
        complete=not diagnostics,
    )


def _read_source(path: Path, diagnostics: list[ScanDiagnostic]) -> str | None:
    try:
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            diagnostics.append(
                ScanDiagnostic(
                    kind="file-too-large",
                    path=path,
                    message=f"Skipped source file larger than {MAX_SOURCE_FILE_BYTES:,} bytes.",
                )
            )
            return None

        with tokenize.open(path) as source_file:
            return source_file.read()
    except UnicodeError:
        diagnostics.append(
            ScanDiagnostic(
                kind="decode-error",
                path=path,
                message="Unable to decode this Python source file.",
            )
        )
    except OSError:
        diagnostics.append(
            ScanDiagnostic(
                kind="read-error",
                path=path,
                message="Unable to read this Python source file.",
            )
        )
    except SyntaxError:
        diagnostics.append(
            ScanDiagnostic(
                kind="encoding-error",
                path=path,
                message="Unable to read this Python file because of its encoding declaration.",
            )
        )
    return None
