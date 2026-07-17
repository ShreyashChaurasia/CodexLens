"""Build bounded, deterministic, redacted source contexts for Pass 2."""

import ast
import hashlib
import tokenize
from dataclasses import dataclass
from pathlib import Path

from codexlens.models import AiScanDiagnostic
from codexlens.static_analysis.discovery import discover_python_files
from codexlens.static_analysis.secrets import redact_sensitive_source

MAX_CONTEXT_CHARS = 80_000
MAX_UNIT_CHARS = 12_000


@dataclass(frozen=True, slots=True)
class SourceUnit:
    """A source fragment with stable local-to-model location mapping."""

    unit_id: str
    path: Path
    kind: str
    symbol: str
    start_line: int
    end_line: int
    file_line_count: int
    source: str

    def to_payload(self) -> dict[str, object]:
        """Serialize a source unit without exposing an absolute local path."""

        return {
            "unit_id": self.unit_id,
            "path": self.path.as_posix(),
            "kind": self.kind,
            "symbol": self.symbol,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "source_sha256": hashlib.sha256(self.source.encode("utf-8")).hexdigest(),
            "source": self.source,
        }


@dataclass(frozen=True, slots=True)
class ContextBuildResult:
    """Source units and coverage limitations for one AI deep scan request."""

    units_discovered: int
    units: tuple[SourceUnit, ...]
    diagnostics: tuple[AiScanDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class _UnitCandidate:
    path: Path
    kind: str
    symbol: str
    start_line: int
    end_line: int
    file_line_count: int
    source: str


def build_source_context(target: Path) -> ContextBuildResult:
    """Collect code units while enforcing an API payload budget.

    Source is redacted before it is included in a unit. The source-unit ranges
    retain their original file line numbers so returned findings can be checked
    locally before they reach the terminal.
    """

    root = target.resolve()
    base = root if root.is_dir() else root.parent
    discovery = discover_python_files(root)
    diagnostics: list[AiScanDiagnostic] = []
    candidates: list[_UnitCandidate] = []

    for path in discovery.files:
        source = _read_source(path, diagnostics)
        if source is None:
            continue
        candidates.extend(_extract_candidates(path, base, source))

    for diagnostic in discovery.diagnostics:
        diagnostics.append(
            AiScanDiagnostic(
                kind=f"ai-{diagnostic.kind}",
                path=_relative_path(diagnostic.path, base),
                message="A source path could not be included in the AI analysis context.",
            )
        )

    units: list[SourceUnit] = []
    chars_used = 0
    budget_exhausted = False
    for candidate in candidates:
        redacted_source = redact_sensitive_source(candidate.source)
        if len(redacted_source) > MAX_UNIT_CHARS:
            diagnostics.append(
                AiScanDiagnostic(
                    kind="ai-context-unit-limit",
                    path=candidate.path,
                    message=(
                        "A source unit was omitted because it exceeds the per-unit "
                        "AI context limit."
                    ),
                )
            )
            continue
        if chars_used + len(redacted_source) > MAX_CONTEXT_CHARS:
            budget_exhausted = True
            break

        units.append(
            SourceUnit(
                unit_id=f"u{len(units) + 1:04d}",
                path=candidate.path,
                kind=candidate.kind,
                symbol=candidate.symbol,
                start_line=candidate.start_line,
                end_line=candidate.end_line,
                file_line_count=candidate.file_line_count,
                source=redacted_source,
            )
        )
        chars_used += len(redacted_source)

    if budget_exhausted:
        diagnostics.append(
            AiScanDiagnostic(
                kind="ai-context-limit",
                message=(
                    "The AI context budget was reached before all source units could be reviewed."
                ),
            )
        )

    return ContextBuildResult(
        units_discovered=len(candidates),
        units=tuple(units),
        diagnostics=tuple(diagnostics),
    )


def _read_source(path: Path, diagnostics: list[AiScanDiagnostic]) -> str | None:
    try:
        with tokenize.open(path) as source_file:
            return source_file.read()
    except UnicodeError:
        diagnostics.append(
            AiScanDiagnostic(
                kind="ai-decode-error",
                path=path,
                message="A Python source file could not be decoded for AI analysis.",
            )
        )
    except OSError:
        diagnostics.append(
            AiScanDiagnostic(
                kind="ai-read-error",
                path=path,
                message="A Python source file could not be read for AI analysis.",
            )
        )
    except SyntaxError:
        diagnostics.append(
            AiScanDiagnostic(
                kind="ai-encoding-error",
                path=path,
                message="A Python source file has an invalid encoding declaration.",
            )
        )
    return None


def _extract_candidates(path: Path, base: Path, source: str) -> tuple[_UnitCandidate, ...]:
    if not source.strip():
        return ()

    relative_path = _relative_path(path, base)
    lines = source.splitlines(keepends=True)
    line_count = max(1, len(lines))
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return (
            _UnitCandidate(
                path=relative_path,
                kind="module",
                symbol="<module>",
                start_line=1,
                end_line=line_count,
                file_line_count=line_count,
                source=source,
            ),
        )

    definitions = [
        node
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    if not definitions:
        return (
            _UnitCandidate(
                path=relative_path,
                kind="module",
                symbol="<module>",
                start_line=1,
                end_line=line_count,
                file_line_count=line_count,
                source=source,
            ),
        )

    candidates: list[_UnitCandidate] = []
    previous_end_line = 0

    for node in definitions:
        start_line = _node_start_line(node)
        end_line = node.end_lineno or node.lineno
        if start_line > previous_end_line + 1:
            candidates.append(
                _candidate_from_range(
                    relative_path,
                    "module_context",
                    "<module context>",
                    previous_end_line + 1,
                    start_line - 1,
                    line_count,
                    lines,
                )
            )
        if isinstance(node, ast.ClassDef):
            class_candidate = _candidate_from_range(
                relative_path,
                "class",
                node.name,
                start_line,
                end_line,
                line_count,
                lines,
            )
            if len(class_candidate.source) <= MAX_UNIT_CHARS:
                candidates.append(class_candidate)
                previous_end_line = end_line
                continue

            method_nodes = [
                child
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if method_nodes:
                candidates.append(class_candidate)
                candidates.extend(
                    _candidate_from_range(
                        relative_path,
                        "method",
                        f"{node.name}.{child.name}",
                        _node_start_line(child),
                        child.end_lineno or child.lineno,
                        line_count,
                        lines,
                    )
                    for child in method_nodes
                )
                previous_end_line = end_line
                continue
            candidates.append(class_candidate)
            previous_end_line = end_line
            continue

        candidates.append(
            _candidate_from_range(
                relative_path,
                "function",
                node.name,
                start_line,
                end_line,
                line_count,
                lines,
            )
        )
        previous_end_line = end_line

    if previous_end_line < line_count:
        candidates.append(
            _candidate_from_range(
                relative_path,
                "module_context",
                "<module context>",
                previous_end_line + 1,
                line_count,
                line_count,
                lines,
            )
        )

    return tuple(candidates)


def _candidate_from_range(
    path: Path,
    kind: str,
    symbol: str,
    start_line: int,
    end_line: int,
    file_line_count: int,
    lines: list[str],
) -> _UnitCandidate:
    return _UnitCandidate(
        path=path,
        kind=kind,
        symbol=symbol,
        start_line=start_line,
        end_line=end_line,
        file_line_count=file_line_count,
        source="".join(lines[start_line - 1 : end_line]),
    )


def _node_start_line(node: ast.AST) -> int:
    decorators = getattr(node, "decorator_list", ())
    return min((decorator.lineno for decorator in decorators), default=node.lineno)


def _relative_path(path: Path, base: Path) -> Path:
    try:
        return path.resolve().relative_to(base.resolve())
    except ValueError:
        return Path(path.name)
