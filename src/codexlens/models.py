"""Stable data contracts shared by the CLI and scan pipeline."""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Severity(StrEnum):
    """Impact level for a security finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingConfidence(StrEnum):
    """Whether a finding is confirmed or needs human review."""

    CONFIRMED = "confirmed"
    CANDIDATE = "candidate"


class AiScanStatus(StrEnum):
    """Lifecycle state for the model-assisted second scan pass."""

    SKIPPED = "skipped"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class AiFindingConfidence(StrEnum):
    """The model's self-assessed confidence for an AI review finding."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class OutputFormat(StrEnum):
    """Presentation format selected at the CLI boundary."""

    RICH = "rich"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Options selected for one CodexLens scan request."""

    target: Path
    fix_enabled: bool = False
    model: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """One security issue reported by a scan pass."""

    rule_id: str
    title: str
    severity: Severity
    confidence: FindingConfidence
    description: str
    path: Path
    line: int
    column: int | None = None
    cwe: str | None = None


@dataclass(frozen=True, slots=True)
class AiFinding:
    """One review finding returned by the AI deep-scan pass."""

    category: str
    severity: Severity
    confidence: AiFindingConfidence
    title: str
    description: str
    path: Path
    start_line: int
    end_line: int
    evidence: str
    impact: str
    recommendation: str
    cwe_ids: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    # These fields are created locally while Pass 2 validates a model location.
    # Pass 3 uses them to bind a requested fix to exactly the source unit the
    # model reviewed, rather than trusting a model-supplied path or range.
    source_unit_id: str = ""
    source_unit_start_line: int = 0
    source_unit_end_line: int = 0
    source_unit_sha256: str = ""


@dataclass(frozen=True, slots=True)
class ScanDiagnostic:
    """A non-security problem that made part of a scan incomplete."""

    kind: str
    path: Path
    message: str
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True, slots=True)
class AiScanDiagnostic:
    """A non-security failure or coverage limitation in the AI scan pass."""

    kind: str
    message: str
    path: Path | None = None


@dataclass(frozen=True, slots=True)
class StaticScanResult:
    """Output from the local, deterministic first scan pass."""

    files_discovered: int
    files_scanned: int
    findings: tuple[Finding, ...] = ()
    diagnostics: tuple[ScanDiagnostic, ...] = ()
    complete: bool = True

    @property
    def confirmed_findings(self) -> tuple[Finding, ...]:
        """Findings certain enough to fail a CI scan."""

        return tuple(
            finding
            for finding in self.findings
            if finding.confidence is FindingConfidence.CONFIRMED
        )

    @property
    def candidates(self) -> tuple[Finding, ...]:
        """Potential issues that need human review before being treated as failures."""

        return tuple(
            finding
            for finding in self.findings
            if finding.confidence is FindingConfidence.CANDIDATE
        )


@dataclass(frozen=True, slots=True)
class AiScanResult:
    """Output from the model-assisted business-logic scan pass."""

    status: AiScanStatus
    model: str | None = None
    units_discovered: int = 0
    units_scanned: int = 0
    findings: tuple[AiFinding, ...] = ()
    diagnostics: tuple[AiScanDiagnostic, ...] = ()
    summary: str | None = None

    @classmethod
    def skipped(cls) -> "AiScanResult":
        """Return an intentionally skipped result when no model was selected."""

        return cls(status=AiScanStatus.SKIPPED)

    @property
    def incomplete(self) -> bool:
        """Whether a requested AI scan did not complete with full coverage."""

        return self.status in {AiScanStatus.PARTIAL, AiScanStatus.FAILED}


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The aggregate result of the currently available scan passes."""

    config: ScanConfig
    static: StaticScanResult
    ai: AiScanResult = field(default_factory=AiScanResult.skipped)

    @property
    def exit_code(self) -> int:
        """Return a CI-friendly exit status for this scan."""

        if self.static.diagnostics or self.ai.incomplete:
            return 3
        if self.static.confirmed_findings:
            return 1
        return 0
