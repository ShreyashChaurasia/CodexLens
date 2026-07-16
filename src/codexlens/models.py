"""Stable data contracts shared by the CLI and scan pipeline."""

from dataclasses import dataclass
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
class ScanDiagnostic:
    """A non-security problem that made part of a scan incomplete."""

    kind: str
    path: Path
    message: str
    line: int | None = None
    column: int | None = None


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
class ScanResult:
    """The aggregate result of the currently available scan passes."""

    config: ScanConfig
    static: StaticScanResult

    @property
    def exit_code(self) -> int:
        """Return a CI-friendly exit status for this scan."""

        if self.static.diagnostics:
            return 3
        if self.static.confirmed_findings:
            return 1
        return 0
