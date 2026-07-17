"""Immutable contracts for constrained, locally validated patch proposals."""

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from codexlens.models import AiFinding


class PatchStatus(StrEnum):
    """Lifecycle state for a requested Pass 3 auto-fix run."""

    SKIPPED = "skipped"
    PROPOSED = "proposed"
    DECLINED = "declined"
    APPLIED = "applied"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class FixCandidate:
    """A local binding between one Pass 2 finding and one source unit."""

    candidate_id: str
    finding: AiFinding
    relative_path: Path
    source_unit_id: str
    source_unit_start_line: int
    source_unit_end_line: int
    source_unit_sha256: str


@dataclass(frozen=True, slots=True)
class PatchDiagnostic:
    """A sanitized reason why a patch was skipped, rejected, or could not apply."""

    kind: str
    message: str
    path: Path | None = None


@dataclass(frozen=True, slots=True)
class PatchProposal:
    """One fully validated, unapplied, single-file source-unit replacement."""

    candidate: FixCandidate
    target_root: Path
    target_root_device: int
    target_root_inode: int
    path: Path
    relative_path: Path
    base_file_sha256: str
    original_bytes: bytes = field(repr=False)
    updated_bytes: bytes = field(repr=False)
    encoding: str = "utf-8"
    unified_diff: str = ""
    summary: str = ""
    verification_notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PatchGenerationResult:
    """The safe result of generating one proposal; it never writes a file."""

    proposal: PatchProposal | None = None
    diagnostics: tuple[PatchDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class PatchApplyResult:
    """The outcome of attempting an atomic apply after user confirmation."""

    status: PatchStatus
    diagnostic: PatchDiagnostic | None = None


@dataclass(frozen=True, slots=True)
class FixRunResult:
    """Summary of one interactive Pass 3 run."""

    status: PatchStatus
    candidates_considered: int = 0
    proposals_shown: int = 0
    declined: int = 0
    applied_path: Path | None = None
    diagnostics: tuple[PatchDiagnostic, ...] = ()
