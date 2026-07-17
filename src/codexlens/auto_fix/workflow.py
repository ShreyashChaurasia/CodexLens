"""Confirmation-gated orchestration for CodexLens Pass 3."""

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

from codexlens.auto_fix.apply import apply_patch_proposal
from codexlens.auto_fix.models import (
    FixCandidate,
    FixRunResult,
    PatchApplyResult,
    PatchDiagnostic,
    PatchProposal,
    PatchStatus,
)
from codexlens.auto_fix.service import OpenAIResponsesPatchGenerator, PatchGenerator
from codexlens.models import AiFinding, AiScanResult, AiScanStatus, ScanConfig

ConfirmPatch = Callable[[PatchProposal], bool]
PatchApplier = Callable[[PatchProposal], PatchApplyResult]


def run_fix_workflow(
    config: ScanConfig,
    ai: AiScanResult,
    *,
    generator: PatchGenerator | None = None,
    confirm: ConfirmPatch | None = None,
    applier: PatchApplier = apply_patch_proposal,
) -> FixRunResult:
    """Generate, preview, confirm, and atomically apply at most one safe patch."""

    if not config.fix_enabled:
        return FixRunResult(status=PatchStatus.SKIPPED)
    if config.model is None:
        return _skipped("patch-model-missing", "Auto-fix requires a selected OpenAI model.")
    if ai.status is not AiScanStatus.COMPLETED:
        return _skipped(
            "patch-ai-scan-incomplete",
            "Auto-fix was skipped because the AI deep scan did not complete.",
        )
    if not ai.findings:
        return _skipped(
            "patch-no-ai-findings",
            "No eligible AI deep-scan findings were available for auto-fix.",
        )

    candidates, candidate_diagnostics = _build_candidates(ai.findings)
    if not candidates:
        return FixRunResult(
            status=PatchStatus.SKIPPED,
            diagnostics=tuple(candidate_diagnostics),
        )

    patch_generator = generator or OpenAIResponsesPatchGenerator()
    confirmer = confirm or _decline_by_default
    diagnostics = list(candidate_diagnostics)
    proposals_shown = 0
    declined = 0
    rejected = False
    failed = False

    for candidate_index, candidate in enumerate(candidates, start=1):
        try:
            generation = patch_generator.generate(
                target=config.target,
                model=config.model,
                candidate=candidate,
            )
        except Exception:
            diagnostics.append(
                PatchDiagnostic(
                    kind="patch-generation-error",
                    message="A patch could not be generated safely for this finding.",
                    path=candidate.relative_path,
                )
            )
            failed = True
            continue

        diagnostics.extend(generation.diagnostics)
        proposal = generation.proposal
        if proposal is None:
            rejected = True
            if any(diagnostic.kind == "patch-api-error" for diagnostic in generation.diagnostics):
                failed = True
            continue

        proposals_shown += 1
        try:
            accepted = confirmer(proposal)
        except Exception:
            diagnostics.append(
                PatchDiagnostic(
                    kind="patch-confirmation-unavailable",
                    message=(
                        "No interactive confirmation was available, so the patch was not applied."
                    ),
                    path=proposal.relative_path,
                )
            )
            accepted = False
        if not accepted:
            declined += 1
            continue

        try:
            apply_result = applier(proposal)
        except Exception:
            diagnostics.append(
                PatchDiagnostic(
                    kind="patch-apply-error",
                    message=(
                        "The patch could not be applied safely; the original file was preserved."
                    ),
                    path=proposal.relative_path,
                )
            )
            failed = True
            continue
        if apply_result.diagnostic is not None:
            diagnostics.append(apply_result.diagnostic)
        if apply_result.status is PatchStatus.APPLIED:
            return FixRunResult(
                status=PatchStatus.APPLIED,
                candidates_considered=candidate_index,
                proposals_shown=proposals_shown,
                declined=declined,
                applied_path=proposal.relative_path,
                diagnostics=tuple(diagnostics),
            )
        return FixRunResult(
            status=apply_result.status,
            candidates_considered=candidate_index,
            proposals_shown=proposals_shown,
            declined=declined,
            diagnostics=tuple(diagnostics),
        )

    status = _final_status(declined=declined, rejected=rejected, failed=failed)
    return FixRunResult(
        status=status,
        candidates_considered=len(candidates),
        proposals_shown=proposals_shown,
        declined=declined,
        diagnostics=tuple(diagnostics),
    )


def _build_candidates(
    findings: tuple[AiFinding, ...],
) -> tuple[tuple[FixCandidate, ...], tuple[PatchDiagnostic, ...]]:
    candidates: list[FixCandidate] = []
    diagnostics: list[PatchDiagnostic] = []
    for finding in findings:
        candidate = _candidate_from_finding(finding)
        if candidate is None:
            diagnostics.append(
                PatchDiagnostic(
                    kind="patch-finding-unbound",
                    message=(
                        "An AI finding was not bound to a reviewed source unit, "
                        "so it was not auto-fixed."
                    ),
                    path=finding.path,
                )
            )
            continue
        candidates.append(candidate)
    return tuple(candidates), tuple(diagnostics)


def _candidate_from_finding(finding: AiFinding) -> FixCandidate | None:
    if (
        finding.path.is_absolute()
        or finding.path.drive
        or finding.path.root
        or finding.path.suffix.lower() != ".py"
        or not finding.path.parts
        or any(part in {"", ".", ".."} for part in finding.path.parts)
        or not finding.source_unit_id
        or not _is_positive_int(finding.source_unit_start_line)
        or not _is_positive_int(finding.source_unit_end_line)
        or finding.source_unit_start_line > finding.source_unit_end_line
        or not _is_sha256(finding.source_unit_sha256)
    ):
        return None
    relative_path = Path(*finding.path.parts)
    candidate_id = _candidate_id(finding, relative_path)
    return FixCandidate(
        candidate_id=candidate_id,
        finding=finding,
        relative_path=relative_path,
        source_unit_id=finding.source_unit_id,
        source_unit_start_line=finding.source_unit_start_line,
        source_unit_end_line=finding.source_unit_end_line,
        source_unit_sha256=finding.source_unit_sha256,
    )


def _candidate_id(finding: AiFinding, relative_path: object) -> str:
    fingerprint = {
        "path": str(relative_path).replace("\\", "/"),
        "category": finding.category,
        "start_line": finding.start_line,
        "end_line": finding.end_line,
        "source_unit_id": finding.source_unit_id,
        "source_unit_start_line": finding.source_unit_start_line,
        "source_unit_end_line": finding.source_unit_end_line,
        "source_unit_sha256": finding.source_unit_sha256,
        "title": finding.title,
    }
    digest = hashlib.sha256(
        json.dumps(fingerprint, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"fx_{digest[:20]}"


def _skipped(kind: str, message: str) -> FixRunResult:
    return FixRunResult(
        status=PatchStatus.SKIPPED,
        diagnostics=(PatchDiagnostic(kind=kind, message=message),),
    )


def _final_status(*, declined: int, rejected: bool, failed: bool) -> PatchStatus:
    if failed:
        return PatchStatus.FAILED
    if rejected:
        return PatchStatus.REJECTED
    if declined:
        return PatchStatus.DECLINED
    return PatchStatus.SKIPPED


def _decline_by_default(_: PatchProposal) -> bool:
    """Keep programmatic or non-interactive callers non-mutating by default."""

    return False


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
