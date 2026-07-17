"""OpenAI Responses integration and local validation for CodexLens Pass 2."""

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from openai import OpenAI, OpenAIError

from codexlens.ai_analysis.context import ContextBuildResult, SourceUnit, build_source_context
from codexlens.ai_analysis.prompts import (
    PASS2_INSTRUCTIONS,
    PASS2_RESPONSE_SCHEMA,
    build_user_prompt,
)
from codexlens.models import (
    AiFinding,
    AiFindingConfidence,
    AiScanDiagnostic,
    AiScanResult,
    AiScanStatus,
    Severity,
    StaticScanResult,
)
from codexlens.static_analysis.secrets import redact_sensitive_source

MAX_OUTPUT_TOKENS = 6_000


class AiAnalyzer(Protocol):
    """The application boundary for an AI business-logic analyzer."""

    def analyze(self, target: Path, model: str, static: StaticScanResult) -> AiScanResult:
        """Run a deep scan for *target* using the caller-selected model."""


class OpenAIResponsesAnalyzer:
    """Run Pass 2 with the synchronous OpenAI Responses client."""

    def __init__(self, client_factory: Callable[[], Any] = OpenAI) -> None:
        self._client_factory = client_factory

    def analyze(self, target: Path, model: str, static: StaticScanResult) -> AiScanResult:
        """Submit redacted source units and validate the model response locally."""

        context = build_source_context(target)
        if not context.units:
            return _empty_context_result(context, model)

        try:
            client = self._client_factory()
            response = client.responses.create(
                model=model,
                instructions=PASS2_INSTRUCTIONS,
                input=build_user_prompt(_build_payload(context, static, target)),
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "codexlens_pass2_result",
                        "strict": True,
                        "schema": PASS2_RESPONSE_SCHEMA,
                    }
                },
                max_output_tokens=MAX_OUTPUT_TOKENS,
                store=False,
            )
        except (OpenAIError, OSError, ValueError):
            return AiScanResult(
                status=AiScanStatus.FAILED,
                model=model,
                units_discovered=context.units_discovered,
                units_scanned=len(context.units),
                diagnostics=(*context.diagnostics, _api_diagnostic()),
            )

        response_status = getattr(response, "status", None)
        if response_status not in (None, "completed"):
            return AiScanResult(
                status=AiScanStatus.FAILED,
                model=model,
                units_discovered=context.units_discovered,
                units_scanned=len(context.units),
                diagnostics=(
                    *context.diagnostics,
                    AiScanDiagnostic(
                        kind="ai-response-incomplete",
                        message=(
                            "The selected OpenAI model returned an incomplete "
                            "AI deep-scan response."
                        ),
                    ),
                ),
            )

        parsed = _parse_output(getattr(response, "output_text", None), context.units)
        partial_diagnostic = (
            (
                AiScanDiagnostic(
                    kind="ai-model-partial",
                    message="The selected OpenAI model reported partial AI deep-scan coverage.",
                ),
            )
            if parsed.model_reported_partial
            else ()
        )
        diagnostics = (*context.diagnostics, *parsed.diagnostics, *partial_diagnostic)
        status = _result_status(context, parsed, diagnostics)
        return AiScanResult(
            status=status,
            model=model,
            units_discovered=context.units_discovered,
            units_scanned=len(context.units),
            findings=parsed.findings,
            diagnostics=diagnostics,
            summary=parsed.summary,
        )


@dataclass(frozen=True, slots=True)
class _ParseResult:
    findings: tuple[AiFinding, ...] = ()
    diagnostics: tuple[AiScanDiagnostic, ...] = ()
    summary: str | None = None
    model_reported_partial: bool = False


def _empty_context_result(context: ContextBuildResult, model: str) -> AiScanResult:
    if context.units_discovered == 0 and not context.diagnostics:
        return AiScanResult(
            status=AiScanStatus.COMPLETED,
            model=model,
            summary="No Python source units were available for AI deep analysis.",
        )

    return AiScanResult(
        status=AiScanStatus.FAILED,
        model=model,
        units_discovered=context.units_discovered,
        diagnostics=(
            *context.diagnostics,
            AiScanDiagnostic(
                kind="ai-context-empty",
                message="No safe source context was available for the requested AI deep scan.",
            ),
        ),
    )


def _build_payload(
    context: ContextBuildResult,
    static: StaticScanResult,
    target: Path,
) -> dict[str, object]:
    base = target.resolve() if target.is_dir() else target.resolve().parent
    return {
        "schema_version": "codexlens.pass2.input.v1",
        "target_root": ".",
        "source_units": [unit.to_payload() for unit in context.units],
        "pass1_findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "path": _relative_path(finding.path, base),
                "line": finding.line,
                "description": finding.description,
            }
            for finding in static.findings
        ],
    }


def _parse_output(output_text: object, units: Sequence[SourceUnit]) -> _ParseResult:
    if not isinstance(output_text, str) or not output_text.strip():
        return _ParseResult(
            diagnostics=(
                AiScanDiagnostic(
                    kind="ai-response-empty",
                    message="The selected OpenAI model returned no structured AI deep-scan result.",
                ),
            )
        )

    try:
        payload = json.loads(output_text)
    except json.JSONDecodeError:
        return _ParseResult(
            diagnostics=(
                AiScanDiagnostic(
                    kind="ai-response-invalid-json",
                    message="The selected OpenAI model returned an invalid AI deep-scan result.",
                ),
            )
        )

    if not isinstance(payload, dict):
        return _ParseResult(
            diagnostics=(
                AiScanDiagnostic(
                    kind="ai-response-invalid-shape",
                    message=(
                        "The selected OpenAI model returned an invalid AI deep-scan result shape."
                    ),
                ),
            )
        )

    expected_root_keys = {"schema_version", "status", "summary", "findings", "coverage"}
    if set(payload) != expected_root_keys:
        return _ParseResult(
            diagnostics=(
                AiScanDiagnostic(
                    kind="ai-response-invalid-shape",
                    message=(
                        "The selected OpenAI model returned an invalid AI deep-scan result shape."
                    ),
                ),
            )
        )

    if payload.get("schema_version") != "codexlens.pass2.v1":
        return _ParseResult(
            diagnostics=(
                AiScanDiagnostic(
                    kind="ai-response-schema-version",
                    message=(
                        "The selected OpenAI model returned an unsupported "
                        "AI deep-scan schema version."
                    ),
                ),
            )
        )

    response_status = payload.get("status")
    summary = payload.get("summary")
    findings_payload = payload.get("findings")
    coverage = payload.get("coverage")
    if (
        response_status not in {"complete", "partial"}
        or not isinstance(summary, str)
        or not isinstance(findings_payload, list)
        or not isinstance(coverage, dict)
    ):
        return _ParseResult(
            diagnostics=(
                AiScanDiagnostic(
                    kind="ai-response-invalid-shape",
                    message=(
                        "The selected OpenAI model returned an incomplete "
                        "AI deep-scan result shape."
                    ),
                ),
            )
        )

    unit_by_id = {unit.unit_id: unit for unit in units}
    diagnostics = list(_validate_coverage(coverage, unit_by_id))
    findings: list[AiFinding] = []
    for index, finding_payload in enumerate(findings_payload, start=1):
        finding, diagnostic = _parse_finding(finding_payload, unit_by_id, index)
        if diagnostic is not None:
            diagnostics.append(diagnostic)
        elif finding is not None:
            findings.append(finding)

    findings.sort(
        key=lambda finding: (
            finding.path.as_posix().casefold(),
            finding.start_line,
            finding.category,
            finding.title.casefold(),
        )
    )
    return _ParseResult(
        findings=tuple(findings),
        diagnostics=tuple(diagnostics),
        summary=_safe_text(summary),
        model_reported_partial=response_status == "partial",
    )


def _validate_coverage(
    coverage: Mapping[str, object],
    unit_by_id: Mapping[str, SourceUnit],
) -> tuple[AiScanDiagnostic, ...]:
    expected_keys = {"reviewed_unit_ids", "unreviewed_unit_ids", "limitations"}
    if set(coverage) != expected_keys:
        return (
            AiScanDiagnostic(
                kind="ai-response-invalid-coverage",
                message=(
                    "The selected OpenAI model returned an invalid AI deep-scan coverage report."
                ),
            ),
        )

    diagnostics: list[AiScanDiagnostic] = []
    for key in ("reviewed_unit_ids", "unreviewed_unit_ids"):
        value = coverage.get(key)
        if not isinstance(value, list) or any(
            not isinstance(unit_id, str) or unit_id not in unit_by_id for unit_id in value
        ):
            diagnostics.append(
                AiScanDiagnostic(
                    kind="ai-response-invalid-coverage",
                    message=(
                        "The selected OpenAI model returned an invalid "
                        "AI deep-scan coverage report."
                    ),
                )
            )
            break
    limitations = coverage.get("limitations")
    if not isinstance(limitations, list) or any(not isinstance(item, str) for item in limitations):
        diagnostics.append(
            AiScanDiagnostic(
                kind="ai-response-invalid-coverage",
                message=(
                    "The selected OpenAI model returned an invalid AI deep-scan coverage report."
                ),
            )
        )
    return tuple(diagnostics)


def _parse_finding(
    payload: object,
    unit_by_id: Mapping[str, SourceUnit],
    index: int,
) -> tuple[AiFinding | None, AiScanDiagnostic | None]:
    if not isinstance(payload, dict):
        return None, _invalid_finding(index)

    expected_keys = {
        "category",
        "severity",
        "confidence",
        "title",
        "primary_location",
        "evidence",
        "attack_preconditions",
        "impact",
        "recommendation",
        "cwe_ids",
        "related_static_rule_ids",
        "assumptions",
    }
    if set(payload) != expected_keys:
        return None, _invalid_finding(index)

    category = payload.get("category")
    severity = _parse_enum(payload.get("severity"), Severity)
    confidence = _parse_enum(payload.get("confidence"), AiFindingConfidence)
    title = payload.get("title")
    evidence = payload.get("evidence")
    impact = payload.get("impact")
    recommendation = payload.get("recommendation")
    location = payload.get("primary_location")
    string_lists = (
        payload.get("attack_preconditions"),
        payload.get("cwe_ids"),
        payload.get("related_static_rule_ids"),
        payload.get("assumptions"),
    )
    if (
        not isinstance(category, str)
        or category not in _ALLOWED_CATEGORIES
        or severity is None
        or confidence is None
        or not _are_nonempty_strings(title, evidence, impact, recommendation)
        or not all(_is_string_list(value) for value in string_lists)
        or not isinstance(location, dict)
        or set(location) != {"unit_id", "start_line", "end_line"}
    ):
        return None, _invalid_finding(index)

    unit_id = location.get("unit_id")
    start_line = location.get("start_line")
    end_line = location.get("end_line")
    unit = unit_by_id.get(unit_id) if isinstance(unit_id, str) else None
    if (
        unit is None
        or not _is_positive_int(start_line)
        or not _is_positive_int(end_line)
        or start_line > end_line
        or start_line < unit.start_line
        or end_line > unit.end_line
    ):
        return None, _invalid_finding(index)

    preconditions, cwe_ids, _, assumptions = string_lists
    description = _safe_text(evidence)
    if preconditions:
        safe_preconditions = "; ".join(_safe_text(item) for item in preconditions)
        description = f"{description} Preconditions: {safe_preconditions}"
    return (
        AiFinding(
            category=category,
            severity=severity,
            confidence=confidence,
            title=_safe_text(title),
            description=description,
            path=unit.path,
            start_line=start_line,
            end_line=end_line,
            evidence=_safe_text(evidence),
            impact=_safe_text(impact),
            recommendation=_safe_text(recommendation),
            cwe_ids=tuple(_safe_text(item) for item in cwe_ids),
            assumptions=tuple(_safe_text(item) for item in assumptions),
        ),
        None,
    )


def _parse_enum(value: object, enum_type: type[Severity] | type[AiFindingConfidence]) -> Any | None:
    if not isinstance(value, str):
        return None
    try:
        return enum_type(value)
    except ValueError:
        return None


def _is_string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _are_nonempty_strings(*values: object) -> bool:
    return all(isinstance(value, str) and value.strip() for value in values)


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _invalid_finding(index: int) -> AiScanDiagnostic:
    return AiScanDiagnostic(
        kind="ai-response-invalid-finding",
        message=f"The AI deep-scan result contained an invalid finding at position {index}.",
    )


def _result_status(
    context: ContextBuildResult,
    parsed: _ParseResult,
    diagnostics: Sequence[AiScanDiagnostic],
) -> AiScanStatus:
    if context.diagnostics or parsed.diagnostics or parsed.model_reported_partial or diagnostics:
        return AiScanStatus.PARTIAL
    return AiScanStatus.COMPLETED


def _api_diagnostic() -> AiScanDiagnostic:
    return AiScanDiagnostic(
        kind="ai-api-error",
        message=(
            "The selected OpenAI model could not complete the AI deep scan. "
            "Check OPENAI_API_KEY, model access, and network availability."
        ),
    )


def _relative_path(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base).as_posix()
    except ValueError:
        return path.name


def _safe_text(value: str) -> str:
    """Redact accidental credential-like text before it reaches terminal output."""

    return redact_sensitive_source(value).strip()


_ALLOWED_CATEGORIES = frozenset(
    {
        "authorization_bypass",
        "insecure_direct_object_reference",
        "race_condition",
        "mass_assignment",
        "privilege_escalation",
        "other_business_logic",
    }
)
