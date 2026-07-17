"""OpenAI Responses integration for model-neutral Pass 3 patch proposals."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from openai import OpenAI, OpenAIError

from codexlens.auto_fix.models import FixCandidate, PatchDiagnostic, PatchGenerationResult
from codexlens.auto_fix.prompts import (
    PASS3_INSTRUCTIONS,
    PASS3_RESPONSE_SCHEMA,
    build_patch_payload,
    build_patch_prompt,
)
from codexlens.auto_fix.validation import capture_patch_snapshot, validate_model_payload

MAX_OUTPUT_TOKENS = 4_000
MAX_RESPONSE_CHARS = 64_000


class PatchGenerator(Protocol):
    """The non-mutating boundary for producing one safe patch proposal."""

    def generate(
        self,
        *,
        target: Path,
        model: str,
        candidate: FixCandidate,
    ) -> PatchGenerationResult:
        """Generate a proposal for one locally validated candidate without writing files."""


class OpenAIResponsesPatchGenerator:
    """Generate strict JSON source-unit replacements through the Responses API."""

    def __init__(self, client_factory: Callable[[], Any] = OpenAI) -> None:
        self._client_factory = client_factory

    def generate(
        self,
        *,
        target: Path,
        model: str,
        candidate: FixCandidate,
    ) -> PatchGenerationResult:
        """Capture a preimage, request a replacement, and validate it locally."""

        snapshot, diagnostic = capture_patch_snapshot(target, candidate)
        if diagnostic is not None:
            return PatchGenerationResult(diagnostics=(diagnostic,))
        if snapshot is None:
            return PatchGenerationResult(
                diagnostics=(
                    PatchDiagnostic(
                        kind="patch-snapshot-error",
                        message="The patch target could not be prepared safely.",
                        path=candidate.relative_path,
                    ),
                )
            )

        payload = build_patch_payload(
            candidate_id=candidate.candidate_id,
            source_unit_id=candidate.source_unit_id,
            source_unit_sha256=candidate.source_unit_sha256,
            base_file_sha256=snapshot.base_file_sha256,
            relative_path=snapshot.relative_path.as_posix(),
            start_line=candidate.source_unit_start_line,
            end_line=candidate.source_unit_end_line,
            source=snapshot.unit_source,
            finding={
                "category": candidate.finding.category,
                "title": candidate.finding.title,
                "description": candidate.finding.description,
                "evidence": candidate.finding.evidence,
                "impact": candidate.finding.impact,
                "recommendation": candidate.finding.recommendation,
                "start_line": candidate.finding.start_line,
                "end_line": candidate.finding.end_line,
            },
        )
        try:
            client = self._client_factory()
            response = client.responses.create(
                model=model,
                instructions=PASS3_INSTRUCTIONS,
                input=build_patch_prompt(payload),
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "codexlens_pass3_result",
                        "strict": True,
                        "schema": PASS3_RESPONSE_SCHEMA,
                    }
                },
                max_output_tokens=MAX_OUTPUT_TOKENS,
                store=False,
            )
        except (OpenAIError, OSError, ValueError):
            return PatchGenerationResult(
                diagnostics=(
                    PatchDiagnostic(
                        kind="patch-api-error",
                        message=(
                            "The selected OpenAI model could not generate a patch. "
                            "Check OPENAI_API_KEY, model access, and network availability."
                        ),
                        path=candidate.relative_path,
                    ),
                )
            )

        if getattr(response, "status", None) not in (None, "completed"):
            return PatchGenerationResult(
                diagnostics=(
                    PatchDiagnostic(
                        kind="patch-response-incomplete",
                        message="The selected OpenAI model returned an incomplete patch response.",
                        path=candidate.relative_path,
                    ),
                )
            )

        output_text = getattr(response, "output_text", None)
        if not isinstance(output_text, str) or not output_text.strip():
            return PatchGenerationResult(
                diagnostics=(
                    PatchDiagnostic(
                        kind="patch-response-empty",
                        message="The selected OpenAI model returned no structured patch response.",
                        path=candidate.relative_path,
                    ),
                )
            )
        if len(output_text) > MAX_RESPONSE_CHARS:
            return PatchGenerationResult(
                diagnostics=(
                    PatchDiagnostic(
                        kind="patch-response-too-large",
                        message="The selected OpenAI model returned an oversized patch response.",
                        path=candidate.relative_path,
                    ),
                )
            )
        try:
            response_payload = json.loads(output_text)
        except json.JSONDecodeError:
            return PatchGenerationResult(
                diagnostics=(
                    PatchDiagnostic(
                        kind="patch-response-invalid-json",
                        message="The selected OpenAI model returned an invalid patch response.",
                        path=candidate.relative_path,
                    ),
                )
            )
        return validate_model_payload(snapshot, response_payload)
