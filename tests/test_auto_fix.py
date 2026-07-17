import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from codexlens.ai_analysis.context import build_source_context
from codexlens.ai_analysis.service import OpenAIResponsesAnalyzer
from codexlens.auto_fix.apply import apply_patch_proposal
from codexlens.auto_fix.models import (
    FixCandidate,
    PatchDiagnostic,
    PatchGenerationResult,
    PatchStatus,
)
from codexlens.auto_fix.service import OpenAIResponsesPatchGenerator
from codexlens.auto_fix.validation import capture_patch_snapshot, validate_model_payload
from codexlens.auto_fix.workflow import run_fix_workflow
from codexlens.models import (
    AiFinding,
    AiFindingConfidence,
    AiScanResult,
    AiScanStatus,
    ScanConfig,
    Severity,
)
from codexlens.static_analysis import run_static_analysis


class FakeResponses:
    def __init__(self, response: object) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        return self.response


class FakeClient:
    def __init__(self, responses: FakeResponses) -> None:
        self.responses = responses


class RecordingGenerator:
    def __init__(self, result: PatchGenerationResult) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def generate(self, **kwargs: object) -> PatchGenerationResult:
        self.calls.append(kwargs)
        return self.result


class SequencedGenerator:
    def __init__(self, *results: PatchGenerationResult) -> None:
        self._results = list(results)
        self.calls: list[dict[str, object]] = []

    def generate(self, **kwargs: object) -> PatchGenerationResult:
        self.calls.append(kwargs)
        return self._results.pop(0)


def test_patch_generator_uses_selected_model_and_builds_a_local_diff(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    candidate = _candidate_for(source)
    replacement = _replacement()
    response = SimpleNamespace(
        status="completed",
        output_text=json.dumps(
            _response_payload(
                candidate,
                hashlib.sha256(source_file.read_bytes()).hexdigest(),
                replacement,
            )
        ),
    )
    responses = FakeResponses(response)
    generator = OpenAIResponsesPatchGenerator(client_factory=lambda: FakeClient(responses))

    result = generator.generate(
        target=tmp_path,
        model="custom/provider-model:2026-07",
        candidate=candidate,
    )

    assert result.proposal is not None
    assert not result.diagnostics
    assert source_file.read_text(encoding="utf-8") == source
    assert result.proposal.relative_path == Path("routes.py")
    assert "--- a/routes.py" in result.proposal.unified_diff
    assert "+++ b/routes.py" in result.proposal.unified_diff
    assert "load_order_for_user" in result.proposal.unified_diff

    call = responses.calls[0]
    assert call["model"] == "custom/provider-model:2026-07"
    assert call["store"] is False
    assert call["text"] == {
        "format": {
            "type": "json_schema",
            "name": "codexlens_pass3_result",
            "strict": True,
            "schema": call["text"]["format"]["schema"],
        }
    }
    assert str(tmp_path) not in call["input"]


def test_patch_generator_rejects_wrong_response_binding_without_writing(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    candidate = _candidate_for(source)
    payload = _response_payload(
        candidate,
        hashlib.sha256(source_file.read_bytes()).hexdigest(),
        _replacement(),
    )
    payload["candidate_id"] = "wrong-candidate"
    responses = FakeResponses(SimpleNamespace(status="completed", output_text=json.dumps(payload)))
    generator = OpenAIResponsesPatchGenerator(client_factory=lambda: FakeClient(responses))

    result = generator.generate(target=tmp_path, model="any-model", candidate=candidate)

    assert result.proposal is None
    assert result.diagnostics[0].kind == "patch-response-invalid-binding"
    assert source_file.read_text(encoding="utf-8") == source


def test_pass2_source_binding_supports_crlf_and_refuses_a_changed_unit(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_bytes(source.replace("\n", "\r\n").encode("utf-8"))
    static = run_static_analysis(tmp_path)
    unit = build_source_context(tmp_path).units[0]
    response = SimpleNamespace(
        status="completed",
        output_text=json.dumps(
            _pass2_response_payload(unit.unit_id, unit.start_line, unit.end_line)
        ),
    )
    responses = FakeResponses(response)
    analyzer = OpenAIResponsesAnalyzer(client_factory=lambda: FakeClient(responses))

    ai = analyzer.analyze(tmp_path, "any-model", static)

    assert ai.status is AiScanStatus.COMPLETED
    finding = ai.findings[0]
    candidate = FixCandidate(
        candidate_id="fx_from_pass2",
        finding=finding,
        relative_path=finding.path,
        source_unit_id=finding.source_unit_id,
        source_unit_start_line=finding.source_unit_start_line,
        source_unit_end_line=finding.source_unit_end_line,
        source_unit_sha256=finding.source_unit_sha256,
    )
    snapshot, diagnostic = capture_patch_snapshot(tmp_path, candidate)

    assert snapshot is not None
    assert diagnostic is None
    source_file.write_bytes(
        source.replace("load_order", "load_changed_order").replace("\n", "\r\n").encode("utf-8")
    )
    changed_snapshot, changed_diagnostic = capture_patch_snapshot(tmp_path, candidate)

    assert changed_snapshot is None
    assert changed_diagnostic is not None
    assert changed_diagnostic.kind == "patch-unit-stale"


def test_fix_workflow_skips_without_model_or_completed_ai_scan(tmp_path: Path) -> None:
    source = _source()
    (tmp_path / "routes.py").write_text(source, encoding="utf-8")
    finding = _candidate_for(source).finding
    generator = RecordingGenerator(PatchGenerationResult())

    no_model = run_fix_workflow(
        ScanConfig(target=tmp_path, fix_enabled=True),
        AiScanResult(status=AiScanStatus.COMPLETED, findings=(finding,)),
        generator=generator,
    )
    incomplete = run_fix_workflow(
        ScanConfig(target=tmp_path, fix_enabled=True, model="any-model"),
        AiScanResult(status=AiScanStatus.PARTIAL, findings=(finding,)),
        generator=generator,
    )

    assert no_model.status is PatchStatus.SKIPPED
    assert incomplete.status is PatchStatus.SKIPPED
    assert not generator.calls


def test_declining_a_valid_proposal_does_not_write(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    candidate = _candidate_for(source)
    proposal = _proposal_for(tmp_path, candidate, _replacement())
    generator = RecordingGenerator(PatchGenerationResult(proposal=proposal))

    result = run_fix_workflow(
        ScanConfig(target=tmp_path, fix_enabled=True, model="any-model"),
        AiScanResult(status=AiScanStatus.COMPLETED, findings=(candidate.finding,)),
        generator=generator,
        confirm=lambda _: False,
    )

    assert result.status is PatchStatus.DECLINED
    assert result.proposals_shown == 1
    assert source_file.read_text(encoding="utf-8") == source


def test_fix_failure_is_not_masked_by_an_earlier_declined_proposal(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    candidate = _candidate_for(source)
    proposal = _proposal_for(tmp_path, candidate, _replacement())
    second_finding = replace(candidate.finding, title="A second finding in the same unit")
    generator = SequencedGenerator(
        PatchGenerationResult(proposal=proposal),
        PatchGenerationResult(
            diagnostics=(
                PatchDiagnostic(
                    kind="patch-api-error",
                    message="The selected OpenAI model could not generate a patch.",
                ),
            )
        ),
    )

    result = run_fix_workflow(
        ScanConfig(target=tmp_path, fix_enabled=True, model="any-model"),
        AiScanResult(
            status=AiScanStatus.COMPLETED,
            findings=(candidate.finding, second_finding),
        ),
        generator=generator,
        confirm=lambda _: False,
    )

    assert result.status is PatchStatus.FAILED
    assert len(generator.calls) == 2
    assert source_file.read_text(encoding="utf-8") == source


def test_confirming_a_proposal_applies_once_then_stops(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    candidate = _candidate_for(source)
    proposal = _proposal_for(tmp_path, candidate, _replacement())
    generator = RecordingGenerator(PatchGenerationResult(proposal=proposal))
    second_finding = replace(candidate.finding, title="A second finding in the same unit")

    result = run_fix_workflow(
        ScanConfig(target=tmp_path, fix_enabled=True, model="any-model"),
        AiScanResult(
            status=AiScanStatus.COMPLETED,
            findings=(candidate.finding, second_finding),
        ),
        generator=generator,
        confirm=lambda _: True,
    )

    assert result.status is PatchStatus.APPLIED
    assert len(generator.calls) == 1
    assert "load_order_for_user" in source_file.read_text(encoding="utf-8")


def test_stale_file_is_not_overwritten_after_confirmation(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    candidate = _candidate_for(source)
    proposal = _proposal_for(tmp_path, candidate, _replacement())
    generator = RecordingGenerator(PatchGenerationResult(proposal=proposal))
    second_finding = replace(candidate.finding, title="A second finding in the same unit")

    def confirm(_: object) -> bool:
        source_file.write_text("def changed_elsewhere():\n    return True\n", encoding="utf-8")
        return True

    result = run_fix_workflow(
        ScanConfig(target=tmp_path, fix_enabled=True, model="any-model"),
        AiScanResult(
            status=AiScanStatus.COMPLETED,
            findings=(candidate.finding, second_finding),
        ),
        generator=generator,
        confirm=confirm,
    )

    assert result.status is PatchStatus.REJECTED
    assert len(generator.calls) == 1
    assert source_file.read_text(encoding="utf-8") == "def changed_elsewhere():\n    return True\n"
    assert any(diagnostic.kind == "patch-apply-stale-file" for diagnostic in result.diagnostics)


def test_sensitive_source_unit_is_never_sent_for_patch_generation(tmp_path: Path) -> None:
    source = 'def read_key():\n    api_key = "secret-value"\n    return api_key\n'
    (tmp_path / "routes.py").write_text(source, encoding="utf-8")
    candidate = _candidate_for(source)
    responses = FakeResponses(SimpleNamespace(status="completed", output_text="{}"))
    generator = OpenAIResponsesPatchGenerator(client_factory=lambda: FakeClient(responses))

    result = generator.generate(target=tmp_path, model="any-model", candidate=candidate)

    assert result.proposal is None
    assert result.diagnostics[0].kind == "patch-source-sensitive"
    assert not responses.calls


def test_path_escape_is_rejected_before_a_model_request(tmp_path: Path) -> None:
    source = _source()
    (tmp_path / "routes.py").write_text(source, encoding="utf-8")
    candidate = replace(_candidate_for(source), relative_path=Path("..") / "outside.py")

    snapshot, diagnostic = capture_patch_snapshot(tmp_path, candidate)

    assert snapshot is None
    assert diagnostic is not None
    assert diagnostic.kind == "patch-path-invalid"


def test_atomic_write_failure_preserves_original_file(tmp_path: Path, monkeypatch) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    proposal = _proposal_for(tmp_path, _candidate_for(source), _replacement())

    def fail_replace(_: object, __: object) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr("codexlens.auto_fix.apply.os.replace", fail_replace)
    result = apply_patch_proposal(proposal)

    assert result.status is PatchStatus.FAILED
    assert source_file.read_text(encoding="utf-8") == source


def test_apply_rejects_a_tampered_proposal_preimage_or_target_root(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    proposal = _proposal_for(tmp_path, _candidate_for(source), _replacement())

    bad_preimage = replace(proposal, original_bytes=b"not the captured source")
    bad_root = replace(proposal, target_root_inode=proposal.target_root_inode + 1)

    assert apply_patch_proposal(bad_preimage).status is PatchStatus.REJECTED
    assert apply_patch_proposal(bad_root).status is PatchStatus.REJECTED
    assert source_file.read_text(encoding="utf-8") == source


def test_apply_rejects_a_recreated_root_or_noncanonical_relative_path(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source_file = project / "routes.py"
    source = _source()
    source_file.write_text(source, encoding="utf-8")
    proposal = _proposal_for(project, _candidate_for(source), _replacement())
    noncanonical = replace(proposal, relative_path=Path("nested") / ".." / "routes.py")

    assert apply_patch_proposal(noncanonical).status is PatchStatus.REJECTED
    assert source_file.read_text(encoding="utf-8") == source

    previous_project = tmp_path / "previous-project"
    project.rename(previous_project)
    project.mkdir()
    recreated_source = project / "routes.py"
    recreated_source.write_text(source, encoding="utf-8")

    assert apply_patch_proposal(proposal).status is PatchStatus.REJECTED
    assert recreated_source.read_text(encoding="utf-8") == source


def test_changed_encoding_cookie_is_rejected_before_a_patch_is_proposed(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source_bytes = b"# coding: latin-1\nlabel = 'caf\xe9'\n"
    source_file.write_bytes(source_bytes)
    source = source_bytes.decode("latin-1")
    candidate = _candidate_for(source)
    snapshot, diagnostic = capture_patch_snapshot(tmp_path, candidate)

    assert diagnostic is None
    assert snapshot is not None
    result = validate_model_payload(
        snapshot,
        _response_payload(
            candidate,
            snapshot.base_file_sha256,
            "# coding: utf-8\nlabel = 'café'\n",
        ),
    )

    assert result.proposal is None
    assert result.diagnostics[0].kind == "patch-encoding-error"
    assert source_file.read_bytes() == source_bytes


def _source() -> str:
    return (
        "def cancel_order(order_id, current_user):\n"
        "    order = load_order(order_id)\n"
        "    order.cancel()\n"
    )


def _replacement() -> str:
    return (
        "def cancel_order(order_id, current_user):\n"
        "    order = load_order_for_user(order_id, current_user)\n"
        "    order.cancel()\n"
    )


def _candidate_for(source: str) -> FixCandidate:
    finding = AiFinding(
        category="insecure_direct_object_reference",
        severity=Severity.HIGH,
        confidence=AiFindingConfidence.HIGH,
        title="Order changes are not scoped to the current user",
        description="The request-controlled identifier is loaded without owner scoping.",
        path=Path("routes.py"),
        start_line=2,
        end_line=2,
        evidence="The order lookup is not scoped to the current user.",
        impact="A user could modify another user's order.",
        recommendation="Scope the lookup to the authenticated owner.",
        source_unit_id="u0001",
        source_unit_start_line=1,
        source_unit_end_line=len(source.splitlines()),
        source_unit_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
    )
    return FixCandidate(
        candidate_id="fx_test_candidate",
        finding=finding,
        relative_path=Path("routes.py"),
        source_unit_id=finding.source_unit_id,
        source_unit_start_line=finding.source_unit_start_line,
        source_unit_end_line=finding.source_unit_end_line,
        source_unit_sha256=finding.source_unit_sha256,
    )


def _proposal_for(
    target: Path,
    candidate: FixCandidate,
    replacement: str,
):
    snapshot, diagnostic = capture_patch_snapshot(target, candidate)
    assert diagnostic is None
    assert snapshot is not None
    result = validate_model_payload(
        snapshot,
        _response_payload(candidate, snapshot.base_file_sha256, replacement),
    )
    assert result.proposal is not None
    return result.proposal


def _response_payload(
    candidate: FixCandidate,
    base_file_sha256: str,
    replacement: str,
) -> dict[str, object]:
    return {
        "schema_version": "codexlens.pass3.v1",
        "status": "proposed",
        "candidate_id": candidate.candidate_id,
        "source_unit_id": candidate.source_unit_id,
        "source_unit_sha256": candidate.source_unit_sha256,
        "base_file_sha256": base_file_sha256,
        "summary": "Scopes the order lookup to the current user.",
        "verification_notes": ["Run authorization tests for the order endpoint."],
        "replacement_source": replacement,
    }


def _pass2_response_payload(unit_id: str, start_line: int, end_line: int) -> dict[str, object]:
    return {
        "schema_version": "codexlens.pass2.v1",
        "status": "complete",
        "summary": "Reviewed the submitted order handler.",
        "findings": [
            {
                "category": "insecure_direct_object_reference",
                "severity": "high",
                "confidence": "high",
                "title": "Order changes are not scoped to the current user",
                "primary_location": {
                    "unit_id": unit_id,
                    "start_line": start_line,
                    "end_line": end_line,
                },
                "evidence": "The request-controlled identifier is loaded without owner scoping.",
                "attack_preconditions": [],
                "impact": "A user could modify another user's order.",
                "recommendation": "Scope the lookup to the authenticated owner.",
                "cwe_ids": ["CWE-639"],
                "related_static_rule_ids": [],
                "assumptions": [],
            }
        ],
        "coverage": {
            "reviewed_unit_ids": [unit_id],
            "unreviewed_unit_ids": [],
            "limitations": [],
        },
    }
