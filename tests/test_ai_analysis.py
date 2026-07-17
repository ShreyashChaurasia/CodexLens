import json
from pathlib import Path
from types import SimpleNamespace

from codexlens.ai_analysis.context import build_source_context
from codexlens.ai_analysis.service import OpenAIResponsesAnalyzer
from codexlens.models import AiScanStatus
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


def test_ai_analysis_uses_the_selected_model_and_redacts_source(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"
    source_file.write_text(
        "\n".join(
            [
                f'API_KEY = "{secret}"',
                "",
                '@router.post("/orders/{order_id}/cancel")',
                "def cancel_order(order_id, current_user):",
                "    order = load_order(order_id)",
                "    order.cancel()",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    static = run_static_analysis(tmp_path)
    context = build_source_context(tmp_path)
    unit = next(item for item in context.units if item.kind == "function")
    response = _response_for(unit.unit_id, unit.start_line, unit.end_line)
    responses = FakeResponses(response)
    analyzer = OpenAIResponsesAnalyzer(client_factory=lambda: FakeClient(responses))

    result = analyzer.analyze(tmp_path, "custom/provider-model:2026-07", static)

    assert result.status is AiScanStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.findings[0].path == Path("routes.py")
    assert result.findings[0].start_line == unit.start_line
    assert result.findings[0].confidence.value == "high"
    assert result.findings[0].source_unit_id == unit.unit_id
    assert result.findings[0].source_unit_start_line == unit.start_line
    assert result.findings[0].source_unit_end_line == unit.end_line

    call = responses.calls[0]
    assert call["model"] == "custom/provider-model:2026-07"
    assert call["store"] is False
    assert call["text"] == {
        "format": {
            "type": "json_schema",
            "name": "codexlens_pass2_result",
            "strict": True,
            "schema": call["text"]["format"]["schema"],
        }
    }
    assert secret not in call["input"]
    assert "[REDACTED_SECRET]" in call["input"]


def test_ai_analysis_rejects_model_locations_outside_submitted_context(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text(
        "def get_order(order_id):\n    return load_order(order_id)\n",
        encoding="utf-8",
    )
    static = run_static_analysis(tmp_path)
    context = build_source_context(tmp_path)
    unit = context.units[0]
    payload = json.loads(_response_for(unit.unit_id, unit.start_line, unit.end_line).output_text)
    payload["findings"][0]["primary_location"]["unit_id"] = "unknown-unit"
    responses = FakeResponses(
        SimpleNamespace(status="completed", output_text=json.dumps(payload))
    )
    analyzer = OpenAIResponsesAnalyzer(client_factory=lambda: FakeClient(responses))

    result = analyzer.analyze(tmp_path, "arbitrary-model", static)

    assert result.status is AiScanStatus.PARTIAL
    assert not result.findings
    assert any(
        diagnostic.kind == "ai-response-invalid-finding" for diagnostic in result.diagnostics
    )


def test_ai_analysis_sanitizes_client_failures(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    static = run_static_analysis(tmp_path)

    def failing_factory() -> object:
        raise ValueError("do not expose this raw client failure")

    analyzer = OpenAIResponsesAnalyzer(client_factory=failing_factory)
    result = analyzer.analyze(tmp_path, "arbitrary-model", static)

    assert result.status is AiScanStatus.FAILED
    messages = "\n".join(diagnostic.message for diagnostic in result.diagnostics)
    assert "OPENAI_API_KEY" in messages
    assert "raw client failure" not in messages


def test_model_reported_partial_coverage_is_an_incomplete_scan(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text(
        "def get_order(order_id):\n    return load_order(order_id)\n",
        encoding="utf-8",
    )
    static = run_static_analysis(tmp_path)
    unit = build_source_context(tmp_path).units[0]
    response = _response_for(unit.unit_id, unit.start_line, unit.end_line)
    payload = json.loads(response.output_text)
    payload["status"] = "partial"
    responses = FakeResponses(
        SimpleNamespace(status="completed", output_text=json.dumps(payload))
    )
    analyzer = OpenAIResponsesAnalyzer(client_factory=lambda: FakeClient(responses))

    result = analyzer.analyze(tmp_path, "arbitrary-model", static)

    assert result.status is AiScanStatus.PARTIAL
    assert any(diagnostic.kind == "ai-model-partial" for diagnostic in result.diagnostics)


def test_source_context_keeps_module_level_route_registration(tmp_path: Path) -> None:
    source_file = tmp_path / "routes.py"
    source_file.write_text(
        "def get_order(order_id):\n    return load_order(order_id)\n\n"
        "app.add_url_rule('/orders/<order_id>', view_func=get_order)\n",
        encoding="utf-8",
    )

    context = build_source_context(tmp_path)

    assert [unit.kind for unit in context.units] == ["function", "module_context"]
    assert "app.add_url_rule" in context.units[1].source
    assert context.units[1].start_line == 3
    assert context.units[1].end_line == 4


def _response_for(unit_id: str, start_line: int, end_line: int) -> SimpleNamespace:
    return SimpleNamespace(
        status="completed",
        output_text=json.dumps(
            {
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
                        "evidence": (
                            "The request-controlled identifier is loaded without ownership scoping."
                        ),
                        "attack_preconditions": [
                            "An attacker can supply another order identifier."
                        ],
                        "impact": "An attacker could change another user's order.",
                        "recommendation": (
                            "Scope the query to the authenticated owner before mutation."
                        ),
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
        ),
    )
