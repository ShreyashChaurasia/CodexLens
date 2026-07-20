import json
import re
from pathlib import Path

from typer.testing import CliRunner

from codexlens.cli import app
from codexlens.models import (
    AiFinding,
    AiFindingConfidence,
    AiScanResult,
    AiScanStatus,
    ScanConfig,
    ScanResult,
    Severity,
    StaticScanResult,
)

runner = CliRunner()
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _plain_cli_output(text: str) -> str:
    """Return CLI text without terminal styling sequences."""

    return _ANSI_ESCAPE.sub("", text)


def test_json_output_is_parseable_source_free_and_uses_relative_paths(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(project), "--format", "json"])

    assert result.exit_code == 0
    assert "\x1b" not in result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "codexlens.scan.v1"
    assert payload["target"] == {"kind": "directory", "path": "."}
    assert payload["exit_code"] == 0
    assert payload["static"]["status"] == "complete"
    assert payload["static"]["files_scanned"] == 1
    assert payload["static"]["findings"] == []
    assert payload["ai"]["status"] == "skipped"
    assert str(project) not in result.output


def test_json_output_redacts_static_secret_and_preserves_failure_exit_code(tmp_path: Path) -> None:
    source_file = tmp_path / "settings.py"
    secret = "demo-password-not-for-production"
    source_file.write_text(f'DB_PASSWORD = "{secret}"\n', encoding="utf-8")

    result = runner.invoke(app, ["scan", str(source_file), "--format", "json"])

    assert result.exit_code == 1
    assert secret not in result.output
    payload = json.loads(result.output)
    finding = payload["static"]["findings"][0]
    assert finding["rule_id"] == "CL001"
    assert finding["location"] == {"column": None, "line": 1, "path": "settings.py"}
    assert payload["exit_code"] == 1


def test_json_output_preserves_incomplete_ai_exit_code(tmp_path: Path, monkeypatch) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = runner.invoke(
        app,
        ["scan", str(source_file), "--model", "custom/model:2026-07", "--format", "json"],
    )

    assert result.exit_code == 3
    payload = json.loads(result.output)
    assert payload["exit_code"] == 3
    assert payload["ai"]["status"] == "failed"
    assert payload["ai"]["diagnostics"][0]["kind"] == "ai-api-error"


def test_json_output_omits_raw_ai_evidence_and_source_unit_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_file = tmp_path / "routes.py"
    source_file.write_text("def approve():\n    return None\n", encoding="utf-8")
    finding = AiFinding(
        category="insecure_direct_object_reference",
        severity=Severity.HIGH,
        confidence=AiFindingConfidence.HIGH,
        title="Expense lookup is not tenant-scoped",
        description="The approved route loads by client-controlled identifier.",
        path=Path("routes.py"),
        start_line=1,
        end_line=2,
        evidence="PRIVATE_RAW_SOURCE_EVIDENCE",
        impact="Another tenant's expense could be approved.",
        recommendation="Scope the lookup to the actor tenant.",
        source_unit_id="u0007",
        source_unit_start_line=1,
        source_unit_end_line=2,
        source_unit_sha256="a" * 64,
    )
    scan_result = ScanResult(
        config=ScanConfig(target=source_file, model="recorded-demo"),
        static=StaticScanResult(files_discovered=1, files_scanned=1),
        ai=AiScanResult(
            status=AiScanStatus.COMPLETED,
            model="recorded-demo",
            findings=(finding,),
        ),
    )
    monkeypatch.setattr("codexlens.cli.run_scan", lambda _config: scan_result)

    result = runner.invoke(
        app,
        ["scan", str(source_file), "--model", "recorded-demo", "--format", "json"],
    )

    assert result.exit_code == 0
    assert "PRIVATE_RAW_SOURCE_EVIDENCE" not in result.output
    assert "source_unit_sha256" not in result.output
    payload = json.loads(result.output)
    ai_finding = payload["ai"]["findings"][0]
    assert ai_finding["location"]["path"] == "routes.py"
    assert ai_finding["impact"] == "Another tenant's expense could be approved."


def test_json_output_rejects_auto_fix_before_running_a_scan(tmp_path: Path, monkeypatch) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")

    def should_not_run(_: ScanConfig) -> ScanResult:
        raise AssertionError("JSON auto-fix mode must not start a scan.")

    monkeypatch.setattr("codexlens.cli.run_scan", should_not_run)
    result = runner.invoke(app, ["scan", str(source_file), "--fix", "--format", "json"])
    plain = _plain_cli_output(result.output).lower()

    assert result.exit_code == 2
    assert re.search(r"--\s*fix\b", plain)
    assert "json" in plain
    assert re.search(r"\b(cannot|incompatible|not supported)\b", plain)
