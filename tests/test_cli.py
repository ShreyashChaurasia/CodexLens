from pathlib import Path

import typer
from typer.testing import CliRunner

from codexlens.auto_fix.models import (
    FixCandidate,
    FixRunResult,
    PatchDiagnostic,
    PatchProposal,
    PatchStatus,
)
from codexlens.cli import _confirm_patch, app
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


def test_root_help_lists_scan_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "CodexLens" in result.output
    assert "scan" in result.output


def test_scan_help_documents_target_and_fix() -> None:
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "TARGET" in result.output
    assert "--fix" in result.output
    assert "--model" in result.output
    assert "CODEXLENS_MODEL" in result.output


def test_clean_directory_scan_reports_static_analysis(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(project)])

    assert result.exit_code == 0
    assert "Target:" in result.output
    assert "Static analysis" in result.output
    assert "1 files scanned" in result.output
    assert "No static-analysis findings" in result.output


def test_scan_file_is_supported(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(source_file)])

    assert result.exit_code == 0
    assert "Target type:" in result.output
    assert "file" in result.output
    assert "1 files scanned" in result.output


def test_fix_flag_skips_without_a_model_and_does_not_write_target(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    original_contents = "print('hello')\n"
    source_file.write_text(original_contents, encoding="utf-8")

    result = runner.invoke(app, ["scan", str(source_file), "--fix"])

    assert result.exit_code == 0
    assert "Fix mode: requested" in result.output
    assert "Auto-fix was skipped" in result.output
    assert "selected OpenAI model" in result.output
    assert source_file.read_text(encoding="utf-8") == original_contents


def test_model_flag_reports_an_incomplete_ai_pass_without_an_api_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = runner.invoke(app, ["scan", str(source_file), "--model", "custom/model:2026-07"])

    assert result.exit_code == 3
    assert "OpenAI model: custom/model:2026-07" in result.output
    assert "AI deep scan" in result.output
    assert "Incomplete" in result.output
    assert "OPENAI_API_KEY" in result.output


def test_failed_requested_fix_returns_three(tmp_path: Path, monkeypatch) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    scan_result = ScanResult(
        config=ScanConfig(target=source_file, fix_enabled=True, model="test-model"),
        static=StaticScanResult(files_discovered=1, files_scanned=1),
        ai=AiScanResult(status=AiScanStatus.COMPLETED, model="test-model"),
    )
    monkeypatch.setattr("codexlens.cli.run_scan", lambda _: scan_result)
    monkeypatch.setattr(
        "codexlens.cli.run_fix_workflow",
        lambda *_args, **_kwargs: FixRunResult(
            status=PatchStatus.FAILED,
            diagnostics=(
                PatchDiagnostic(
                    kind="patch-api-error",
                    message="The selected OpenAI model could not generate a patch.",
                ),
            ),
        ),
    )

    result = runner.invoke(app, ["scan", str(source_file), "--model", "test-model", "--fix"])

    assert result.exit_code == 3
    assert "Auto-fix could not complete safely" in result.output


def test_interactive_confirmation_accepts_y_and_declines_n_or_eof(tmp_path: Path) -> None:
    prompt_app = typer.Typer()
    proposal = _confirmation_proposal(tmp_path)

    @prompt_app.command()
    def prompt() -> None:
        typer.echo(str(_confirm_patch(proposal)))

    accepted = runner.invoke(prompt_app, [], input="y\n")
    declined = runner.invoke(prompt_app, [], input="n\n")
    unavailable = runner.invoke(prompt_app, [], input="")

    assert accepted.exit_code == 0
    assert "Apply this patch to app.py?" in accepted.output
    assert accepted.output.rstrip().endswith("True")
    assert declined.exit_code == 0
    assert declined.output.rstrip().endswith("False")
    assert unavailable.exit_code == 0
    assert unavailable.output.rstrip().endswith("False")


def test_environment_model_is_used_when_no_flag_is_provided(tmp_path: Path, monkeypatch) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.setenv("CODEXLENS_MODEL", "environment-model")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = runner.invoke(app, ["scan", str(source_file)])

    assert result.exit_code == 3
    assert "OpenAI model: environment-model" in result.output
    assert "AI deep scan" in result.output


def test_model_flag_overrides_environment_model(tmp_path: Path, monkeypatch) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.setenv("CODEXLENS_MODEL", "environment-model")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    result = runner.invoke(app, ["scan", str(source_file), "-m", "command-line-model"])

    assert result.exit_code == 3
    assert "OpenAI model: command-line-model" in result.output
    assert "environment-model" not in result.output


def test_blank_model_configuration_is_rejected(tmp_path: Path, monkeypatch) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.setenv("CODEXLENS_MODEL", " ")

    environment_result = runner.invoke(app, ["scan", str(source_file)])
    cli_result = runner.invoke(app, ["scan", str(source_file), "--model", "  "])

    assert environment_result.exit_code == 2
    assert "CODEXLENS_MODEL" in environment_result.output
    assert cli_result.exit_code == 2
    assert "non-empty OpenAI model ID" in cli_result.output


def test_confirmed_finding_returns_one_and_redacts_secret(tmp_path: Path) -> None:
    source_file = tmp_path / "settings.py"
    secret = "demo-password-not-for-production"
    source_file.write_text(f'DB_PASSWORD = "{secret}"\n', encoding="utf-8")

    result = runner.invoke(app, ["scan", str(source_file)])

    assert result.exit_code == 1
    assert "CL001" in result.output
    assert "HIGH" in result.output
    assert secret not in result.output


def test_entropy_candidate_does_not_fail_scan(tmp_path: Path) -> None:
    source_file = tmp_path / "config.py"
    source_file.write_text(
        'opaque_value = "eB7@qL2#vN9$kR4%tW8!yH3&cM6*Pz1Z"\n',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(source_file)])

    assert result.exit_code == 0
    assert "CL003" in result.output
    assert "candidate" in result.output


def test_incomplete_scan_returns_three(tmp_path: Path) -> None:
    source_file = tmp_path / "broken.py"
    source_file.write_text("def broken(:\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(source_file)])

    assert result.exit_code == 3
    assert "Incomplete scan diagnostics" in result.output
    assert "syntax error" in result.output.lower()


def test_scan_rejects_nonexistent_path(tmp_path: Path) -> None:
    missing_path = tmp_path / "does-not-exist"

    result = runner.invoke(app, ["scan", str(missing_path)])

    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_scan_rejects_non_python_file(tmp_path: Path) -> None:
    text_file = tmp_path / "notes.txt"
    text_file.write_text("notes", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(text_file)])

    assert result.exit_code == 2
    assert "TARGET must be a Python" in result.output
    assert "directory" in result.output


def test_scan_requires_a_target() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "Missing argument" in result.output


def _confirmation_proposal(target: Path) -> PatchProposal:
    root_stat = target.stat()
    finding = AiFinding(
        category="insecure_direct_object_reference",
        severity=Severity.HIGH,
        confidence=AiFindingConfidence.HIGH,
        title="Example authorization finding",
        description="Example finding.",
        path=Path("app.py"),
        start_line=1,
        end_line=1,
        evidence="Example evidence.",
        impact="Example impact.",
        recommendation="Example recommendation.",
    )
    candidate = FixCandidate(
        candidate_id="fx_confirmation",
        finding=finding,
        relative_path=Path("app.py"),
        source_unit_id="u0001",
        source_unit_start_line=1,
        source_unit_end_line=1,
        source_unit_sha256="0" * 64,
    )
    return PatchProposal(
        candidate=candidate,
        target_root=target,
        target_root_device=root_stat.st_dev,
        target_root_inode=root_stat.st_ino,
        path=target / "app.py",
        relative_path=Path("app.py"),
        base_file_sha256="0" * 64,
        original_bytes=b"",
        updated_bytes=b"",
        unified_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n",
        summary="Example change.",
    )
