from pathlib import Path

from typer.testing import CliRunner

from codexlens.cli import app

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


def test_fix_flag_is_acknowledged_without_writing_target(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    original_contents = "print('hello')\n"
    source_file.write_text(original_contents, encoding="utf-8")

    result = runner.invoke(app, ["scan", str(source_file), "--fix"])

    assert result.exit_code == 0
    assert "Fix mode: requested" in result.output
    assert "Fix mode was requested" in result.output
    assert "were changed" in result.output
    assert source_file.read_text(encoding="utf-8") == original_contents


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
