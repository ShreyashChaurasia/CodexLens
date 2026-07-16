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


def test_scan_directory_renders_truthful_scaffold_status(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    result = runner.invoke(app, ["scan", str(project)])

    assert result.exit_code == 0
    assert "Target:" in result.output
    assert "directory" in result.output
    assert "Scaffold only" in result.output
    assert "no security analysis has been run" in result.output
    assert "Fix mode:" in result.output
    assert "disabled" in result.output


def test_scan_file_is_supported(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(source_file)])

    assert result.exit_code == 0
    assert "Target:" in result.output
    assert "Target type:" in result.output
    assert "file" in result.output


def test_fix_flag_is_acknowledged_without_writing_target(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    original_contents = "print('hello')\n"
    source_file.write_text(original_contents, encoding="utf-8")

    result = runner.invoke(app, ["scan", str(source_file), "--fix"])

    assert result.exit_code == 0
    assert "Fix mode:" in result.output
    assert "enabled (no files will be changed yet)" in result.output
    assert source_file.read_text(encoding="utf-8") == original_contents


def test_scan_rejects_nonexistent_path(tmp_path: Path) -> None:
    missing_path = tmp_path / "does-not-exist"

    result = runner.invoke(app, ["scan", str(missing_path)])

    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_scan_requires_a_target() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "Missing argument" in result.output
