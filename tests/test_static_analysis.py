from pathlib import Path

from codexlens.models import FindingConfidence, Severity
from codexlens.static_analysis.discovery import discover_python_files
from codexlens.static_analysis.engine import run_static_analysis


def test_discovery_is_deterministic_and_skips_tooling_directories(tmp_path: Path) -> None:
    source_root = tmp_path / "project"
    _write(source_root / "b.py", "pass\n")
    _write(source_root / "package" / "a.py", "pass\n")
    _write(source_root / ".venv" / "ignored.py", "pass\n")
    _write(source_root / ".git" / "hook.py", "pass\n")
    _write(source_root / "__pycache__" / "cached.py", "pass\n")
    _write(source_root / "README.md", "ignored")

    result = discover_python_files(source_root)

    assert result.files == (
        (source_root / "b.py").resolve(),
        (source_root / "package" / "a.py").resolve(),
    )
    assert not result.diagnostics


def test_discovery_accepts_a_single_python_file(tmp_path: Path) -> None:
    source_file = _write(tmp_path / "app.py", "pass\n")

    result = discover_python_files(source_file)

    assert result.files == (source_file.resolve(),)


def test_empty_directory_is_a_complete_clean_scan(tmp_path: Path) -> None:
    result = run_static_analysis(tmp_path)

    assert result.complete
    assert result.files_discovered == 0
    assert result.files_scanned == 0
    assert not result.findings


def test_hardcoded_sensitive_assignment_is_found_without_value(tmp_path: Path) -> None:
    secret = "demo-password-not-for-production"
    source_file = _write(tmp_path / "settings.py", f'DB_PASSWORD = "{secret}"\n')

    result = run_static_analysis(source_file)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "CL001"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is FindingConfidence.CONFIRMED
    assert finding.path == source_file.resolve()
    assert finding.line == 1
    assert secret not in finding.description


def test_known_credential_pattern_takes_precedence_over_assignment(tmp_path: Path) -> None:
    source_file = _write(
        tmp_path / "settings.py",
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
    )

    result = run_static_analysis(source_file)

    assert [finding.rule_id for finding in result.findings] == ["CL002"]
    assert result.findings[0].severity is Severity.CRITICAL


def test_placeholders_and_environment_lookups_are_not_hardcoded_secrets(tmp_path: Path) -> None:
    source_file = _write(
        tmp_path / "settings.py",
        'DB_PASSWORD = "${DB_PASSWORD}"\n'
        'API_SECRET = "[REDACTED_SECRET]"\n'
        'api_key = os.environ["API_KEY"]\n',
    )

    result = run_static_analysis(source_file)

    assert not result.findings


def test_high_entropy_literal_is_a_candidate_and_not_a_failure(tmp_path: Path) -> None:
    source_file = _write(
        tmp_path / "config.py",
        'opaque_value = "eB7@qL2#vN9$kR4%tW8!yH3&cM6*Pz1Z"\n',
    )

    result = run_static_analysis(source_file)

    assert [finding.rule_id for finding in result.findings] == ["CL003"]
    assert result.candidates == result.findings
    assert not result.confirmed_findings


def test_low_entropy_and_hex_values_are_not_secret_candidates(tmp_path: Path) -> None:
    source_file = _write(
        tmp_path / "constants.py",
        'repeated = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        'digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"\n',
    )

    result = run_static_analysis(source_file)

    assert not result.findings


def test_ast_rules_detect_aliases_and_preserve_safe_counterparts(tmp_path: Path) -> None:
    source_file = _write(
        tmp_path / "unsafe.py",
        "import os as operating_system\n"
        "from subprocess import run as execute\n"
        "import pickle\n"
        "import requests as http\n"
        "import yaml\n"
        "operating_system.system(f'echo {user}')\n"
        "execute(command, shell=True)\n"
        "eval(payload)\n"
        "pickle.loads(payload)\n"
        "yaml.load(payload)\n"
        "yaml.load(payload, Loader=yaml.SafeLoader)\n"
        "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        "http.get('https://example.test', verify=False)\n"
        "execute(['grep', user, 'users.txt'], check=True)\n"
        "yaml.safe_load(payload)\n"
        "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n",
    )

    result = run_static_analysis(source_file)

    assert [finding.rule_id for finding in result.findings] == [
        "CL101",
        "CL102",
        "CL103",
        "CL104",
        "CL105",
        "CL106",
        "CL107",
    ]


def test_syntax_error_is_diagnostic_but_text_checks_and_siblings_continue(tmp_path: Path) -> None:
    _write(
        tmp_path / "broken.py",
        'DB_PASSWORD = "demo-password-not-for-production"\ndef broken(:\n',
    )
    _write(
        tmp_path / "unsafe.py",
        "import os\nos.system(f'echo {user}')\n",
    )

    result = run_static_analysis(tmp_path)

    assert {finding.rule_id for finding in result.findings} == {"CL001", "CL101"}
    assert result.files_scanned == 2
    assert not result.complete
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].kind == "syntax-error"
    assert result.diagnostics[0].path.name == "broken.py"


def _write(path: Path, contents: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")
    return path
