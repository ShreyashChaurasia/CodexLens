from pathlib import Path

from codexlens.application import run_scan
from codexlens.models import (
    AiFinding,
    AiFindingConfidence,
    AiScanDiagnostic,
    AiScanResult,
    AiScanStatus,
    ScanConfig,
    Severity,
)


class RecordingAnalyzer:
    def __init__(self, result: AiScanResult) -> None:
        self.result = result
        self.calls: list[tuple[Path, str]] = []

    def analyze(self, target: Path, model: str, _static: object) -> AiScanResult:
        self.calls.append((target, model))
        return self.result


def test_no_model_skips_ai_without_invoking_analyzer(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    analyzer = RecordingAnalyzer(AiScanResult(status=AiScanStatus.COMPLETED, model="unused"))

    result = run_scan(ScanConfig(target=tmp_path), ai_analyzer=analyzer)

    assert result.ai.status is AiScanStatus.SKIPPED
    assert not analyzer.calls
    assert result.exit_code == 0


def test_selected_model_reaches_injected_analyzer_unchanged(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    analyzer = RecordingAnalyzer(
        AiScanResult(status=AiScanStatus.COMPLETED, model="custom/provider-model:2026-07")
    )

    result = run_scan(
        ScanConfig(target=tmp_path, model="custom/provider-model:2026-07"),
        ai_analyzer=analyzer,
    )

    assert analyzer.calls == [(tmp_path, "custom/provider-model:2026-07")]
    assert result.ai.status is AiScanStatus.COMPLETED
    assert result.exit_code == 0


def test_incomplete_ai_scan_takes_exit_code_precedence(tmp_path: Path) -> None:
    source_file = tmp_path / "settings.py"
    source_file.write_text('DB_PASSWORD = "demo-password-not-for-production"\n', encoding="utf-8")
    analyzer = RecordingAnalyzer(
        AiScanResult(
            status=AiScanStatus.FAILED,
            model="custom-model",
            diagnostics=(AiScanDiagnostic(kind="ai-api-error", message="AI scan failed."),),
        )
    )

    result = run_scan(ScanConfig(target=tmp_path, model="custom-model"), ai_analyzer=analyzer)

    assert result.static.confirmed_findings
    assert result.exit_code == 3


def test_ai_review_findings_do_not_fail_ci_by_default(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text("print('hello')\n", encoding="utf-8")
    finding = AiFinding(
        category="authorization_bypass",
        severity=Severity.HIGH,
        confidence=AiFindingConfidence.HIGH,
        title="Authorization check is missing",
        description="The route mutates an object without an ownership check.",
        path=Path("app.py"),
        start_line=1,
        end_line=1,
        evidence="The mutation has no authorization condition.",
        impact="Another user's data could be changed.",
        recommendation="Scope the operation to the current principal.",
    )
    analyzer = RecordingAnalyzer(
        AiScanResult(
            status=AiScanStatus.COMPLETED,
            model="custom-model",
            findings=(finding,),
        )
    )

    result = run_scan(ScanConfig(target=tmp_path, model="custom-model"), ai_analyzer=analyzer)

    assert result.ai.findings == (finding,)
    assert result.exit_code == 0
