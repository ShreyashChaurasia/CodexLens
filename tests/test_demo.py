from io import StringIO

from rich.console import Console
from typer.testing import CliRunner

from codexlens.auto_fix.models import PatchStatus
from codexlens.cli import app
from codexlens.demo import run_offline_demo
from codexlens.models import AiScanStatus

runner = CliRunner()


def test_offline_demo_replays_a_complete_finding_and_applies_only_after_confirmation() -> None:
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None)

    result = run_offline_demo(console, confirm=lambda _proposal: True)

    assert result.exit_code == 0
    assert result.vulnerable_before_patch is True
    assert result.scan.ai.status is AiScanStatus.COMPLETED
    assert result.scan.ai.units_discovered == result.scan.ai.units_scanned
    assert len(result.scan.ai.findings) == 1
    assert result.fix.status is PatchStatus.APPLIED
    assert result.blocked_after_patch is True
    assert result.ai_requests == 1
    assert result.patch_requests == 1
    assert "OFFLINE RECORDED REPLAY" in stream.getvalue()
    assert "No OpenAI API request is made" in stream.getvalue()


def test_offline_demo_decline_preserves_the_temporary_fixture() -> None:
    stream = StringIO()
    console = Console(file=stream, force_terminal=False, color_system=None)

    result = run_offline_demo(console, confirm=lambda _proposal: False)

    assert result.exit_code == 0
    assert result.vulnerable_before_patch is True
    assert result.fix.status is PatchStatus.DECLINED
    assert result.blocked_after_patch is None
    assert result.ai_requests == 1
    assert result.patch_requests == 1
    assert "discarded unchanged" in stream.getvalue()


def test_demo_command_is_explicitly_offline_and_keeps_confirmation_in_the_ui() -> None:
    result = runner.invoke(app, ["demo"], input="n\n")

    assert result.exit_code == 0
    assert "OFFLINE RECORDED REPLAY" in result.output
    assert "No OpenAI API request is made" in result.output
    assert "Apply this patch to expenseflow.py?" in result.output
    assert "Patch declined" in result.output
