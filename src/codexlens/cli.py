"""Typer commands and terminal-facing validation for CodexLens."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from codexlens.application import run_scan
from codexlens.auto_fix.models import PatchProposal, PatchStatus
from codexlens.auto_fix.workflow import run_fix_workflow
from codexlens.config import ModelConfigurationError, resolve_openai_model
from codexlens.models import ScanConfig
from codexlens.reporting import (
    render_fix_result,
    render_patch_proposal,
    render_scan_result,
)

app = typer.Typer(
    name="codexlens",
    help="CodexLens: AI-powered security auditing for Python projects.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.callback()
def codexlens() -> None:
    """Run CodexLens commands."""


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=True,
            dir_okay=True,
            readable=True,
            resolve_path=True,
            help="Python source file or project directory to audit.",
        ),
    ],
    fix: Annotated[
        bool,
        typer.Option(
            "--fix",
            help="Request confirmation-gated patches for completed AI findings.",
        ),
    ] = False,
    model: Annotated[
        str | None,
        typer.Option(
            "--model",
            "-m",
            help="OpenAI model ID for Pass 2 AI analysis; overrides CODEXLENS_MODEL.",
        ),
    ] = None,
) -> None:
    """Start a security audit for TARGET."""

    if target.is_file() and target.suffix.lower() != ".py":
        raise typer.BadParameter(
            "TARGET must be a Python (.py) file or a directory.",
            param_hint="TARGET",
        )

    try:
        selected_model = resolve_openai_model(model)
    except ModelConfigurationError as error:
        raise typer.BadParameter(str(error), param_hint=error.source) from error

    result = run_scan(ScanConfig(target=target, fix_enabled=fix, model=selected_model))
    render_scan_result(console, result)
    exit_code = result.exit_code
    if result.config.fix_enabled:
        fix_result = run_fix_workflow(result.config, result.ai, confirm=_confirm_patch)
        render_fix_result(console, fix_result, result.config.target)
        if fix_result.status is PatchStatus.FAILED:
            exit_code = max(exit_code, 3)
    if exit_code:
        raise typer.Exit(code=exit_code)


def _confirm_patch(proposal: PatchProposal) -> bool:
    """Render a local diff and require an explicit interactive opt-in to write it."""

    render_patch_proposal(console, proposal)
    try:
        return typer.confirm(
            f"Apply this patch to {proposal.relative_path.as_posix()}?",
            default=False,
        )
    except (typer.Abort, EOFError, OSError):
        return False
