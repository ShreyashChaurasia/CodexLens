"""Typer commands and terminal-facing validation for CodexLens."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from codexlens.application import run_scan
from codexlens.models import ScanConfig
from codexlens.reporting import render_scan_result

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
        typer.Option("--fix", help="Propose fixes after findings are available."),
    ] = False,
) -> None:
    """Start a security audit for TARGET."""

    result = run_scan(ScanConfig(target=target, fix_enabled=fix))
    render_scan_result(console, result)
