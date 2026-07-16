"""Rich rendering helpers for CodexLens command output."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from codexlens.models import ScanResult


def render_scan_result(console: Console, result: ScanResult) -> None:
    """Render the current pipeline status without overstating scan results."""

    target_kind = "directory" if result.config.target.is_dir() else "file"
    fix_mode = "enabled (no files will be changed yet)" if result.config.fix_enabled else "disabled"

    console.print(
        Panel.fit(
            f"[bold]Target:[/bold] {result.config.target}\n"
            f"[bold]Target type:[/bold] {target_kind}\n"
            f"[bold]Fix mode:[/bold] {fix_mode}",
            title="[bold cyan]CodexLens[/bold cyan]",
            border_style="cyan",
        )
    )

    pipeline = Table(title="Security audit pipeline", show_header=True, header_style="bold cyan")
    pipeline.add_column("Pass", style="bold", width=8)
    pipeline.add_column("Purpose")
    pipeline.add_column("Status", style="yellow")
    pipeline.add_row("1", "Static analysis", "Pending implementation")
    pipeline.add_row("2", "AI deep scan", "Pending implementation")
    pipeline.add_row("3", "Interactive auto-fix", "Pending implementation")
    console.print(pipeline)
    console.print(f"[yellow]{result.message}[/yellow]")
