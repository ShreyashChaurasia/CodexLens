"""Application boundary for the CodexLens scanning pipeline."""

from codexlens.models import ScanConfig, ScanResult
from codexlens.static_analysis import run_static_analysis


def run_scan(config: ScanConfig) -> ScanResult:
    """Run Pass 1 without modifying the target or invoking a configured model."""

    return ScanResult(config=config, static=run_static_analysis(config.target))
