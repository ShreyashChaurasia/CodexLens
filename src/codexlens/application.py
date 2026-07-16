"""Application boundary for the CodexLens scanning pipeline."""

from codexlens.models import ScanConfig, ScanResult
from codexlens.static_analysis import run_static_analysis


def run_scan(config: ScanConfig) -> ScanResult:
    """Run the local static-analysis pass without modifying the target."""

    return ScanResult(config=config, static=run_static_analysis(config.target))
