"""Application boundary for the CodexLens scanning pipeline."""

from codexlens.models import ScanConfig, ScanResult

SCAFFOLD_MESSAGE = "Scaffold only - no security analysis has been run."


def run_scan(config: ScanConfig) -> ScanResult:
    """Run the scan pipeline.

    This intentionally has no side effects until the static-analysis pass is
    implemented. Keeping this boundary pure means the CLI can later add the
    three passes without mixing terminal concerns, OpenAI calls, or file writes.
    """

    return ScanResult(config=config, message=SCAFFOLD_MESSAGE)
