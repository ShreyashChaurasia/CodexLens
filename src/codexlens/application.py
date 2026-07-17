"""Application boundary for the CodexLens scanning pipeline."""

from codexlens.ai_analysis import AiAnalyzer, OpenAIResponsesAnalyzer
from codexlens.models import AiScanResult, ScanConfig, ScanResult
from codexlens.static_analysis import run_static_analysis


def run_scan(config: ScanConfig, *, ai_analyzer: AiAnalyzer | None = None) -> ScanResult:
    """Run Pass 1 and, when selected, the model-assisted Pass 2 review."""

    static = run_static_analysis(config.target)
    if config.model is None:
        ai = AiScanResult.skipped()
    else:
        analyzer = ai_analyzer or OpenAIResponsesAnalyzer()
        ai = analyzer.analyze(config.target, config.model, static)
    return ScanResult(config=config, static=static, ai=ai)
