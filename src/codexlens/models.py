"""Small, stable data contracts shared by the CLI and scan pipeline."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Options selected for one CodexLens scan request."""

    target: Path
    fix_enabled: bool = False


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The current result of running a scan request."""

    config: ScanConfig
    message: str
