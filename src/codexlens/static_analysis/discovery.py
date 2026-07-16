"""Safe, deterministic Python source-file discovery."""

import os
from dataclasses import dataclass
from pathlib import Path

from codexlens.models import ScanDiagnostic

MAX_PYTHON_FILES = 10_000
IGNORED_DIRECTORIES = frozenset(
    {
        ".eggs",
        ".git",
        ".hg",
        ".mypy_cache",
        ".nox",
        ".pytest_cache",
        ".ruff_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "env",
        "node_modules",
        "site-packages",
        "venv",
    }
)


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """Python files that can safely be passed to the static-analysis engine."""

    files: tuple[Path, ...]
    diagnostics: tuple[ScanDiagnostic, ...] = ()


def discover_python_files(target: Path) -> DiscoveryResult:
    """Find Python files beneath *target* without following symbolic links."""

    resolved_target = target.resolve()
    if resolved_target.is_file():
        if resolved_target.suffix.lower() != ".py":
            return DiscoveryResult(files=())
        return DiscoveryResult(files=(resolved_target,))

    files: list[Path] = []
    diagnostics: list[ScanDiagnostic] = []

    def on_error(error: OSError) -> None:
        error_path = Path(error.filename).resolve() if error.filename else resolved_target
        diagnostics.append(
            ScanDiagnostic(
                kind="traversal-error",
                path=error_path,
                message="Unable to traverse this directory.",
            )
        )

    for root, directory_names, file_names in os.walk(
        resolved_target,
        followlinks=False,
        onerror=on_error,
    ):
        root_path = Path(root)
        directory_names[:] = _included_directories(root_path, directory_names, diagnostics)

        for file_name in sorted(file_names, key=str.casefold):
            candidate = root_path / file_name
            if candidate.suffix.lower() != ".py":
                continue
            if candidate.is_symlink():
                diagnostics.append(
                    ScanDiagnostic(
                        kind="symbolic-link",
                        path=candidate,
                        message="Skipped symbolic-link source file.",
                    )
                )
                continue

            resolved_candidate = candidate.resolve()
            if not _is_within(resolved_candidate, resolved_target):
                diagnostics.append(
                    ScanDiagnostic(
                        kind="path-escape",
                        path=candidate,
                        message="Skipped source file outside the selected target.",
                    )
                )
                continue

            if len(files) >= MAX_PYTHON_FILES:
                diagnostics.append(
                    ScanDiagnostic(
                        kind="file-limit",
                        path=resolved_target,
                        message=f"Stopped after {MAX_PYTHON_FILES} Python files.",
                    )
                )
                return DiscoveryResult(
                    files=tuple(_sorted_files(files, resolved_target)),
                    diagnostics=tuple(diagnostics),
                )
            files.append(resolved_candidate)

    return DiscoveryResult(
        files=tuple(_sorted_files(files, resolved_target)),
        diagnostics=tuple(diagnostics),
    )


def _included_directories(
    root: Path,
    directory_names: list[str],
    diagnostics: list[ScanDiagnostic],
) -> list[str]:
    included: list[str] = []
    for directory_name in sorted(directory_names, key=str.casefold):
        candidate = root / directory_name
        if directory_name in IGNORED_DIRECTORIES or directory_name.endswith(".egg-info"):
            continue
        if candidate.is_symlink():
            diagnostics.append(
                ScanDiagnostic(
                    kind="symbolic-link",
                    path=candidate,
                    message="Skipped symbolic-link directory.",
                )
            )
            continue
        included.append(directory_name)
    return included


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _sorted_files(files: list[Path], root: Path) -> list[Path]:
    return sorted(files, key=lambda path: path.relative_to(root).as_posix().casefold())
