"""Create a disposable ExpenseFlow workspace for the live CodexLens patch demo."""

from pathlib import Path
from shutil import copytree, rmtree

EXAMPLE_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_SOURCE = EXAMPLE_ROOT / "vulnerable"
WORKSPACE = EXAMPLE_ROOT / "work"


def main() -> None:
    """Reset only the hard-coded ignored work directory from the canonical fixture."""

    if not CANONICAL_SOURCE.is_dir():
        raise RuntimeError("The canonical vulnerable fixture is missing.")
    if WORKSPACE.exists():
        if WORKSPACE.resolve().parent != EXAMPLE_ROOT.resolve():
            raise RuntimeError("Refusing to reset a workspace outside the ExpenseFlow example.")
        rmtree(WORKSPACE)

    copytree(CANONICAL_SOURCE, WORKSPACE)
    print(f"Prepared disposable demo workspace: {WORKSPACE}")
    print("Scan work/app/main.py with CodexLens; vulnerable/ remains unchanged.")


if __name__ == "__main__":
    main()
