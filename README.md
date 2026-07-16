# CodexLens

CodexLens is an AI-powered security auditor for Python projects. It combines fast local checks with AI-assisted reasoning about business-logic vulnerabilities, then presents reviewable patches for explicit user approval.

## Current milestone

Pass 1 is implemented. `scan` recursively discovers Python files, skips common virtual-environment and build directories, and runs local checks for hardcoded credentials, high-entropy secret candidates, and unsafe Python calls. It does **not** call the OpenAI API, generate patches, or modify files.

## Setup

CodexLens requires Python 3.11 or newer.

```bash
uv sync --all-groups
uv run codexlens --help
uv run codexlens scan ./my_project
```

`--fix` is accepted now to establish the command contract, but it does not write changes until the interactive patching pass is implemented. Confirmed security findings return exit code `1`; an incomplete scan returns `3`.

## Planned pipeline

1. **Static analysis** — local regex, entropy, and AST checks for high-signal issues.
2. **AI deep scan** — context-aware analysis for authorization flaws, IDOR, race conditions, mass assignment, and privilege escalation.
3. **Interactive auto-fix** — proposed unified diffs, applied only after explicit confirmation.

## Development

```bash
uv run pytest
uv run ruff check .
```
