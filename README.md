# CodexLens

CodexLens is an AI-powered security auditor for Python projects. It combines fast local checks with AI-assisted reasoning about business-logic vulnerabilities, then presents reviewable patches for explicit user approval.

## Current milestone

The CLI foundation is ready. `scan` validates a file or directory and previews the planned three-pass pipeline. It does **not** yet analyze code, call the OpenAI API, generate patches, or modify files.

## Setup

```bash
uv sync --all-groups
uv run codexlens --help
uv run codexlens scan ./my_project
```

`--fix` is accepted now to establish the command contract, but it does not write changes until the interactive patching pass is implemented.

## Planned pipeline

1. **Static analysis** — local regex, entropy, and AST checks for high-signal issues.
2. **AI deep scan** — context-aware analysis for authorization flaws, IDOR, race conditions, mass assignment, and privilege escalation.
3. **Interactive auto-fix** — proposed unified diffs, applied only after explicit confirmation.

## Development

```bash
uv run pytest
uv run ruff check .
```
