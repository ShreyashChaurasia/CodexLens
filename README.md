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

## AI model selection

CodexLens is model-agnostic: the future AI passes will use the exact OpenAI model ID you select, with no Terra, Codex, or other model-family default. Select a model for one command with `--model` (or `-m`), or set `CODEXLENS_MODEL` for your environment:

```powershell
$env:CODEXLENS_MODEL = "my-approved-model-id"
uv run codexlens scan ./my_project
uv run codexlens scan ./my_project --model another-model-id
```

The command-line value takes precedence. CodexLens accepts any non-empty identifier without a client-side allowlist; when Pass 2 is added, choose a text-capable Responses model that your API key can access. See OpenAI's [model catalog](https://developers.openai.com/api/docs/models) for current model capabilities. Configuring a model does not call the API during the current Pass 1-only milestone.

## Planned pipeline

1. **Static analysis** — local regex, entropy, and AST checks for high-signal issues.
2. **AI deep scan** — context-aware analysis with a user-selected OpenAI model for authorization flaws, IDOR, race conditions, mass assignment, and privilege escalation.
3. **Interactive auto-fix** — proposed unified diffs, applied only after explicit confirmation.

## Development

```bash
uv run pytest
uv run ruff check .
```
