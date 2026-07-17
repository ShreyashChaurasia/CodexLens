# CodexLens

CodexLens is an AI-powered security auditor for Python projects. It combines fast local checks with AI-assisted reasoning about business-logic vulnerabilities, then presents reviewable patches for explicit user approval.

## Current milestone

Passes 1 and 2 are implemented. `scan` recursively discovers Python files, skips common virtual-environment and build directories, and runs local checks for hardcoded credentials, high-entropy secret candidates, and unsafe Python calls. When a model is selected, it also runs an AI-assisted business-logic review for broken access control, IDOR, race conditions, mass assignment, and privilege escalation. Pass 3 does not yet generate or apply patches.

## Setup

CodexLens requires Python 3.11 or newer.

```bash
uv sync --all-groups
uv run codexlens --help
uv run codexlens scan ./my_project
```

`--fix` is accepted now to establish the command contract, but it does not write changes until the interactive patching pass is implemented. Confirmed static findings return exit code `1`; an incomplete requested scan returns `3`.

## AI model selection

CodexLens is model-agnostic: it uses the exact OpenAI model ID you select, with no Terra, Codex, or other model-family default. Select a model for one command with `--model` (or `-m`), or set `CODEXLENS_MODEL` for your environment:

```powershell
$env:CODEXLENS_MODEL = "my-approved-model-id"
$env:OPENAI_API_KEY = "your-api-key"
uv run codexlens scan ./my_project
uv run codexlens scan ./my_project --model another-model-id
```

The command-line value takes precedence. Without a selected model, CodexLens runs only local Pass 1 checks and makes no API call. With a selected model, it accepts any non-empty model ID without a client-side allowlist and runs Pass 2 through the Responses API. Choose a text-capable model that your API key can access and that supports Structured Outputs. See OpenAI's [model catalog](https://developers.openai.com/api/docs/models) and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs) for current capabilities.

Before source is sent to the API, CodexLens redacts known credentials, sensitive assignments, and high-entropy literals; it also limits and line-maps the source context. Pass 2 sends `store=False`, validates the returned JSON and every reported path/line locally, and labels AI findings as human-review candidates. A missing API key, inaccessible/incompatible model, context limit, or malformed response preserves the static result and returns exit code `3` with a sanitized diagnostic.

## Planned pipeline

1. **Static analysis** — local regex, entropy, and AST checks for high-signal issues.
2. **AI deep scan** — context-aware, structured analysis with a user-selected OpenAI model for authorization flaws, IDOR, race conditions, mass assignment, and privilege escalation.
3. **Interactive auto-fix** — proposed unified diffs, applied only after explicit confirmation.

## Development

```bash
uv run pytest
uv run ruff check .
```
