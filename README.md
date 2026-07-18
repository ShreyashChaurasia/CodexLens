# CodexLens

CodexLens is an AI-powered security auditor for Python projects. It combines fast local checks with AI-assisted reasoning about business-logic vulnerabilities, then presents reviewable patches for explicit user approval.

## Current milestone

All three passes are implemented. `scan` recursively discovers Python files, skips common virtual-environment and build directories, and runs local checks for hardcoded credentials, high-entropy secret candidates, and unsafe Python calls. When a model is selected, it also runs an AI-assisted business-logic review for broken access control, IDOR, race conditions, mass assignment, and privilege escalation. With `--fix`, CodexLens can propose one narrowly scoped patch at a time for a completed AI finding.

## Setup

CodexLens requires Python 3.11 or newer.

```bash
uv sync --all-groups
uv run codexlens --help
uv run codexlens scan ./my_project
```

Confirmed static findings return exit code `1`; an incomplete requested scan returns `3`.

## AI model selection

CodexLens is model-agnostic: it uses the exact OpenAI model ID you select, with no Terra, Codex, or other model-family default. Select a model for one command with `--model` (or `-m`), or set `CODEXLENS_MODEL` for your environment:

```powershell
$env:CODEXLENS_MODEL = "my-approved-model-id"
$env:OPENAI_API_KEY = "your-api-key"
uv run codexlens scan ./my_project
uv run codexlens scan ./my_project --model another-model-id
```

The command-line value takes precedence. Without a selected model, CodexLens runs only local Pass 1 checks and makes no API call. With a selected model, it accepts any non-empty model ID without a client-side allowlist and runs Pass 2 through the Responses API; Pass 3 makes a second Responses API request only when `--fix` is supplied. Choose a text-capable model that your API key can access and that supports Structured Outputs. See OpenAI's [model catalog](https://developers.openai.com/api/docs/models) and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs) for current capabilities.

Before source is sent to the API, CodexLens redacts known credentials, sensitive assignments, and high-entropy literals; it also limits and line-maps the source context. Pass 2 sends `store=False`, validates the returned JSON and every reported path/line locally, and labels AI findings as human-review candidates. A missing API key, inaccessible/incompatible model, context limit, or malformed response preserves the static result and returns exit code `3` with a sanitized diagnostic.

## Interactive auto-fix

Use `--fix` together with a model to request Pass 3:

```bash
uv run codexlens scan ./my_project --model my-approved-model-id --fix
```

Pass 3 is intentionally conservative:

- It considers only findings from a **completed** Pass 2 scan, never generic static findings.
- It binds each request to the exact reviewed Python source unit and captures a fresh local file snapshot before calling the model.
- A unit containing a likely secret is never sent for patch generation.
- The model returns a complete replacement for that one unit through a strict JSON schema. CodexLens creates the displayed unified diff locally, checks syntax, scope, sensitive content, response bindings, and patch size, then asks `Apply this patch ...? [y/N]`.
- Applying a patch requires an explicit `y`. CodexLens re-hashes the file immediately before an atomic same-directory replacement, so stale files are not overwritten. After one applied patch, rerun the scan before considering another fix.

If input is unavailable, a proposal is declined by default. CodexLens never executes a model-provided patch command or trusts a model-provided file path or diff.

## CI and machine-readable output

The terminal UI is the default. Use `--format json` for a stable,
source-free report that can be stored as a CI artifact or consumed by another
tool:

```bash
uv run codexlens scan src --format json > codexlens-report.json
```

The JSON schema version is `codexlens.scan.v1`. It includes relative locations,
finding metadata, diagnostics, pass status, and the same exit code as the
terminal command, but omits source code, raw model responses, source-unit
bindings, and patch diffs. Exit code `0` means no confirmed static findings,
`1` means confirmed static findings, and `3` means an incomplete scan.
AI findings remain human-review candidates and do not independently fail CI.

`--format json` cannot be combined with `--fix`: patch review requires the
interactive Rich diff and explicit confirmation.

The included [CI workflow](.github/workflows/ci.yml) pins Python 3.11, runs
Ruff and pytest, and uploads this JSON report as a workflow artifact.

## Architecture and safety model

```text
Python target
    |
    +-- Pass 1: local regex / entropy / AST checks
    |       `--> confirmed static findings and diagnostics
    |
    `-- Pass 2: bounded, redacted source units --(selected OpenAI model)--> structured review
                    |                                            |
                    `----------- local schema, path, and line validation
                                                                 |
--fix only ------------------------------------------------------+
    |
    `-- Pass 3: fresh source snapshot --> constrained replacement --> local diff and checks
                                                                     |
                                                           explicit y / n in Rich UI
                                                                     |
                                                   re-hash + atomic same-directory write
```

CodexLens treats both scanned source and model output as untrusted data. It
does not trust model-supplied paths, diffs, shell commands, or line locations.
Before a patch is shown, it is bound to the reviewed source unit, checked for
scope, syntax, encoding, sensitive content, response bindings, and size; it is
re-hashed immediately before the atomic replacement. A result is still a
security review aid, not a security guarantee: keep human review, tests, and
normal deployment controls in the loop.

## Owned ExpenseFlow demo

[`examples/expenseflow/`](examples/expenseflow/README.md) is an owned,
intentionally vulnerable multi-tenant FastAPI fixture. It provides a
reproducible IDOR/broken-access-control demo, an exploit proof, a hardened
reference, and a disposable workspace for the live `--fix` recording. It uses
only synthetic data and must never be deployed.

For a no-key judge walkthrough, run the built-in replay:

```bash
uv run codexlens demo
```

`demo` is prominently labelled as an **offline recorded replay** and makes no
OpenAI API request. It stages a small owned ExpenseFlow fixture in a temporary
directory, replays schema-valid Pass 2 and Pass 3 responses through the same
local validation code, shows the Rich diff, asks for the same explicit `y`/`n`
confirmation, verifies the authorization invariant after an accepted patch,
and then discards the staged source. Use the commands in the example README
when recording the real selected-model API flow.

The [Build Week recording script](BUILD_WEEK_DEMO_SCRIPT.md) separates the
no-key replay from the live selected-model flow and lists the remaining
submission steps that need your real account, video, and feedback session ID.

## Planned pipeline

1. **Static analysis** — local regex, entropy, and AST checks for high-signal issues.
2. **AI deep scan** — context-aware, structured analysis with a user-selected OpenAI model for authorization flaws, IDOR, race conditions, mass assignment, and privilege escalation.
3. **Interactive auto-fix** — constrained, locally validated source-unit replacements, previewed as unified diffs and applied only after explicit confirmation.

## Development

```bash
uv run pytest
uv run ruff check .
```
