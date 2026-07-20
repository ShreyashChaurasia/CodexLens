# CodexLens

CodexLens is a Python CLI security auditor for projects that need more than
pattern matching. It combines deterministic local checks with optional
AI-assisted business-logic review, then presents constrained code fixes in a
Rich terminal diff. A source file changes only after explicit confirmation.

This repository provides a reproducible OpenAI Build Week demonstration of the
complete workflow: static analysis, an AI review candidate, a confirmation-gated
patch, and a security regression test.

## Evaluation paths

| Path | Credentials | Command | Outcome |
| --- | --- | --- | --- |
| Local static audit | None | `uv run codexlens scan src` | Pass 1 detection with no network request. |
| Offline workflow replay | None | `uv run codexlens demo` | A deterministic Rich-terminal replay; no OpenAI request and no repository modification. |
| Live end-to-end evaluation | OpenAI API key and model ID | [ExpenseFlow](examples/expenseflow/README.md) | A selected OpenAI model reviews and proposes a fix for the ExpenseFlow IDOR scenario. |

The offline replay is prominently labelled **offline recorded replay**. It is a
deterministic product walkthrough, not a substitute for a live model result.

## Capabilities

| Pass | Execution | Purpose | Output |
| --- | --- | --- | --- |
| 1. Static analysis | Local | Scans Python files with regex, entropy, and AST checks. | Confirmed findings, candidates, and diagnostics. |
| 2. AI deep scan | Optional OpenAI Responses API request | Reviews bounded, redacted source units for business-logic weaknesses. | Structured findings that require human review. |
| 3. Interactive auto-fix | Optional after completed Pass 2 | Proposes a narrowly scoped source-unit replacement. | A locally generated diff and an explicit `y`/`n` decision. |

Pass 1 detects likely hardcoded credentials and high-entropy secret candidates,
dynamic shell use, `shell=True`, `eval`/`exec`, unsafe pickle/YAML
deserialization, dynamically constructed database queries, and disabled TLS
verification. Pass 2 assesses broken object-level authorization (including
IDOR), privilege escalation, mass assignment, and race conditions.

AI findings are review candidates rather than confirmed vulnerabilities. The
tool is a security-review aid, not a security guarantee.

## Installation and local verification

### Requirements

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- An OpenAI API key only for Pass 2 and Pass 3

At the repository root:

```bash
uv sync --all-groups
uv run codexlens --help
uv run codexlens scan src
uv run codexlens demo
```

`scan src` runs Pass 1 only when no model is configured and makes no external
request. `demo` stages a self-contained ExpenseFlow example in a temporary directory,
replays schema-valid Pass 2 and Pass 3 responses through CodexLens' normal
local validation path, presents the confirmation prompt, and discards the
temporary source after completion.

## Live AI scanning

Live AI scanning requires an OpenAI API key and an accessible, text-capable
model that supports the structured response format used by CodexLens. The
model ID is supplied per live scan or through `CODEXLENS_MODEL`; CodexLens has
no hard-coded model-family default or client-side model allowlist.

PowerShell:

```powershell
$env:OPENAI_API_KEY = "<api-key>"
$env:CODEXLENS_MODEL = "<model-id>"
uv run codexlens scan ./my_project
uv run codexlens scan ./my_project --model "another-model-id"
```

Bash or zsh:

```bash
export OPENAI_API_KEY="<api-key>"
export CODEXLENS_MODEL="<model-id>"
uv run codexlens scan ./my_project
```

The `--model` / `-m` value overrides `CODEXLENS_MODEL`. Without either value,
CodexLens intentionally completes only local Pass 1. With a model configured,
Pass 2 uses the OpenAI Responses API and Pass 3 makes a separate request only
when `--fix` is present. Model capabilities can be confirmed through OpenAI's
[model catalog](https://developers.openai.com/api/docs/models) and
[Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs).

> **Data-handling notice:** A live scan sends bounded source context to OpenAI,
> and API usage is billed to the associated account. Known credentials,
> sensitive assignments, and high-entropy literals are redacted heuristically
> before submission, and API requests set `store=False`; these controls do not
> guarantee removal of every sensitive detail. Live scanning is appropriate
> only for code authorized for sharing with the selected service.

## Interactive patch review

A live Pass 3 run is requested with `--fix`:

```bash
uv run codexlens scan ./my_project --model "model-id" --fix
```

| Safeguard | Behavior |
| --- | --- |
| Eligibility | Only findings from a completed Pass 2 scan and bound to a reviewed Python source unit can reach Pass 3. |
| Preview | CodexLens generates the unified diff locally after validating the replacement's target, scope, syntax, sensitive-content policy, bindings, and size. |
| Confirmation | `y` is the only input that applies a proposal. `n`, Enter, missing input, or an interrupted prompt declines it. |
| Application | A fresh file hash is checked before an atomic same-directory replacement. A run applies at most one validated patch. |

Declining a proposal permits review of another eligible proposal. After an
accepted patch, a new scan and the project's test suite provide the next
verification step. CodexLens does not execute model-provided commands or trust
model-provided file paths and diffs.

## ExpenseFlow showcase

[`examples/expenseflow/`](examples/expenseflow/README.md) is a self-contained,
intentionally vulnerable multi-tenant FastAPI service with synthetic data. The
primary scenario is a manager in one tenant approving an expense belonging to
another tenant: a broken-object-authorization / IDOR flaw that a role check
alone does not prevent.

The baseline evidence is reproducible:

```bash
cd examples/expenseflow
uv sync --all-groups
uv run pytest tests/test_exploit_proof.py tests/test_hardened_reference.py
```

The exploit-proof test passes by demonstrating the vulnerable cross-tenant
approval. The hardened-reference test documents the intended security property.
The example README contains the isolated live-patch workflow and post-patch
regression test. The fixture must not be deployed or reused outside this
controlled demonstration.

The [Build Week recording script](BUILD_WEEK_DEMO_SCRIPT.md) documents the
exploit → live scan → reviewed diff → regression-test sequence and separates
the no-key replay from the live selected-model demonstration.

## CI, reports, and exit codes

The Rich terminal UI is the default. `--format json` produces a stable,
machine-readable report for CI and other tooling:

```bash
uv run codexlens scan src --format json > codexlens-report.json
```

The report schema is `codexlens.scan.v1`. It contains relative locations,
finding metadata, diagnostics, pass status, and the exit code. It intentionally
omits raw source, raw Responses API output, source-unit bindings, and patch
diffs. Finding descriptions can still contain code-derived information, so the
report should be handled as potentially sensitive.

| Exit code | Meaning |
| --- | --- |
| `0` | The requested scan completed with no confirmed static finding. |
| `1` | The scan completed with one or more confirmed static findings. |
| `3` | A requested scan or fix did not complete safely; the output contains a diagnostic. |

AI review candidates do not independently fail CI. `--format json` and `--fix`
cannot be combined because patch review requires the interactive Rich diff and
explicit confirmation.

The included [GitHub Actions workflow](.github/workflows/ci.yml) installs
locked dependencies on Python 3.11, runs Ruff and pytest for both projects, and
uploads the static JSON report as an artifact.

## Scope and security posture

- Pass 1 is local. Pass 2 and Pass 3 are opt-in and request `store=False`.
- Static detection and redaction are narrow heuristics, not complete
  vulnerability coverage or data-loss prevention.
- CodexLens audits Python source files only. Incomplete static or AI coverage
  produces diagnostics and exit code `3` instead of a silent success.
- Scanned code and model output are treated as untrusted data. Human review,
  tests, and normal deployment controls remain required.
- The CLI targets Windows, macOS, and Linux shells; both PowerShell and POSIX
  environment-variable syntax are documented above.

## Development

```bash
uv sync --all-groups
uv run ruff check .
uv run pytest
```

## Project information

- [Release history](https://github.com/ShreyashChaurasia/CodexLens/releases)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

CodexLens is released under the [MIT License](LICENSE).
