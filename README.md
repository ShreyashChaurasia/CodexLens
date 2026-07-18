# CodexLens

CodexLens is a Python CLI security auditor for code that needs more than pattern
matching. It combines local static checks with optional AI-assisted review of
business logic, then presents constrained code fixes as a Rich terminal diff
that must be explicitly approved before a real source file is changed.

Built as an OpenAI Build Week project, CodexLens is deliberately model-neutral:
you choose the OpenAI model ID for each live scan rather than relying on a
hard-coded model-family default.

## How it works

| Pass | Runs where | Purpose |
| --- | --- | --- |
| 1. Static analysis | Locally | Finds high-signal secret and insecure-call patterns without an API key. |
| 2. AI deep scan | Optional OpenAI Responses API request | Reviews bounded source context for business-logic risks that are difficult to express as a local rule. |
| 3. Interactive auto-fix | Optional, after a completed Pass 2 scan | Generates a narrowly scoped replacement, validates it locally, shows a diff, and waits for your approval. |

Pass 1 currently detects likely hardcoded credentials and high-entropy secret
candidates, dynamic shell use, `shell=True`, `eval`/`exec`, unsafe
pickle/YAML deserialization, dynamically constructed database queries, and
disabled TLS verification. Pass 2 asks the selected model to review for broken
object-level authorization (including IDOR), privilege escalation, mass
assignment, and race conditions. AI results are **review candidates**, not
confirmed findings or a security guarantee.

## Quick start — no API key required

### Requirements

- Python 3.11 or newer
- [uv](https://docs.astral.sh/uv/)
- An OpenAI API key only if you use Pass 2 or Pass 3

From the repository root:

```bash
uv sync --all-groups
uv run codexlens --help
uv run codexlens scan src
```

The final command runs local Pass 1 only and makes no network request. For a
deterministic, judge-friendly walkthrough of all three UI stages, run:

```bash
uv run codexlens demo
```

`demo` is prominently labelled an **offline recorded replay**. It does not call
OpenAI or modify this repository: it stages an owned ExpenseFlow fixture in a
temporary directory, replays recorded structured responses through the normal
local validation paths, shows the same confirmation prompt, and discards the
temporary file afterward. It is useful for an offline walkthrough, but it is
not a live model scan.

## Run a live AI scan

Choose a text-capable model that your API key can access and that supports the
structured response format used by CodexLens. Set `CODEXLENS_MODEL` once for
your shell, or pass `--model`/`-m` per command; the command-line value wins.
CodexLens accepts the selected non-empty model ID as-is and does not impose a
model-family allowlist.

PowerShell:

```powershell
$env:OPENAI_API_KEY = "your-api-key"
$env:CODEXLENS_MODEL = "your-model-id"
uv run codexlens scan ./my_project
uv run codexlens scan ./my_project --model another-model-id
```

Bash or zsh:

```bash
export OPENAI_API_KEY="your-api-key"
export CODEXLENS_MODEL="your-model-id"
uv run codexlens scan ./my_project
```

Without a selected model, CodexLens intentionally stops after local Pass 1.
With one, it uses the OpenAI Responses API for Pass 2; Pass 3 sends a separate
request only when `--fix` is also supplied. Consult the official OpenAI
[model catalog](https://developers.openai.com/api/docs/models) and
[Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs)
when choosing a model.

> **Before running a live scan:** Code context is sent to OpenAI and API usage
> is charged to your account. CodexLens bounds and line-maps the context and
> applies heuristic redaction for known credentials, sensitive assignments, and
> high-entropy literals, but no redaction approach can guarantee that every
> secret or sensitive detail is removed. Scan only code you are authorized to
> share, and use synthetic or non-sensitive fixtures for demonstrations.

## Review and apply a fix

Add `--fix` to a live scan to request a Pass 3 proposal for completed AI
findings:

```bash
uv run codexlens scan ./my_project --model your-model-id --fix
```

For each eligible candidate, CodexLens generates the displayed unified diff
locally from a complete replacement for one reviewed source unit. Read the
diff and enter `y` only if you want to apply it. `n`, Enter, unavailable input,
or an interrupted prompt all decline the proposal. Declining one proposal can
move on to another eligible candidate; at most one validated patch can be
applied in a single run.

Before an accepted patch reaches disk, CodexLens verifies its response binding,
target scope, syntax, sensitive-content policy, and size. It captures a fresh
file hash and performs an atomic same-directory replacement only if the file
has not changed since review. It never executes model-supplied commands, trusts
a model-supplied path or diff, or writes a file without explicit confirmation.
After a successful patch, rerun the scan and your normal tests before reviewing
another change.

## ExpenseFlow: the reproducible showcase

[`examples/expenseflow/`](examples/expenseflow/README.md) is an owned,
intentionally vulnerable multi-tenant FastAPI service with synthetic data. Its
primary scenario is a manager in one tenant approving another tenant's expense:
a realistic broken-object-authorization / IDOR flaw that a role check alone
does not prevent.

The fixture gives a complete evidence trail:

```bash
cd examples/expenseflow
uv sync --all-groups
uv run pytest tests/test_exploit_proof.py tests/test_hardened_reference.py
```

The first test deliberately passes by proving the vulnerable cross-tenant
approval. The second demonstrates the expected protected behavior. The example
README includes the disposable live `--fix` workflow and its post-patch
regression test. Never deploy or reuse this fixture's authorization code.

For the Build Week recording order and submission checklist, see
[BUILD_WEEK_DEMO_SCRIPT.md](BUILD_WEEK_DEMO_SCRIPT.md). It clearly separates
the no-key replay from a real selected-model demonstration.

## CI, JSON reports, and exit codes

The Rich terminal UI is the default. Use `--format json` for a stable report in
CI or another tool:

```bash
uv run codexlens scan src --format json > codexlens-report.json
```

The report schema is `codexlens.scan.v1`. It includes relative locations,
finding metadata, diagnostics, pass status, and the exit code. It intentionally
omits raw source, raw Responses API output, source-unit bindings, and patch
diffs. Finding text can still describe code-derived behavior, so treat the
report as potentially sensitive.

| Exit code | Meaning |
| --- | --- |
| `0` | The requested scan completed with no confirmed static finding. |
| `1` | The scan completed and found one or more confirmed static findings. |
| `3` | Part of the requested scan or fix could not complete safely; inspect the diagnostic output. |

AI review candidates do not independently fail CI. `--format json` cannot be
combined with `--fix`, because reviewing a patch requires the interactive Rich
diff and explicit confirmation.

The included [GitHub Actions workflow](.github/workflows/ci.yml) installs the
locked dependencies on Python 3.11, runs Ruff and pytest for both projects, and
uploads a static JSON report as an artifact.

## Safety and limitations

- Pass 1 is local; Pass 2 and Pass 3 are opt-in and request `store=False`.
- Static checks and redaction are deliberately narrow heuristics, not complete
  data-loss prevention or vulnerability coverage.
- CodexLens audits Python source files only. Large or incomplete AI context is
  reported as a diagnostic and produces exit code `3` rather than being silently
  treated as a complete review.
- Treat both scanned code and model output as untrusted. Keep human review,
  tests, and normal deployment controls in the loop.
- The project is a CLI designed for Windows, macOS, and Linux shells; the
  examples above show both PowerShell and POSIX environment syntax.

## Development

```bash
uv sync --all-groups
uv run ruff check .
uv run pytest
```

The project is released under the [MIT License](LICENSE).
