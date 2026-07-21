# CodexLens

```text
 ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗██╗     ███████╗███╗   ██╗███████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝██║     ██╔════╝████╗  ██║██╔════╝
██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ ██║     █████╗  ██╔██╗ ██║███████╗
██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ ██║     ██╔══╝  ██║╚██╗██║╚════██║
╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗███████╗███████╗██║ ╚████║███████╗
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
```

> Security review for business-logic bugs.

[PyPI](https://pypi.org/project/codexlens/) · [GitHub Releases](https://github.com/ShreyashChaurasia/CodexLens/releases) · [Changelog](CHANGELOG.md)

I built CodexLens because static scanners are good at finding known patterns,
but they often miss how authorization, state changes, and business rules fit
together. CodexLens is a Python CLI that starts with fast local checks, can
optionally ask an OpenAI model to review business logic, and shows every
proposed fix as a diff before it touches a file.

Nothing is overwritten automatically. CodexLens applies a patch only if you
explicitly type `y` at the terminal.

> **Important:** CodexLens is a security-review tool, not a security guarantee.
> Static findings and AI findings still need normal engineering review, tests,
> and deployment controls.

## Install

CodexLens requires Python 3.11 or newer.

### From PyPI

```bash
python -m pip install --upgrade codexlens
codexlens --version
codexlens --help
```

`codexlens --version` displays the CodexLens banner followed by the installed
version number.

If you use [uv](https://docs.astral.sh/uv/), the equivalent is:

```bash
uv tool install codexlens
codexlens --version
codexlens --help
```

### From source

```bash
git clone https://github.com/ShreyashChaurasia/CodexLens.git
cd CodexLens
uv sync --all-groups
uv run codexlens --version
```

## Start with a local scan

```bash
codexlens scan ./my_project
```

With no model configured, this runs Pass 1 only. It stays local and makes no
OpenAI request.

## How the scan works

| Pass | What happens | What you get |
| --- | --- | --- |
| 1. Static analysis | CodexLens walks Python files and uses regex, entropy checks, and AST analysis. | Confirmed findings, review candidates, and diagnostics. |
| 2. AI deep review | An optional OpenAI Responses API call reviews bounded source units such as functions, classes, and routes. | Structured business-logic findings that still need human review. |
| 3. Patch review | An optional second request is made only after a completed AI review and only with `--fix`. | A locally generated diff and an explicit approve-or-decline decision. |

The local pass looks for likely hardcoded credentials, high-entropy secret
candidates, dangerous shell construction, `shell=True`, `eval`/`exec`, unsafe
pickle or YAML deserialization, dynamic database queries, and disabled TLS
verification.

The AI pass is aimed at problems that need more context: broken object-level
authorization (including IDOR), privilege escalation, mass assignment, and
race conditions. Treat those results as leads for review, not automatic proof
of a vulnerability.

## Run a live AI review

Choose a model your OpenAI API account can access and that supports the
structured response format used by CodexLens. The project does not hard-code a
model family or keep a client-side allowlist.

PowerShell:

```powershell
$env:OPENAI_API_KEY = "<api-key>"
codexlens scan ./my_project --model "model-id"
```

Bash or zsh:

```bash
export OPENAI_API_KEY="<api-key>"
codexlens scan ./my_project --model "model-id"
```

You can also set `CODEXLENS_MODEL` once for your shell:

```powershell
$env:CODEXLENS_MODEL = "model-id"
codexlens scan ./my_project
```

An explicit `--model` (or `-m`) always wins over `CODEXLENS_MODEL`. If neither
is set, CodexLens intentionally stops after the local pass. Model availability
and structured-output support can be checked in OpenAI's
[model catalog](https://developers.openai.com/api/docs/models) and
[Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs).

Live scans send bounded source context to OpenAI and API usage is billed to the
configured account. CodexLens sets `store=False` and redacts known credentials,
sensitive assignments, and high-entropy literals where it can. Those are
helpful safeguards, not a promise that every sensitive detail is removed, so
only scan code you are authorized to share.

## Review a proposed patch

```bash
codexlens scan ./my_project --model "model-id" --fix
```

Pass 3 is deliberately narrow:

- It considers only findings from a completed AI review that are bound to a
  reviewed Python source unit.
- CodexLens builds the unified diff locally and validates the target, source
  binding, replacement scope, syntax, sensitive-content policy, and size
  before showing it.
- `y` is the only response that writes a patch. `n`, Enter, unavailable input,
  and an interrupted prompt all decline it.
- Just before writing, CodexLens checks the file hash again and uses an atomic
  same-directory replacement. One scan can apply at most one accepted patch.

After accepting a change, run the scan again and run the project's tests.
CodexLens never runs model-provided commands and does not trust
model-provided paths or diffs.

`--format json` cannot be combined with `--fix` because patch review needs the
interactive Rich terminal UI and an explicit confirmation.

## ExpenseFlow example

[ExpenseFlow](examples/expenseflow/README.md) is an intentionally vulnerable
FastAPI example included with this project. Its main scenario is a manager in
one tenant approving an expense from another tenant: an IDOR / broken
object-level authorization flaw that a role check alone does not prevent.

From a source checkout:

```bash
cd examples/expenseflow
uv sync --all-groups
uv run pytest -vv tests/test_exploit_proof.py tests/test_hardened_reference.py
```

The exploit-proof test passes by demonstrating the bug. The hardened-reference
test records the behavior a real fix should preserve. The example README
includes the disposable live-patch workflow and regression test. Do not deploy
the fixture or reuse it as authorization guidance.

## CI and JSON reports

Use JSON output when a CI job or another tool needs the scan result:

```bash
codexlens scan src --format json > codexlens-report.json
```

The report stays local only when `--model` is not supplied and
`CODEXLENS_MODEL` is unset. The schema is `codexlens.scan.v1`. Reports contain
relative locations, finding metadata, diagnostics, pass status, and the exit
code, but leave out raw source, raw API responses, source-unit bindings, and
patch diffs. Finding descriptions can still contain code-derived information,
so handle reports as potentially sensitive.

| Exit code | Meaning |
| --- | --- |
| `0` | The scan completed with no confirmed static finding. |
| `1` | The scan completed with one or more confirmed static findings. |
| `3` | A requested scan or patch workflow did not complete safely; inspect the diagnostic. |

AI review candidates do not independently fail CI. The included
[GitHub Actions workflow](.github/workflows/ci.yml) runs Ruff and pytest for
both projects on Python 3.11, then uploads the static JSON report as an
artifact.

## Development

```bash
uv sync --all-groups
uv run ruff check .
uv run pytest
```

## Scope and security notes

- CodexLens audits Python source files.
- Pass 1 is local. Pass 2 and Pass 3 are opt-in and use `store=False`.
- Static detection and redaction are heuristics; neither provides complete
  vulnerability coverage or data-loss prevention.
- Scanned code and model output are untrusted input. Keep human review, tests,
  and normal deployment controls in the loop.
- The CLI is intended to work from Windows, macOS, and Linux shells.

## Project links

- [PyPI package](https://pypi.org/project/codexlens/)
- [GitHub Releases](https://github.com/ShreyashChaurasia/CodexLens/releases)
- [Security policy](SECURITY.md)
- [MIT License](LICENSE)
