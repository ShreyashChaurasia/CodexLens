# ExpenseFlow: Intentionally Vulnerable Demo Service

ExpenseFlow is a self-contained, intentionally vulnerable multi-tenant FastAPI
service used to evaluate CodexLens. It contains synthetic actors and in-memory
data only. **It must not be deployed, connected to real systems, or reused as
authorization guidance.**

The primary scenario is broken object-level authorization (IDOR): an Acme
manager has the required role but can approve a Globex expense because the
route loads an attacker-controlled expense ID without enforcing the caller's
tenant boundary. Detecting this flaw requires reasoning about the authenticated
actor, requested expense, and tenant relationship rather than matching a simple
insecure-code pattern.

## Expected evaluation outcomes

| Evaluation step | Expected result |
| --- | --- |
| Baseline exploit proof | The test passes by showing an Acme manager receives `200 OK` while approving a Globex expense. |
| Offline CodexLens replay | Requires no API credentials and never changes the repository. |
| Live accepted patch | Changes only the disposable `work/` copy, never `vulnerable/`. |
| Post-patch regression | Cross-tenant approval returns `403` or `404`, and the target expense remains unapproved. |

## Security scenarios

| Scenario | Why it matters | Demo scope |
| --- | --- | --- |
| Cross-tenant approval / IDOR | A manager can approve another tenant's expense. | Primary live-patch and regression scenario |
| Mass assignment | The update model permits protected fields such as `tenant_id`, `status`, and `approved_by`. | Detection only |
| Check-then-act budget approval | A persistent implementation would require transactional concurrency control. | Detection only |

## Safety boundaries

- The FastAPI server is intended for local loopback use only.
- [`vulnerable/`](vulnerable/) is the canonical unsafe source and remains
  unchanged throughout a live-patch demonstration.
- `scripts/prepare_demo.py` creates the ignored, disposable `work/` copy. Only
  that copy is a valid live `--fix` target.
- A live CodexLens scan sends source context to OpenAI; this synthetic fixture
  is suitable for that purpose.
- Re-running `prepare_demo.py` deletes and recreates `work/`, discarding all
  work-copy edits.

## Run the baseline and reproduce the vulnerability

At `examples/expenseflow/`:

```bash
uv sync --all-groups
uv run pytest tests/test_exploit_proof.py tests/test_hardened_reference.py
uv run ruff check .
```

`test_exploit_proof.py` is expected to pass because it demonstrates the defect.
`test_hardened_reference.py` documents the intended behavior without modifying
the vulnerable source.

For manual reproduction, start the server on the local loopback interface:

```bash
uv run uvicorn vulnerable.app.main:app --host 127.0.0.1 --port 8001
```

From a second terminal, submit the cross-tenant approval request with the
applicable shell command.

Bash, zsh, or Git Bash:

```bash
curl -X POST http://127.0.0.1:8001/expenses/exp-globex-001/approve \
  -H "X-Demo-User: manager-acme"
```

Windows PowerShell:

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8001/expenses/exp-globex-001/approve" `
  -Headers @{ "X-Demo-User" = "manager-acme" }
```

Before repair, both requests return a successful approval even though
`manager-acme` belongs to a different tenant. `Ctrl+C` stops the local server.

## Credential-free CodexLens replay

CodexLens includes an offline recorded replay at the repository root:

```bash
cd ../..
uv run codexlens demo
```

The replay enables credential-free review of the Rich terminal workflow. It is
not a scan of this FastAPI service, makes no OpenAI API request, and operates
only on a temporary self-discarding example.

## Live patch evaluation

The following PowerShell sequence prepares a disposable workspace and requests
a live scan. It is run from the repository root after the main CodexLens
environment has been installed with `uv sync --all-groups`.

```powershell
uv run python examples/expenseflow/scripts/prepare_demo.py
$env:OPENAI_API_KEY = "<api-key>"
$env:CODEXLENS_MODEL = "<model-id>"
uv run codexlens scan examples/expenseflow/work/app/main.py --fix
```

Bash or zsh equivalent:

```bash
uv run python examples/expenseflow/scripts/prepare_demo.py
export OPENAI_API_KEY="<api-key>"
export CODEXLENS_MODEL="<model-id>"
uv run codexlens scan examples/expenseflow/work/app/main.py --fix
```

The selected model must be available to the configured OpenAI API account and
support the structured response format required by CodexLens. Pass 2 findings
may vary by model. Each eligible Pass 3 proposal is shown as a locally
generated diff; unrelated or unsafe proposals are declined with `n`.

An accepted repair must scope the expense lookup to the authenticated actor's
tenant, such as by using `get_expense_for_tenant`. CodexLens applies at most one
accepted patch per scan. A confirmed `y` changes only `work/app/main.py`; the
canonical `vulnerable/` service remains unchanged.

## Verify an accepted patch

After a suitable patch has been accepted, return to `examples/expenseflow/` and
run:

```bash
uv run pytest tests/test_live_patch.py
```

The regression verifies that cross-tenant approval is denied and that the
Globex expense remains unapproved. Before a repair it fails. Without a prepared
`work/` directory it skips, which is not evidence of a successful repair.

The disposable workspace is reset from the repository root:

```bash
uv run python examples/expenseflow/scripts/prepare_demo.py
```

## Further documentation

The root [README](../../README.md) describes the full pipeline, data-handling
boundaries, JSON reporting, and exit codes. The
[Build Week recording script](../../BUILD_WEEK_DEMO_SCRIPT.md) documents the
exploit → live scan → reviewed diff → regression-test sequence.
