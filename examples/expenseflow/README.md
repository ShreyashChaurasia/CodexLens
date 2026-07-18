# ExpenseFlow demo fixture

ExpenseFlow is an owned, intentionally vulnerable multi-tenant FastAPI service
used to demonstrate CodexLens. It contains only synthetic actors and in-memory
data. **Do not deploy it, connect it to real systems, or reuse its authorization
code as an implementation example.**

Its primary scenario is broken object-level authorization (an IDOR): an Acme
manager has the manager role but can approve a Globex expense because the route
loads an attacker-controlled expense ID without first enforcing the caller's
tenant scope. That distinction makes it a useful business-logic example rather
than a simple pattern-matching exercise.

The route module also contains two secondary, detection-only scenarios:

| Scenario | Why it matters | Demo scope |
| --- | --- | --- |
| Mass assignment | The update model permits protected fields such as `tenant_id`, `status`, and `approved_by`. | Detection only |
| Check-then-act budget approval | A real persistent implementation would need transactional concurrency control. | Detection only |
| Cross-tenant approval / IDOR | A manager can approve another tenant's expense. | Primary live patch and regression demo |

## Safety boundaries

- Run the FastAPI app locally only; do not expose it on a network interface.
- The canonical [`vulnerable/`](vulnerable/) source is deliberately unsafe and
  must remain unchanged.
- For a live patch demo, scan only the ignored, disposable `work/` copy created
  by `scripts/prepare_demo.py`.
- A live CodexLens scan sends source context to OpenAI. Use only this synthetic
  fixture or other code you are authorized to share.
- Re-running `prepare_demo.py` deletes and recreates `work/`, so it discards
  every work-copy edit.

## Install and prove the vulnerability

From this directory:

```bash
uv sync --all-groups
uv run pytest tests/test_exploit_proof.py tests/test_hardened_reference.py
uv run ruff check .
```

`test_exploit_proof.py` is expected to **pass** because it proves the unsafe
behavior: an Acme manager receives `200 OK` while approving the Globex expense.
`test_hardened_reference.py` demonstrates the desired property without editing
the canonical vulnerable source.

To inspect the issue manually, start the app bound to local loopback only:

```bash
uv run uvicorn vulnerable.app.main:app --host 127.0.0.1 --port 8001
```

In a separate terminal, use the command appropriate for your shell.

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

Both requests should succeed before the repair, despite `manager-acme` belonging
to a different tenant. Stop Uvicorn with `Ctrl+C` when finished.

## No-key CodexLens walkthrough

The root project has a separate offline walkthrough:

```bash
cd ../..
uv run codexlens demo
```

It is an **offline recorded replay**, not a scan of this FastAPI fixture. It
makes no OpenAI API request and operates on a temporary, self-discarding owned
example. Use it when you need to demonstrate the Rich UI without credentials;
use the next section for a real API-backed ExpenseFlow scan.

## Live CodexLens patch flow

Start in the repository root. Ensure the root CodexLens environment has already
been installed with `uv sync --all-groups`. Then prepare a fresh disposable
workspace and run the live scan:

```powershell
uv run python examples/expenseflow/scripts/prepare_demo.py
$env:OPENAI_API_KEY = "your-api-key"
$env:CODEXLENS_MODEL = "your-model-id"
uv run codexlens scan examples/expenseflow/work/app/main.py --fix
```

On Bash or zsh, set the same variables with `export` before the final command.
For a Build Week recording, choose a model available to the recording account;
CodexLens itself does not require a specific model family.

Pass 2 can return one or more model-dependent review candidates. For each
eligible Pass 3 proposal, review the locally generated diff rather than
assuming the IDOR finding will appear first. Press `n` for an unrelated or
unsafe proposal. Press `y` only after confirming that the repair narrowly
scopes the expense lookup to the authenticated actor's tenant—for example by
using the existing `get_expense_for_tenant` helper. CodexLens can apply at most
one accepted patch per run.

The preparation script copies `vulnerable/` to the ignored `work/` folder;
therefore a confirmed `y` changes only the disposable copy, never the canonical
fixture.

## Verify an accepted patch

Return to this directory after accepting a suitable patch:

```bash
cd examples/expenseflow
uv run pytest tests/test_live_patch.py
```

This regression is meaningful only after a repair: it expects the cross-tenant
request to return `403` or `404` and verifies that the Globex expense remains
unapproved. Before a repair, it should fail. If `work/` has not been prepared,
pytest skips the test; a skip is not proof that the vulnerability was fixed.

To reset the disposable workspace, return to the repository root and run:

```bash
uv run python examples/expenseflow/scripts/prepare_demo.py
```

## Recording and repository context

See the root [README](../../README.md) for the full pipeline, model/privacy
notes, JSON reporting, and exit codes. The
[Build Week recording script](../../BUILD_WEEK_DEMO_SCRIPT.md) provides the
recommended exploit → live scan → reviewed diff → regression-test narrative.
