# ExpenseFlow: intentionally vulnerable example application

ExpenseFlow is an intentionally vulnerable FastAPI example included with
CodexLens. It demonstrates the kind of authorization bug the scanner is meant
to help developers review. Every actor and record is fake and stored in
memory. Run it locally only. Do not deploy it, connect it to real systems, or
reuse its authorization code as a reference.

The main scenario is broken object-level authorization (IDOR): an Acme manager
has the right role but can approve a Globex expense because the route accepts an
attacker-controlled expense ID without checking the manager's tenant. Finding
that requires following the actor, the requested object, and the tenant
relationship—not just matching a risky API call.

## What this example covers

| Step | Expected result |
| --- | --- |
| Baseline exploit proof | The test passes by showing that an Acme manager receives `200 OK` while approving a Globex expense. |
| Live accepted patch | It changes only the disposable `work/` copy, never `vulnerable/`. |
| Post-patch regression | Cross-tenant approval returns `403` or `404`, and the target expense stays unapproved. |

## The intentional flaws

| Scenario | Why it matters | Example scope |
| --- | --- | --- |
| Cross-tenant approval / IDOR | A manager can approve another tenant's expense. | Primary live-patch and regression scenario |
| Mass assignment | The update model allows protected fields such as `tenant_id`, `status`, and `approved_by`. | Detection only |
| Check-then-act budget approval | A real persistent implementation would need transactional concurrency control. | Detection only |

## Keep this example local

- `vulnerable/` is the canonical unsafe source. It should stay unchanged.
- `scripts/prepare_demo.py` creates the ignored, disposable `work/` copy. Only
  that copy is a valid live `--fix` target.
- Running the preparation script again deletes and recreates `work/`, so it
  discards any prior work-copy edits.
- A live CodexLens scan sends source context to OpenAI. This fixture is
  synthetic and intended for this example.
- Keep `OPENAI_API_KEY` out of logs, screenshots, and shell history.

## Set up the example and prove the bug

ExpenseFlow has its own `uv` project and requires Python 3.11 or newer. From
`examples/expenseflow/`:

```bash
uv sync --all-groups
uv run python --version
uv run pytest -vv tests/test_exploit_proof.py tests/test_hardened_reference.py
uv run ruff check .
```

`test_exploit_proof.py` is supposed to pass because it proves the vulnerable
route works. `test_hardened_reference.py` records the desired behavior without
changing the unsafe source.

For a manual reproduction, start the service on the local loopback interface:

```bash
uv run uvicorn vulnerable.app.main:app --host 127.0.0.1 --port 8001
```

In a second terminal, send the cross-tenant approval request.

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

Before a repair, both commands report a successful approval even though
`manager-acme` belongs to a different tenant. Press `Ctrl+C` to stop the local
server.

## Run a live review

Run these commands from the repository root after installing the main
CodexLens dependencies. First do a live scan without `--fix` to confirm that
the selected model works with your API account. Then recreate the disposable
copy before requesting a patch.

PowerShell:

```powershell
uv run python examples/expenseflow/scripts/prepare_demo.py
$env:OPENAI_API_KEY = "<api-key>"
$env:CODEXLENS_MODEL = "<model-id>"

# Review only: no patch request is made.
uv run codexlens scan examples/expenseflow/work/app/main.py

# Start with a clean disposable copy before requesting a patch.
uv run python examples/expenseflow/scripts/prepare_demo.py
uv run codexlens scan examples/expenseflow/work/app/main.py --fix
```

Bash or zsh:

```bash
uv run python examples/expenseflow/scripts/prepare_demo.py
export OPENAI_API_KEY="<api-key>"
export CODEXLENS_MODEL="<model-id>"

# Review only: no patch request is made.
uv run codexlens scan examples/expenseflow/work/app/main.py

# Start with a clean disposable copy before requesting a patch.
uv run python examples/expenseflow/scripts/prepare_demo.py
uv run codexlens scan examples/expenseflow/work/app/main.py --fix
```

Use a model your account can access that supports the structured response
format required by CodexLens. Pass 2 findings may vary by model, so inspect the
reasoning and evidence before asking for a fix.

When a Pass 3 proposal appears, inspect the diff. Typing `y` writes it;
typing `n`, pressing Enter, or closing the prompt leaves the file alone. An
accepted patch can change only `work/app/main.py` and CodexLens applies at most
one patch in a scan. `vulnerable/` remains the baseline for the example.

## Verify an accepted patch

After accepting a suitable patch, return to `examples/expenseflow/` and run:

```bash
uv run pytest -vv tests/test_live_patch.py
```

The regression passes only when cross-tenant approval is denied and the
Globex expense remains unchanged. It fails before a repair. If there is no
prepared `work/` directory, it skips; a skipped test is not proof that the
demo has been fixed.

To reset the disposable workspace from the repository root:

```bash
uv run python examples/expenseflow/scripts/prepare_demo.py
```

## Next steps

The root [README](../../README.md) covers installation, the three-pass
pipeline, live-model configuration, JSON reports, and exit codes.
