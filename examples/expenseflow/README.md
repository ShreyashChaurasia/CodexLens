# ExpenseFlow demo fixture

ExpenseFlow is an owned, intentionally vulnerable multi-tenant expense-approval
service used to demonstrate CodexLens. It contains only synthetic users and
data. **Do not deploy it, reuse its authorization code, or connect it to real
systems.**

The primary demo issue is a broken object-level authorization check: a manager
from one tenant can approve an expense belonging to another tenant. It is a
useful CodexLens example because the route has a valid role check, yet lacks the
ownership/tenant check needed to enforce the actual business rule.

Two secondary, detection-only examples are included in the same route module:

- a mass-assignment update route that accepts protected expense fields; and
- a check-then-act budget approval route that needs transactional concurrency
  protection in a real persistent system.

## Run the fixture

From this directory, create the isolated demo environment and validate the
canonical fixture:

```bash
uv sync --all-groups
uv run pytest tests/test_exploit_proof.py tests/test_hardened_reference.py
uv run ruff check .
```

The exploit-proof test deliberately passes by showing the bad behavior. The
hardened-reference test demonstrates the expected security property without
changing the vulnerable source.

To inspect the vulnerable API manually:

```bash
uv run uvicorn vulnerable.app.main:app --port 8001
curl -X POST http://127.0.0.1:8001/expenses/exp-globex-001/approve \
  -H "X-Demo-User: manager-acme"
```

The request succeeds even though `manager-acme` belongs to a different tenant.

## CodexLens live-patch flow

Run these commands from the repository root after setting an OpenAI API key and
a model that your account can access. For the Build Week recording, select the
GPT-5.6 model available to the account; CodexLens itself remains model-neutral.

```powershell
uv run python examples/expenseflow/scripts/prepare_demo.py
$env:OPENAI_API_KEY = "your-api-key"
$env:CODEXLENS_MODEL = "your-gpt-5.6-model-id"
uv run codexlens scan examples/expenseflow/work/app/main.py --fix
```

`prepare_demo.py` creates an ignored `work/` copy, so the canonical vulnerable
fixture stays intact. During `--fix`, CodexLens must show a locally generated
diff and prompt for confirmation. Type `y` only after reviewing the patch. A
correct narrow repair scopes the expense lookup to the authenticated actor's
tenant, typically by using the existing `get_expense_for_tenant` helper.

After accepting the patch, return to this directory and run the security
regression test:

```bash
uv run pytest tests/test_live_patch.py
```

It verifies that the cross-tenant request is denied and that the target expense
remains unapproved. It is expected to fail before a repair is applied. To reset
the live workspace, run `prepare_demo.py` again from the repository root.

## Video sequence

1. Run the exploit-proof test to establish the cross-tenant impact.
2. Prepare `work/` and scan only `work/app/main.py` with CodexLens.
3. Show the Pass 2 finding, Pass 3 diff, and the explicit `y` confirmation.
4. Run `tests/test_live_patch.py` to prove the protected outcome.
5. Point out that the original `vulnerable/` fixture was never overwritten.
