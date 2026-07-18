# CodexLens Build Week Demo Script

Use this as a recording checklist, not as a claim that the offline replay is a
live model run. Replace every bracketed placeholder with real submission
details before publishing.

## Preflight

- [ ] Repository is public with the MIT license, or shared with the event's
  required review addresses.
- [ ] `uv sync --all-groups`, `uv run pytest`, and `uv run ruff check .` pass.
- [ ] The live model account has access to the GPT-5.6 model selected for the
  Build Week recording.
- [ ] `OPENAI_API_KEY` is set locally and never shown in the video.
- [ ] The `examples/expenseflow/work/` copy is freshly prepared.
- [ ] The final Codex `/feedback` session ID for the core build is available.

## Under-three-minute recording outline

### 0:00–0:20 — Problem and product

Say: “Traditional static checks can find obvious dangerous calls, but they do
not reliably understand that an expense belongs to a tenant. CodexLens combines
local checks, model-assisted business-logic review, and a confirmation-gated
fix.”

Show the README architecture diagram or run:

```bash
uv run codexlens demo
```

If using this command, say clearly: “This is an offline recorded replay for
judges; it makes no API request.” Do not present it as the live GPT-5.6 result.

### 0:20–0:45 — Establish the real vulnerable behavior

From `examples/expenseflow/`:

```bash
uv run pytest tests/test_exploit_proof.py tests/test_hardened_reference.py
```

Explain that the first test proves a manager in tenant Acme can approve a
Globex expense, while the hardened reference defines the correct invariant.

### 0:45–1:55 — Live selected-model scan and review

From the repository root, use the actual GPT-5.6 model ID available to the
recording account:

```powershell
uv run python examples/expenseflow/scripts/prepare_demo.py
$env:CODEXLENS_MODEL = "[your GPT-5.6 model ID]"
uv run codexlens scan examples/expenseflow/work/app/main.py --fix
```

Narrate the evidence, not just the label: the route checks that the caller is a
manager, then looks up an attacker-controlled expense ID without limiting it to
the actor's tenant. Point out the AI finding is labeled for human review.

Show the generated Rich diff. State that CodexLens produced the diff locally
from a validated one-source-unit replacement. Review it, then explicitly press
`y`; do not automate this input.

### 1:55–2:20 — Verify the repaired behavior

From `examples/expenseflow/`:

```bash
uv run pytest tests/test_live_patch.py
```

Explain that the request is now denied and the original expense stays
unapproved. Show that `vulnerable/` was not changed; only the ignored disposable
`work/` copy was eligible for the live patch.

### 2:20–2:50 — Engineering and Codex use

Show the JSON CI output or the workflow briefly:

```bash
uv run codexlens scan src --format json
```

Say only what is true for the final project. A safe, accurate framing is:
“I used Codex as an implementation partner to design the constrained patch
workflow, build the owned demo fixture, and add tests for confirmation, stale
source, and JSON reporting. GPT-5.6 performs the live business-logic review and
patch proposal in this recording.”

## Submission copy checklist

- [ ] Choose the Developer Tools category.
- [ ] Include the project description, repository URL, setup commands, and
  supported platform (Python 3.11+ on Windows, macOS, and Linux).
- [ ] Link the public narrated video and keep it below the event time limit.
- [ ] Explain that the no-key `codexlens demo` command is a recorded replay and
  the ExpenseFlow fixture is intentionally vulnerable and non-deployable.
- [ ] Highlight the live GPT-5.6 scan separately from the no-key replay.
- [ ] Add the Codex `/feedback` session ID: `[paste session ID here]`.
