# CodexLens Build Week Roadmap

> Temporary working plan for the OpenAI Build Week submission. Keep this file
> beside the package while we build; move the completed public-facing material
> into the repository root before submission.

## Product promise

CodexLens is a Python security auditor that combines fast local static checks,
AI-assisted reasoning about business logic, and a user-controlled patch flow.
It must demonstrate a real security outcome rather than only a model call:

1. Discover a meaningful vulnerability.
2. Explain the impact with source-grounded evidence.
3. Propose one minimal repair.
4. Show the diff and require an explicit approval before any source file is
   overwritten.
5. Verify that the repaired behavior blocks the exploit.

## Build Week demo story

The primary showcase will be **ExpenseFlow**, an owned, intentionally
vulnerable multi-tenant expense-approval service. It is safe to publish and
reproduce because it contains only synthetic data and is never intended for
deployment.

The recorded flow:

1. Run CodexLens against the vulnerable ExpenseFlow project.
2. Pass 1 reports any conventional issues it can see.
3. Pass 2 identifies a cross-tenant approval / IDOR authorization gap that
   regex-only scanning cannot reliably determine.
4. Run with `--fix`; CodexLens renders a locally generated diff.
5. Accept with `y` in the Rich terminal UI; only then is the file atomically
   replaced.
6. Rerun the targeted test to show that a manager from one tenant can no
   longer approve another tenant's expense.

## Delivery phases

### Phase 1 — Reproducible owned demo

- [x] Add `examples/expenseflow/` with clear "intentionally vulnerable" and
  "do not deploy" notices.
- [x] Include a believable multi-tenant route/service boundary with a focused
  IDOR / broken-access-control flaw.
- [x] Include deterministic tests proving the vulnerable behavior and the
  repaired behavior.
- [x] Keep demo dependencies isolated from the CodexLens package.

### Phase 2 — Evaluation evidence

- [ ] Define a small labeled finding set: IDOR, mass assignment, privilege
  escalation, race condition, and clean controls.
- [x] Record expected finding locations, severity, and rationale for the
  primary owned IDOR replay.
- [x] Add an offline, recorded-response path or fixtures for deterministic
  demos when an API call is unavailable.
- [x] Document human review limits: AI findings and patches are candidates,
  not security guarantees.

### Phase 3 — Developer-tool workflow

- [x] Add machine-readable scan output suitable for CI.
- [x] Document exit codes, model configuration, privacy behavior, and safe
  patching semantics.
- [x] Add an example CI invocation and a no-rebuild way for judges to inspect
  the demo and its expected output.

### Phase 4 — Submission package

- [x] Make the README a judge-ready quick start with install, run, and demo
  commands.
- [x] Add an architecture diagram and threat/safety model.
- [ ] Prepare a public, under-three-minute narrated demo video showing both
  Codex and GPT-5.6 use, as required by the event.
- [ ] Capture the Codex `/feedback` session ID for the core implementation.
- [ ] Ensure repository visibility, license, category, and Devpost materials
  meet the final submission requirements.

## Acceptance checklist for each change

- [x] The default local scan works without an API key.
- [x] API use remains model-neutral and uses a user-selected OpenAI model.
- [x] Source paths and findings are validated locally before display or patch.
- [x] A patch is previewed before mutation and only a confirmed `y` can write.
- [x] New behavior has focused tests and passes Ruff.
- [x] Demo instructions are reproducible from a clean checkout.

## Near-term implementation order

1. Add the remaining labeled evaluation cases and clean controls.
2. Decide an explicit CI policy for failing on reviewed AI findings.
3. Record the live GPT-5.6 demo and capture the Codex `/feedback` session ID.
4. Complete Devpost metadata, repository visibility, and final submission checks.
