"""Offline, recorded replay for the owned CodexLens ExpenseFlow demo."""

import json
import runpy
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any

from rich.console import Console
from rich.panel import Panel

from codexlens.ai_analysis.context import build_source_context
from codexlens.ai_analysis.service import OpenAIResponsesAnalyzer
from codexlens.application import run_scan
from codexlens.auto_fix.models import FixRunResult, PatchProposal, PatchStatus
from codexlens.auto_fix.service import OpenAIResponsesPatchGenerator
from codexlens.auto_fix.workflow import run_fix_workflow
from codexlens.models import ScanConfig, ScanResult
from codexlens.reporting import render_fix_result, render_scan_result

_DEMO_MODEL = "recorded-expenseflow-demo"

_EXPENSEFLOW_SOURCE = '''"""Owned intentionally vulnerable ExpenseFlow fixture."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Actor:
    user_id: str
    tenant_id: str
    roles: frozenset[str]


@dataclass
class Expense:
    id: str
    tenant_id: str
    employee_id: str
    status: str = "submitted"
    approved_by: str | None = None


class ExpenseRepository:
    def __init__(self, expenses: list[Expense]) -> None:
        self._expenses = {expense.id: expense for expense in expenses}

    def get(self, expense_id: str) -> Expense:
        return self._expenses[expense_id]

    def get_for_tenant(self, expense_id: str, tenant_id: str) -> Expense:
        expense = self.get(expense_id)
        if expense.tenant_id != tenant_id:
            raise PermissionError("Expense does not belong to the current tenant.")
        return expense


def require_manager(actor: Actor) -> None:
    if "manager" not in actor.roles:
        raise PermissionError("Only managers may approve expenses.")


def approve_expense(
    expense_id: str,
    current_user: Actor,
    repository: ExpenseRepository,
) -> Expense:
    require_manager(current_user)
    expense = repository.get(expense_id)
    if expense.status != "submitted":
        raise ValueError("Only submitted expenses can be approved.")
    expense.status = "approved"
    expense.approved_by = current_user.user_id
    return expense
'''

_PATCHED_APPROVE_EXPENSE = '''def approve_expense(
    expense_id: str,
    current_user: Actor,
    repository: ExpenseRepository,
) -> Expense:
    require_manager(current_user)
    expense = repository.get_for_tenant(expense_id, current_user.tenant_id)
    if expense.status != "submitted":
        raise ValueError("Only submitted expenses can be approved.")
    expense.status = "approved"
    expense.approved_by = current_user.user_id
    return expense
'''


ConfirmPatch = Callable[[PatchProposal], bool]


@dataclass(frozen=True, slots=True)
class DemoRunResult:
    """Observable outcome from one offline replay, suitable for focused tests."""

    scan: ScanResult
    fix: FixRunResult
    vulnerable_before_patch: bool
    blocked_after_patch: bool | None
    ai_requests: int
    patch_requests: int

    @property
    def exit_code(self) -> int:
        """Return a nonzero code only for an unexpected replay failure."""

        if self.scan.exit_code:
            return self.scan.exit_code
        if self.fix.status in {PatchStatus.FAILED, PatchStatus.REJECTED}:
            return 3
        if self.fix.status is PatchStatus.APPLIED and self.blocked_after_patch is not True:
            return 3
        return 0


def run_offline_demo(console: Console, *, confirm: ConfirmPatch) -> DemoRunResult:
    """Run an owned, no-network replay through the real scan and patch boundaries."""

    console.print(
        Panel(
            "This is an offline recorded replay. No OpenAI API request is made. "
            "It stages only a temporary owned ExpenseFlow fixture and still uses "
            "CodexLens' local Pass 2 and Pass 3 validation paths.",
            title="[bold yellow]OFFLINE RECORDED REPLAY[/bold yellow]",
            border_style="yellow",
        )
    )

    with TemporaryDirectory(prefix="codexlens-expenseflow-") as workspace:
        target = Path(workspace) / "expenseflow.py"
        target.write_text(_EXPENSEFLOW_SOURCE, encoding="utf-8")
        vulnerable_before_patch = not _cross_tenant_approval_is_blocked(target)
        if not vulnerable_before_patch:
            raise RuntimeError(
                "The owned demo fixture did not reproduce its expected vulnerability."
            )

        pass2_responses = _RecordedResponses(_recorded_pass2_output(target))
        analyzer = OpenAIResponsesAnalyzer(
            client_factory=lambda: _RecordedClient(pass2_responses)
        )
        config = ScanConfig(target=target, fix_enabled=True, model=_DEMO_MODEL)
        scan = run_scan(config, ai_analyzer=analyzer)
        render_scan_result(console, scan)

        pass3_responses = _RecordedResponses(_recorded_pass3_output)
        generator = OpenAIResponsesPatchGenerator(
            client_factory=lambda: _RecordedClient(pass3_responses)
        )
        fix = run_fix_workflow(
            config,
            scan.ai,
            generator=generator,
            confirm=confirm,
        )
        render_fix_result(console, fix, target)

        blocked_after_patch: bool | None = None
        if fix.status is PatchStatus.APPLIED:
            blocked_after_patch = _cross_tenant_approval_is_blocked(target)
            if blocked_after_patch:
                console.print(
                    "[green]Verified: the cross-tenant approval is denied and the expense "
                    "remains unchanged.[/green]"
                )
            else:
                console.print(
                    "[red]Verification failed: the temporary fixture still permits "
                    "cross-tenant approval.[/red]"
                )
        elif fix.status is PatchStatus.DECLINED:
            console.print(
                "[yellow]Patch declined: the temporary fixture was discarded unchanged.[/yellow]"
            )

        return DemoRunResult(
            scan=scan,
            fix=fix,
            vulnerable_before_patch=vulnerable_before_patch,
            blocked_after_patch=blocked_after_patch,
            ai_requests=len(pass2_responses.calls),
            patch_requests=len(pass3_responses.calls),
        )


class _RecordedClient:
    """Minimal Responses-client shape used only by the offline replay."""

    def __init__(self, responses: "_RecordedResponses") -> None:
        self.responses = responses


class _RecordedResponses:
    """Return a deterministic structured response without making a network request."""

    def __init__(self, response_builder: Callable[[dict[str, object]], str] | str) -> None:
        self._response_builder = response_builder
        self.calls: list[dict[str, object]] = []

    def create(self, **kwargs: object) -> SimpleNamespace:
        self.calls.append(kwargs)
        if isinstance(self._response_builder, str):
            output_text = self._response_builder
        else:
            output_text = self._response_builder(kwargs)
        return SimpleNamespace(status="completed", output_text=output_text)


def _recorded_pass2_output(target: Path) -> str:
    context = build_source_context(target)
    if context.diagnostics:
        raise RuntimeError("The owned demo fixture could not build a complete source context.")
    unit = next(
        (
            candidate
            for candidate in context.units
            if candidate.kind == "function" and candidate.symbol == "approve_expense"
        ),
        None,
    )
    if unit is None:
        raise RuntimeError("The owned demo fixture no longer contains approve_expense.")

    return json.dumps(
        {
            "schema_version": "codexlens.pass2.v1",
            "status": "complete",
            "summary": (
                "Recorded ExpenseFlow review found one high-confidence object-level "
                "authorization flaw."
            ),
            "findings": [
                {
                    "category": "insecure_direct_object_reference",
                    "severity": "high",
                    "confidence": "high",
                    "title": "Expense approval is not scoped to the manager's tenant",
                    "primary_location": {
                        "unit_id": unit.unit_id,
                        "start_line": unit.start_line,
                        "end_line": unit.end_line,
                    },
                    "evidence": (
                        "The route checks the manager role, then loads a caller-selected expense "
                        "with the unscoped repository.get method before mutating it."
                    ),
                    "attack_preconditions": [
                        "A manager can learn or guess an expense identifier from another tenant."
                    ],
                    "impact": "A manager could approve an expense belonging to another tenant.",
                    "recommendation": (
                        "Use the existing tenant-scoped repository lookup before changing "
                        "approval state."
                    ),
                    "cwe_ids": ["CWE-639"],
                    "related_static_rule_ids": [],
                    "assumptions": [],
                }
            ],
            "coverage": {
                "reviewed_unit_ids": [candidate.unit_id for candidate in context.units],
                "unreviewed_unit_ids": [],
                "limitations": [],
            },
        }
    )


def _recorded_pass3_output(request: dict[str, object]) -> str:
    input_text = request.get("input")
    if not isinstance(input_text, str) or "\n\n" not in input_text:
        raise ValueError("Recorded patch request was unavailable.")
    payload = json.loads(input_text.split("\n\n", maxsplit=1)[1])
    candidate = payload.get("candidate")
    source_unit = payload.get("source_unit")
    if not isinstance(candidate, dict) or not isinstance(source_unit, dict):
        raise ValueError("Recorded patch request had an unexpected shape.")

    candidate_id = candidate.get("candidate_id")
    base_file_sha256 = candidate.get("base_file_sha256")
    source_unit_id = source_unit.get("unit_id")
    source_unit_sha256 = source_unit.get("source_sha256")
    if not all(
        isinstance(value, str)
        for value in (candidate_id, base_file_sha256, source_unit_id, source_unit_sha256)
    ):
        raise ValueError("Recorded patch request had invalid bindings.")

    return json.dumps(
        {
            "schema_version": "codexlens.pass3.v1",
            "status": "proposed",
            "candidate_id": candidate_id,
            "source_unit_id": source_unit_id,
            "source_unit_sha256": source_unit_sha256,
            "base_file_sha256": base_file_sha256,
            "summary": "Scope the approved expense lookup to the current manager tenant.",
            "verification_notes": [
                "Rerun the cross-tenant approval regression check after accepting the patch."
            ],
            "replacement_source": _PATCHED_APPROVE_EXPENSE,
        }
    )


def _cross_tenant_approval_is_blocked(target: Path) -> bool:
    """Execute only the temporary owned fixture and test the authorization invariant."""

    namespace: dict[str, Any] = runpy.run_path(str(target))
    actor = namespace["Actor"](
        user_id="manager-acme",
        tenant_id="tenant-acme",
        roles=frozenset({"manager"}),
    )
    expense = namespace["Expense"](
        id="exp-globex-001",
        tenant_id="tenant-globex",
        employee_id="employee-globex",
    )
    repository = namespace["ExpenseRepository"]([expense])

    try:
        namespace["approve_expense"](expense.id, actor, repository)
    except PermissionError:
        return expense.status == "submitted" and expense.approved_by is None
    return False
