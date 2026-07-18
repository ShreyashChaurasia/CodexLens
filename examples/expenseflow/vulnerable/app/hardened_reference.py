"""Reference behavior for the ExpenseFlow authorization demonstration.

This module is not used by the vulnerable route. It lets the fixture test the
security property that a minimal one-function CodexLens patch should restore.
"""

from vulnerable.app.main import (
    TENANT_APPROVED_CENTS,
    Actor,
    Expense,
    get_expense_for_tenant,
    require_manager,
)


def approve_expense_hardened(expense_id: str, actor: Actor) -> Expense:
    """Approve only an expense belonging to the manager's own tenant."""

    require_manager(actor)
    expense = get_expense_for_tenant(expense_id, actor.tenant_id)
    if expense.status != "submitted":
        raise ValueError("Only submitted expenses can be approved.")

    expense.status = "approved"
    expense.approved_by = actor.user_id
    TENANT_APPROVED_CENTS[expense.tenant_id] += expense.amount_cents
    return expense
