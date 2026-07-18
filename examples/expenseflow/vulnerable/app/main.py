"""Intentionally vulnerable multi-tenant ExpenseFlow FastAPI application.

This source exists solely as an owned CodexLens demonstration fixture. It must
not be deployed or used as authorization guidance.
"""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

app = FastAPI(title="ExpenseFlow demo", version="0.1.0")


@dataclass(frozen=True, slots=True)
class Actor:
    """Synthetic authenticated principal supplied by the demo header."""

    user_id: str
    tenant_id: str
    roles: frozenset[str]


class Expense(BaseModel):
    """A mutable expense record from the in-memory demonstration store."""

    id: str
    tenant_id: str
    employee_id: str
    merchant: str
    amount_cents: int = Field(gt=0)
    status: str = "submitted"
    approved_by: str | None = None


class ExpenseUpdate(BaseModel):
    """Deliberately over-broad update shape for the mass-assignment example."""

    merchant: str | None = None
    amount_cents: int | None = Field(default=None, gt=0)
    status: str | None = None
    approved_by: str | None = None
    tenant_id: str | None = None


DEMO_ACTORS = {
    "manager-acme": Actor("user-acme-manager", "tenant-acme", frozenset({"manager"})),
    "employee-acme": Actor("user-acme-employee", "tenant-acme", frozenset({"employee"})),
    "manager-globex": Actor("user-globex-manager", "tenant-globex", frozenset({"manager"})),
}

INITIAL_EXPENSES = (
    Expense(
        id="exp-acme-001",
        tenant_id="tenant-acme",
        employee_id="user-acme-employee",
        merchant="Metro Supplies",
        amount_cents=12_500,
    ),
    Expense(
        id="exp-globex-001",
        tenant_id="tenant-globex",
        employee_id="user-globex-employee",
        merchant="Northwind Travel",
        amount_cents=98_000,
    ),
)
TENANT_APPROVAL_LIMITS = {"tenant-acme": 500_000, "tenant-globex": 500_000}
EXPENSES: dict[str, Expense] = {}
TENANT_APPROVED_CENTS: dict[str, int] = {}


def reset_demo_data() -> None:
    """Restore deterministic, synthetic data for tests and local demonstrations."""

    EXPENSES.clear()
    EXPENSES.update({expense.id: expense.model_copy(deep=True) for expense in INITIAL_EXPENSES})
    TENANT_APPROVED_CENTS.clear()
    TENANT_APPROVED_CENTS.update({tenant_id: 0 for tenant_id in TENANT_APPROVAL_LIMITS})


reset_demo_data()


def get_current_actor(
    x_demo_user: Annotated[str, Header(alias="X-Demo-User")],
) -> Actor:
    """Resolve one of the synthetic actors from a request header."""

    actor = DEMO_ACTORS.get(x_demo_user)
    if actor is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Use a valid X-Demo-User header.",
        )
    return actor


def require_manager(actor: Actor) -> None:
    """Enforce the role-level rule shared by approval endpoints."""

    if "manager" not in actor.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only managers may approve expenses.",
        )


def get_expense_or_404(expense_id: str) -> Expense:
    """Load an expense without applying a tenant scope."""

    expense = EXPENSES.get(expense_id)
    if expense is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Expense not found.")
    return expense


def get_expense_for_tenant(expense_id: str, tenant_id: str) -> Expense:
    """Load an expense only when it belongs to the authenticated tenant."""

    expense = get_expense_or_404(expense_id)
    if expense.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Expense not found.")
    return expense


@app.post("/expenses/{expense_id}/approve", response_model=Expense)
def approve_expense(
    expense_id: str,
    actor: Annotated[Actor, Depends(get_current_actor)],
) -> Expense:
    """Approve a submitted expense when the caller has the manager role."""

    require_manager(actor)
    expense = get_expense_or_404(expense_id)
    if expense.status != "submitted":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only submitted expenses can be approved.",
        )

    expense.status = "approved"
    expense.approved_by = actor.user_id
    TENANT_APPROVED_CENTS[expense.tenant_id] += expense.amount_cents
    return expense


@app.patch("/expenses/{expense_id}", response_model=Expense)
def update_expense(
    expense_id: str,
    update: ExpenseUpdate,
    actor: Annotated[Actor, Depends(get_current_actor)],
) -> Expense:
    """Update an expense after a tenant and actor-level authorization check."""

    expense = get_expense_for_tenant(expense_id, actor.tenant_id)
    if actor.user_id != expense.employee_id and "manager" not in actor.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You may update only your own expenses.",
        )

    for field_name, value in update.model_dump(exclude_unset=True).items():
        setattr(expense, field_name, value)
    return expense


@app.post("/expenses/{expense_id}/approve-with-budget", response_model=Expense)
def approve_with_budget(
    expense_id: str,
    actor: Annotated[Actor, Depends(get_current_actor)],
) -> Expense:
    """Approve within a tenant budget using an intentionally non-atomic sequence."""

    require_manager(actor)
    expense = get_expense_for_tenant(expense_id, actor.tenant_id)
    if expense.status != "submitted":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only submitted expenses can be approved.",
        )

    approved_cents = TENANT_APPROVED_CENTS[expense.tenant_id]
    approval_limit = TENANT_APPROVAL_LIMITS[expense.tenant_id]
    if approved_cents + expense.amount_cents > approval_limit:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This approval would exceed the tenant budget.",
        )

    expense.status = "approved"
    expense.approved_by = actor.user_id
    TENANT_APPROVED_CENTS[expense.tenant_id] = approved_cents + expense.amount_cents
    return expense
