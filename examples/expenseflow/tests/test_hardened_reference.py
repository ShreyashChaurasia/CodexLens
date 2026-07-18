"""Security property a narrow CodexLens patch is expected to restore."""

import pytest
from fastapi import HTTPException

from vulnerable.app.hardened_reference import approve_expense_hardened
from vulnerable.app.main import DEMO_ACTORS, EXPENSES, reset_demo_data


def test_hardened_reference_rejects_cross_tenant_approval_without_mutation() -> None:
    reset_demo_data()

    with pytest.raises(HTTPException) as rejected:
        approve_expense_hardened("exp-globex-001", DEMO_ACTORS["manager-acme"])

    assert rejected.value.status_code == 404
    assert EXPENSES["exp-globex-001"].status == "submitted"
    assert EXPENSES["exp-globex-001"].approved_by is None
