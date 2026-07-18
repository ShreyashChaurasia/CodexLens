"""Regression test for a patch applied only to the disposable work copy."""

import asyncio
import importlib
import sys
from pathlib import Path

import httpx
import pytest

EXAMPLE_ROOT = Path(__file__).resolve().parents[1]
WORK_ROOT = EXAMPLE_ROOT / "work"


@pytest.mark.security_regression
def test_live_patch_rejects_cross_tenant_approval_without_mutation() -> None:
    if not WORK_ROOT.is_dir():
        pytest.skip("Run scripts/prepare_demo.py before testing the disposable work copy.")

    sys.path.insert(0, str(EXAMPLE_ROOT))
    try:
        importlib.invalidate_caches()
        main = importlib.import_module("work.app.main")
        main.reset_demo_data()

        async def approve_cross_tenant_expense() -> httpx.Response:
            transport = httpx.ASGITransport(app=main.app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.post(
                    "/expenses/exp-globex-001/approve",
                    headers={"X-Demo-User": "manager-acme"},
                )

        response = asyncio.run(approve_cross_tenant_expense())
    finally:
        sys.path.pop(0)

    assert response.status_code in {403, 404}
    assert main.EXPENSES["exp-globex-001"].status == "submitted"
    assert main.EXPENSES["exp-globex-001"].approved_by is None
