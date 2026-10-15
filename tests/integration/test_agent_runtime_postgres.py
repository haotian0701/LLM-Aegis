"""Durable agent step ordering and principal isolation."""

from __future__ import annotations

import os

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.agent_provider import ATTACK_PROMPT, NORMAL_PROMPT, TIMEOUT_PROMPT
from aegis.config import Settings
from aegis.main import create_app
from aegis.models import AuditEvent, AuditStep
from aegis.store import PostgresRequestStore
from tests.support import EmptyNer

TEST_DATABASE_URL = os.getenv("AEGIS_TEST_DATABASE_URL")


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_agent_steps_persist_without_raw_tool_arguments() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_async_engine(TEST_DATABASE_URL)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    store = PostgresRequestStore(sessions)
    app = create_app(
        Settings(
            database_url=TEST_DATABASE_URL,
            api_keys={"alice": "agent-alice-token", "bob": "agent-bob-token"},
            hmac_key="integration-agent-hmac-key-longer-than-thirty-two-bytes",
            run_mode="demo",
            demo_provider="mock",
        ),
        store=store,
        ner_detector=EmptyNer(),
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            normal = await client.post(
                "/v1/agent/runs",
                headers={"Authorization": "Bearer agent-alice-token"},
                json={"model": "aegis-mock", "input": NORMAL_PROMPT},
            )
            blocked = await client.post(
                "/v1/agent/runs",
                headers={"Authorization": "Bearer agent-alice-token"},
                json={"model": "aegis-mock", "input": ATTACK_PROMPT},
            )
            timeout = await client.post(
                "/v1/agent/runs",
                headers={"Authorization": "Bearer agent-alice-token"},
                json={"model": "aegis-mock", "input": TIMEOUT_PROMPT},
            )
        assert normal.status_code == 200
        assert blocked.status_code == 403
        assert timeout.status_code == 504
        normal_id = normal.json()["task_id"]
        blocked_id = blocked.headers["x-aegis-request-id"]
        assert await store.get_audit_summary(normal_id, "bob") is None
        summary = await store.get_audit_summary(blocked_id, "alice")
        assert summary is not None and summary.steps is not None
        assert summary.status == "BLOCKED"
        assert [step.sequence for step in summary.steps] == list(range(1, len(summary.steps) + 1))
        denied = next(step for step in summary.steps if step.decision == "DENY")
        assert denied.executed is False
        assert denied.actual_destination == "NONE"
        timeout_summary = await store.get_audit_summary(
            timeout.headers["x-aegis-request-id"], "alice"
        )
        assert timeout_summary is not None and timeout_summary.steps is not None
        unknown = next(step for step in timeout_summary.steps if step.kind == "TOOL_CALL")
        assert unknown.execution_status == "UNKNOWN" and unknown.executed is None
        async with sessions() as session:
            row = await session.get(AuditEvent, blocked_id)
            assert row is not None and row.task_type == "AGENT"
            steps = (
                await session.scalars(select(AuditStep).where(AuditStep.task_id == blocked_id))
            ).all()
            assert all("Synthetic operations note" not in step.input_summary for step in steps)
            assert all("Synthetic operations note" not in step.target for step in steps)
    finally:
        await engine.dispose()
