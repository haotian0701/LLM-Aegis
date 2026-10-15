"""Workspace steps persist in order without exposing raw tool arguments."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Literal

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.agent_provider import AgentTurn
from aegis.config import Settings
from aegis.main import create_app
from aegis.models import AuditEvent, AuditStep
from aegis.store import PostgresRequestStore
from tests.support import EmptyNer, FakeSemantic

TEST_DATABASE_URL = os.getenv("AEGIS_TEST_DATABASE_URL")


class AnswerModel:
    name = "integration-answer-model"
    destination = "EXTERNAL"
    simulation = False

    async def next_turn(self, request: Any) -> AgentTurn:
        assert "README.md:1: routing is audited" in request.messages[-1].content
        return AgentTurn(content="Routing is described in README.md:1.")


class ClearScreen:
    async def classify(self, text: str) -> Literal["CLEAR", "INJECTION", "UNCERTAIN"]:
        return "CLEAR"


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_workspace_steps_persist_and_remain_principal_scoped(tmp_path: Path) -> None:
    assert TEST_DATABASE_URL is not None
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "README.md").write_text("routing is audited\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "README.md"], check=True)
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
            cloud_base_url="https://model.example/v1",
            cloud_api_key="model-key",
            semantic_url="https://screen.example/v1/chat/completions",
            semantic_api_key="screen-key",
            semantic_model="screen",
        ),
        store=store,
        ner_detector=EmptyNer(),
        semantic_detector=FakeSemantic(),
        agent_model=AnswerModel(),
        injection_detector=ClearScreen(),
        workspace_root=tmp_path,
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1"
        ) as client:
            token = (await client.get("/workspace/bootstrap")).json()["token"]
            response = await client.post(
                "/v1/workflows/workspace",
                headers={"Authorization": f"Bearer {token}"},
                json={"model": "aegis-mock", "input": "Where is routing?"},
            )
        assert response.status_code == 200, response.text
        task_id = response.json()["task_id"]
        assert await store.get_audit_summary(task_id, "bob") is None
        async with sessions() as session:
            row = await session.get(AuditEvent, task_id)
            assert row is not None and row.task_type == "AGENT"
            steps = (
                await session.scalars(
                    select(AuditStep)
                    .where(AuditStep.task_id == task_id)
                    .order_by(AuditStep.sequence)
                )
            ).all()
            assert [step.sequence for step in steps] == list(range(1, len(steps) + 1))
            assert steps[0].source == "workspace-planner"
            assert any(step.kind == "RETRIEVAL" and step.decision == "INCLUDE" for step in steps)
            assert all("Where is routing?" not in step.input_summary for step in steps)
    finally:
        await engine.dispose()
