"""Connected approvals survive requests and enforce one dispatch in PostgreSQL."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.approval_store import PostgresApprovalStore
from aegis.config import Settings
from aegis.main import create_app
from aegis.models import AuditEvent, PendingApproval
from aegis.store import PostgresRequestStore
from tests.api.test_github_workflow import FakeGithub, FakeInjection, FakeModel, request
from tests.support import EmptyNer, FakeSemantic

TEST_DATABASE_URL = os.getenv("AEGIS_TEST_DATABASE_URL")


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_postgres_approval_identity_expiry_and_once_only() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_async_engine(TEST_DATABASE_URL)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    approvals = PostgresApprovalStore(sessions)
    github = FakeGithub()
    settings = Settings.model_validate(
        {
            "database_url": TEST_DATABASE_URL,
            "api_keys": {"alice": "alice-connected-token", "bob": "bob-connected-token"},
            "hmac_key": "connected-integration-hmac-key-at-least-32-bytes",
            "run_mode": "connected",
            "cloud_base_url": "https://model.example/v1",
            "cloud_api_key": "test-key",
            "semantic_url": "https://classifier.example/v1/chat/completions",
            "semantic_api_key": "test-key",
            "semantic_model": "classifier",
            "github_token": "test-github-token",
            "github_repo": "alice/sandbox",
            "approval_key": Fernet.generate_key().decode(),
            "model_aliases": {"aegis-mock": "test-model"},
        }
    )
    app = create_app(
        settings,
        store=PostgresRequestStore(sessions),
        ner_detector=EmptyNer(),
        semantic_detector=FakeSemantic(),
        agent_model=FakeModel("add_issue_comment"),
        github_mcp=github,
        injection_detector=FakeInjection(),
        approval_store=approvals,
    )
    alice = {"Authorization": "Bearer alice-connected-token"}
    bob = {"Authorization": "Bearer bob-connected-token"}
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            first = await client.post("/v1/workflows/github-issues", headers=alice, json=request())
            assert first.status_code == 202, first.text
            first_id = first.json()["approval_id"]
            async with sessions() as session:
                row = await session.get(PendingApproval, first_id)
                assert row is not None and row.encrypted_arguments is not None
                assert "I will investigate" not in row.encrypted_arguments
                event = await session.get(AuditEvent, row.task_id)
                assert event is not None and event.status == "PENDING_APPROVAL"
            foreign = await client.post(f"/v1/approvals/{first_id}/approve", headers=bob)
            assert foreign.status_code == 409
            denied = await client.post(f"/v1/approvals/{first_id}/deny", headers=alice)
            assert denied.status_code == 200
            assert (
                await client.post(f"/v1/approvals/{first_id}/approve", headers=alice)
            ).status_code == 409
            assert [name for name, _ in github.calls] == ["issue_read"]

            second = await client.post("/v1/workflows/github-issues", headers=alice, json=request())
            assert second.status_code == 202
            second_id = second.json()["approval_id"]
            async with sessions() as session, session.begin():
                row = await session.get(PendingApproval, second_id)
                assert row is not None
                row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
            assert (
                await client.post(f"/v1/approvals/{second_id}/approve", headers=alice)
            ).status_code == 409
            async with sessions() as session:
                row = await session.get(PendingApproval, second_id)
                assert row is not None and row.status == "EXPIRED"
                assert row.encrypted_arguments is None

            third = await client.post("/v1/workflows/github-issues", headers=alice, json=request())
            assert third.status_code == 202
            third_id = third.json()["approval_id"]
            posted = await client.post(f"/v1/approvals/{third_id}/approve", headers=alice)
            assert posted.status_code == 200, posted.text
            assert (
                await client.post(f"/v1/approvals/{third_id}/approve", headers=alice)
            ).status_code == 409
            assert [name for name, _ in github.calls].count("add_issue_comment") == 1
            async with sessions() as session:
                row = await session.get(PendingApproval, third_id)
                assert row is not None and row.status == "SUCCEEDED"
                assert row.encrypted_arguments is None

            github.timeout_comments = True
            fourth = await client.post("/v1/workflows/github-issues", headers=alice, json=request())
            assert fourth.status_code == 202
            fourth_id = fourth.json()["approval_id"]
            uncertain = await client.post(f"/v1/approvals/{fourth_id}/approve", headers=alice)
            assert uncertain.status_code == 504
            assert (
                await client.post(f"/v1/approvals/{fourth_id}/approve", headers=alice)
            ).status_code == 409
            assert [name for name, _ in github.calls].count("add_issue_comment") == 2
            async with sessions() as session:
                row = await session.get(PendingApproval, fourth_id)
                assert row is not None and row.status == "UNKNOWN"
                assert row.encrypted_arguments is None

            fifth = await client.post("/v1/workflows/github-issues", headers=alice, json=request())
            assert fifth.status_code == 202
            fifth_id = fifth.json()["approval_id"]
            await approvals.claim(fifth_id, "alice")
            await approvals.recover()
            async with sessions() as session:
                row = await session.get(PendingApproval, fifth_id)
                assert row is not None and row.status == "DISPATCHING"
            await approvals.finish(fifth_id, "UNKNOWN", "TEST_INTERRUPTED")
    finally:
        await engine.dispose()
