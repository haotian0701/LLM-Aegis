"""Opt-in HTTP and persistence check against the Compose PostgreSQL service."""

from __future__ import annotations

import os
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.config import Settings
from aegis.main import create_app
from aegis.models import AuditEvent, Conversation

TEST_DATABASE_URL = os.getenv("AEGIS_TEST_DATABASE_URL")


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_http_request_persists_isolated_conversations_and_audits() -> None:
    assert TEST_DATABASE_URL is not None
    conversation_id = f"integration-{uuid4().hex}"
    settings = Settings(
        database_url=TEST_DATABASE_URL,
        api_keys={"integration-alice": "alice-token", "integration-bob": "bob-token"},
        hmac_key="integration-hmac-key-longer-than-32-bytes",
        run_mode="demo",
        demo_provider="mock",
    )
    app = create_app(settings)
    request_ids: list[str] = []
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            for token in ("alice-token", "bob-token"):
                result = await client.post(
                    "/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "X-Aegis-Conversation-Id": conversation_id,
                    },
                    json={
                        "model": "aegis-mock",
                        "messages": [{"role": "user", "content": "integration secret marker"}],
                    },
                )
                assert result.status_code == 200, result.text
                request_ids.append(result.headers["x-aegis-request-id"])

    engine = create_async_engine(TEST_DATABASE_URL)
    sessions = async_sessionmaker(engine)
    try:
        async with sessions() as session:
            conversations = (
                await session.scalars(
                    select(Conversation).where(Conversation.conversation_id == conversation_id)
                )
            ).all()
            audits = (
                await session.scalars(
                    select(AuditEvent).where(AuditEvent.request_id.in_(request_ids))
                )
            ).all()
            assert {item.principal_id for item in conversations} == {
                "integration-alice",
                "integration-bob",
            }
            assert len(audits) == 2
            assert all(item.status == "SUCCEEDED" for item in audits)
            assert all(item.actual_destination == "MOCK" for item in audits)
            assert all(item.simulation for item in audits)
            assert all(item.prompt_hmac and len(item.prompt_hmac) == 64 for item in audits)
            assert "integration secret marker" not in repr(
                [(item.error_detail, item.prompt_hmac) for item in audits]
            )
    finally:
        await engine.dispose()
