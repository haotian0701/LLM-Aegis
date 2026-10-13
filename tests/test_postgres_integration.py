"""Opt-in stage 2 request and persistence check against PostgreSQL."""

from __future__ import annotations

import json
import os
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.config import Settings
from aegis.detection import Finding, TextFragment
from aegis.main import create_app
from aegis.models import AuditEvent, Conversation
from aegis.semantic import OpenAICompatibleSemanticDetector

TEST_DATABASE_URL = os.getenv("AEGIS_TEST_DATABASE_URL")


class EmptyNer:
    async def detect(self, fragments: list[TextFragment]) -> list[Finding]:
        return []


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_stage_two_decisions_and_audits_persist() -> None:
    assert TEST_DATABASE_URL is not None
    conversation_id = f"integration-{uuid4().hex}"
    blocked_id = f"integration-block-{uuid4().hex}"
    settings = Settings(
        database_url=TEST_DATABASE_URL,
        api_keys={"integration-alice": "alice-token", "integration-bob": "bob-token"},
        hmac_key="integration-hmac-key-longer-than-32-bytes",
        run_mode="demo",
        demo_provider="mock",
    )
    semantic_calls: list[dict[str, object]] = []

    def classify(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        semantic_calls.append(payload)
        items = json.loads(payload["messages"][1]["content"])["items"]
        output = {
            "results": [
                {
                    "id": item["id"],
                    "label": "BUSINESS_SECRET" if "merger" in item["text"] else "CLEAR",
                }
                for item in items
            ]
        }
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(output)}}]})

    request_ids: list[str] = []
    async with httpx.AsyncClient(transport=httpx.MockTransport(classify)) as classifier_client:
        detector = OpenAICompatibleSemanticDetector(
            url="https://semantic.example/v1/chat/completions",
            api_key="synthetic-test-key",
            model="fake-classifier",
            client=classifier_client,
        )
        app = create_app(settings, semantic_detector=detector, ner_detector=EmptyNer())
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                for token, text, expected in (
                    ("alice-token", "synthetic merger plan", 200),
                    ("bob-token", "ordinary request", 503),
                ):
                    result = await client.post(
                        "/v1/chat/completions",
                        headers={
                            "Authorization": f"Bearer {token}",
                            "X-Aegis-Conversation-Id": conversation_id,
                        },
                        json={
                            "model": "aegis-mock",
                            "messages": [{"role": "user", "content": text}],
                        },
                    )
                    assert result.status_code == expected, result.text
                    request_ids.append(result.headers["x-aegis-request-id"])
                blocked = await client.post(
                    "/v1/chat/completions",
                    headers={
                        "Authorization": "Bearer alice-token",
                        "X-Aegis-Conversation-Id": blocked_id,
                    },
                    json={
                        "model": "aegis-mock",
                        "messages": [{"role": "user", "content": "api_key=abcdefghijklmnop12345"}],
                    },
                )
                assert blocked.status_code == 403
                request_ids.append(blocked.headers["x-aegis-request-id"])
    assert len(semantic_calls) == 2

    engine = create_async_engine(TEST_DATABASE_URL)
    sessions = async_sessionmaker(engine)
    try:
        async with sessions() as session:
            conversations = (
                await session.scalars(
                    select(Conversation).where(
                        Conversation.conversation_id.in_([conversation_id, blocked_id])
                    )
                )
            ).all()
            audits = (
                await session.scalars(
                    select(AuditEvent).where(AuditEvent.request_id.in_(request_ids))
                )
            ).all()
            by_principal = {(row.principal_id, row.conversation_id): row for row in conversations}
            assert by_principal[("integration-alice", conversation_id)].sensitive is True
            assert by_principal[("integration-bob", conversation_id)].sensitive is False
            assert by_principal[("integration-alice", blocked_id)].sensitive is True
            assert len(audits) == 3
            by_id = {row.request_id: row for row in audits}
            local, cloud, blocked_audit = (by_id[request_id] for request_id in request_ids)
            assert (local.policy_action, local.actual_destination) == ("LOCAL", "MOCK")
            assert (cloud.policy_action, cloud.actual_destination) == ("CLOUD", "NONE")
            assert (blocked_audit.policy_action, blocked_audit.status) == ("BLOCK", "BLOCKED")
            assert local.semantic_destination == cloud.semantic_destination == "EXTERNAL"
            assert blocked_audit.semantic_destination is None
            assert all(row.prompt_hmac and len(row.prompt_hmac) == 64 for row in audits)
            assert "synthetic merger plan" not in repr(
                [(row.detected_categories, row.error_detail, row.prompt_hmac) for row in audits]
            )
    finally:
        await engine.dispose()
