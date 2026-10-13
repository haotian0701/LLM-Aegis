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
from aegis.provider import OpenAICompatibleCloudProvider, SimulatedLocalProvider
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


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_stage_four_cloud_masking_and_sensitive_state_persist() -> None:
    assert TEST_DATABASE_URL is not None
    conversation_id = f"integration-cloud-{uuid4().hex}"
    settings = Settings(
        database_url=TEST_DATABASE_URL,
        api_keys={"integration-cloud": "cloud-client-token"},
        hmac_key="integration-cloud-hmac-key-longer-than-32-bytes",
        run_mode="demo",
        demo_provider="mock",
        model_aliases={"aegis-cloud": "upstream-model"},
    )
    classifier_texts: list[str] = []
    cloud_bodies: list[dict[str, object]] = []

    def classify(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        items = json.loads(payload["messages"][1]["content"])["items"]
        classifier_texts.extend(item["text"] for item in items)
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

    def complete(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        cloud_bodies.append(payload)
        content = payload["messages"][-1]["content"]
        return httpx.Response(
            200,
            json={
                "choices": [
                    {"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
                ]
            },
        )

    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(classify)) as classifier_client,
        httpx.AsyncClient(transport=httpx.MockTransport(complete)) as cloud_client,
    ):
        detector = OpenAICompatibleSemanticDetector(
            url="https://semantic.example/v1/chat/completions",
            api_key="semantic-key",
            model="classifier",
            client=classifier_client,
        )
        cloud = OpenAICompatibleCloudProvider(
            base_url="https://cloud.example/v1",
            api_key="cloud-key",
            model_aliases=settings.model_aliases,
            client=cloud_client,
        )
        app = create_app(
            settings, semantic_detector=detector, cloud_provider=cloud, ner_detector=EmptyNer()
        )
        request_ids: list[str] = []
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                for text, expected in (
                    ("Hello", 200),
                    ("synthetic@example.org", 200),
                    ("synthetic merger plan", 200),
                    ("Hello again", 200),
                ):
                    result = await client.post(
                        "/v1/chat/completions",
                        headers={
                            "Authorization": "Bearer cloud-client-token",
                            "X-Aegis-Conversation-Id": conversation_id,
                        },
                        json={
                            "model": "aegis-cloud",
                            "messages": [{"role": "user", "content": text}],
                        },
                    )
                    assert result.status_code == expected, result.text
                    request_ids.append(result.headers["x-aegis-request-id"])
                    if "@" in text:
                        assert result.json()["choices"][0]["message"]["content"] == text

    assert "synthetic@example.org" in classifier_texts
    assert len(cloud_bodies) == 2
    assert "synthetic@example.org" not in json.dumps(cloud_bodies)
    assert "[[AEGIS_" in json.dumps(cloud_bodies[1])
    engine = create_async_engine(TEST_DATABASE_URL)
    sessions = async_sessionmaker(engine)
    try:
        async with sessions() as session:
            conversation = await session.get(Conversation, ("integration-cloud", conversation_id))
            audits = [await session.get(AuditEvent, request_id) for request_id in request_ids]
            assert conversation is not None and conversation.sensitive is True
            assert conversation.active_request_id is None
            assert all(event is not None for event in audits)
            cloud_audit, mask_audit, local_audit, later_audit = audits
            assert cloud_audit is not None
            assert mask_audit is not None
            assert local_audit is not None
            assert later_audit is not None
            assert (cloud_audit.policy_action, cloud_audit.model_call_status) == (
                "CLOUD",
                "SUCCEEDED",
            )
            assert (mask_audit.policy_action, mask_audit.masking_status) == (
                "MASK_CLOUD",
                "SUCCEEDED",
            )
            assert (mask_audit.actual_destination, mask_audit.masked) == ("EXTERNAL", True)
            assert mask_audit.semantic_destination == "EXTERNAL"
            assert (local_audit.policy_action, later_audit.policy_action) == ("LOCAL", "LOCAL")
            assert all("synthetic@example.org" not in repr(event.__dict__) for event in audits)
    finally:
        await engine.dispose()


@pytest.mark.skipif(TEST_DATABASE_URL is None, reason="AEGIS_TEST_DATABASE_URL is not set")
@pytest.mark.asyncio
async def test_stage_five_simulated_local_intent_and_state_persist() -> None:
    assert TEST_DATABASE_URL is not None
    conversation_id = f"integration-simulated-{uuid4().hex}"
    config = Settings(
        database_url=TEST_DATABASE_URL,
        api_keys={"integration-simulated": "simulated-client-token"},
        hmac_key="integration-simulated-hmac-key-longer-than-32-bytes",
        run_mode="demo",
        demo_provider="simulated_local",
        cloud_base_url="https://cloud.example/v1",
        cloud_api_key="synthetic-cloud-key",
        model_aliases={"aegis-demo": "synthetic-upstream-model"},
    )
    outbound: list[dict[str, object]] = []

    def complete(request: httpx.Request) -> httpx.Response:
        outbound.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"role": "assistant", "content": "synthetic answer"},
                        "finish_reason": "stop",
                    }
                ]
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(complete)) as upstream:
        local = SimulatedLocalProvider(
            base_url=config.cloud_base_url or "",
            api_key=config.cloud_api_key or "",
            model_aliases=config.model_aliases,
            client=upstream,
        )
        app = create_app(config, provider=local, ner_detector=EmptyNer())
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                headers = {
                    "Authorization": "Bearer simulated-client-token",
                    "X-Aegis-Conversation-Id": conversation_id,
                }
                blocked = await client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": "aegis-demo",
                        "messages": [{"role": "user", "content": "api_key=abcdefghijklmnop12345"}],
                    },
                )
                assert blocked.status_code == 403
                followup = await client.post(
                    "/v1/chat/completions",
                    headers=headers,
                    json={
                        "model": "aegis-demo",
                        "messages": [{"role": "user", "content": "synthetic follow-up"}],
                    },
                )
                assert followup.status_code == 200
                assert followup.headers["x-aegis-policy-action"] == "LOCAL"
                assert followup.headers["x-aegis-actual-destination"] == "EXTERNAL"
                assert followup.headers["x-aegis-simulation"] == "true"

    assert len(outbound) == 1
    assert outbound[0]["messages"] == [{"role": "user", "content": "synthetic follow-up"}]
    engine = create_async_engine(TEST_DATABASE_URL)
    try:
        async with async_sessionmaker(engine)() as session:
            conversation = await session.get(
                Conversation, ("integration-simulated", conversation_id)
            )
            audit = await session.get(AuditEvent, followup.headers["x-aegis-request-id"])
            assert conversation is not None and conversation.sensitive
            assert conversation.active_request_id is None
            assert audit is not None
            assert (audit.policy_action, audit.actual_destination, audit.simulation) == (
                "LOCAL",
                "EXTERNAL",
                True,
            )
            assert (audit.provider_name, audit.provider_model, audit.model_call_status) == (
                "simulated-local-openai-compatible",
                "synthetic-upstream-model",
                "SUCCEEDED",
            )
            assert "synthetic follow-up" not in repr(audit.__dict__)
    finally:
        await engine.dispose()
