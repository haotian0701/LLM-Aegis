"""Demo console read endpoints and signed pagination."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from test_gateway import EmptyNer, FakeSemantic, MemoryStore, auth, payload, settings

from aegis.config import Settings
from aegis.main import DEMO_PRINCIPAL, create_app
from aegis.models import AuditEvent, Conversation
from aegis.store import PostgresRequestStore


@pytest.mark.asyncio
async def test_api_starts_without_frontend_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("aegis.main.FRONTEND_DIST", tmp_path)
    app = create_app(settings(), store=MemoryStore(), ner_detector=EmptyNer())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 1234)),
        base_url="http://127.0.0.1",
    ) as client:
        page = await client.get("/")
        assert page.status_code == 503
        assert "Aegis frontend build required" in page.text
        assert (await client.get("/healthz")).status_code == 200


@pytest.mark.asyncio
async def test_demo_reads_are_scoped_paginated_and_metadata_only() -> None:
    store = MemoryStore()
    app = create_app(
        settings(), store=store, semantic_detector=FakeSemantic(), ner_detector=EmptyNer()
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 1234)),
        base_url="http://127.0.0.1",
    ) as client:
        home = await client.get("/")
        assert home.status_code in {200, 503}
        assert "Aegis" in home.text and "按请求" not in home.text
        token = (await client.get("/demo/bootstrap")).json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        conversation_id = f"demo-{uuid4().hex}"
        request_ids = []
        for message in ("Hello", "demo.user@example.com", "api_key=abcdefghijklmnop12345"):
            result = await client.post(
                "/v1/chat/completions",
                json=payload(message),
                headers={**headers, "X-Aegis-Conversation-Id": conversation_id},
            )
            request_ids.append(result.headers["x-aegis-request-id"])
        other = await client.post(
            "/v1/chat/completions", json=payload("api_key=otherprincipal12345678"), headers=auth()
        )
        other_id = other.headers["x-aegis-request-id"]

        first = await client.get("/demo/audits", params={"limit": 2}, headers=headers)
        assert first.status_code == 200
        assert len(first.json()["items"]) == 2
        assert first.json()["next_cursor"]
        second = await client.get(
            "/demo/audits",
            params={"limit": 2, "cursor": first.json()["next_cursor"]},
            headers=headers,
        )
        assert second.status_code == 200
        ids = [item["request_id"] for item in first.json()["items"] + second.json()["items"]]
        assert set(ids) == set(request_ids)
        assert other_id not in ids
        assert "prompt_hmac" not in first.text and "demo.user@example.com" not in first.text
        assert all(
            "started_at" in item and "provider_name" in item for item in first.json()["items"]
        )

        blocked = await client.get(
            "/demo/audits", params={"policy_action": "BLOCK", "status": "BLOCKED"}, headers=headers
        )
        assert [item["request_id"] for item in blocked.json()["items"]] == [request_ids[-1]]
        filtered = await client.get(
            "/demo/audits", params={"conversation_id": conversation_id}, headers=headers
        )
        assert len(filtered.json()["items"]) == 3
        assert (
            await client.get(
                "/demo/audits",
                params={"cursor": first.json()["next_cursor"], "policy_action": "BLOCK"},
                headers=headers,
            )
        ).status_code == 400
        assert (
            await client.get("/demo/audits", params={"cursor": "tampered"}, headers=headers)
        ).status_code == 400
        assert (
            await client.get("/demo/audits", params={"limit": 101}, headers=headers)
        ).status_code == 400
        assert (await client.get("/demo/audits")).status_code == 401

        conversation = await client.get(f"/demo/conversations/{conversation_id}", headers=headers)
        assert conversation.status_code == 200
        assert conversation.json()["state"] == "SENSITIVE"
        assert conversation.json()["state_version"] == 1
        assert conversation.json()["active_request"] is False
        detail = await client.get(f"/demo/audit/{request_ids[-1]}", headers=headers)
        assert detail.json()["conversation_state_before"] == "NORMAL"
        assert detail.json()["conversation_state_after"] == "SENSITIVE"
        assert "prompt_hmac" not in detail.text
        assert (await client.get(f"/demo/audit/{other_id}", headers=headers)).status_code == 404

    restarted = create_app(
        settings(), store=store, semantic_detector=FakeSemantic(), ner_detector=EmptyNer()
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=restarted, client=("127.0.0.1", 1234)),
        base_url="http://127.0.0.1",
    ) as client:
        assert (await client.get("/demo/audits", headers=headers)).status_code == 401
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.10", 1234)),
        base_url="http://127.0.0.1",
    ) as remote:
        assert (await remote.get("/demo/audits", headers=headers)).status_code == 404
        assert (
            await remote.get(f"/demo/conversations/{conversation_id}", headers=headers)
        ).status_code == 404
    strict = create_app(settings("strict"), store=MemoryStore(), ner_detector=EmptyNer())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=strict, client=("127.0.0.1", 1234)),
        base_url="http://127.0.0.1",
    ) as client:
        assert (await client.get("/demo/audits", headers=headers)).status_code == 404


@pytest.mark.skipif(not os.getenv("AEGIS_TEST_DATABASE_URL"), reason="PostgreSQL is unavailable")
@pytest.mark.asyncio
async def test_postgres_audit_cursor_and_principal_isolation() -> None:
    url = os.environ["AEGIS_TEST_DATABASE_URL"]
    engine = create_async_engine(url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    conversation_id = f"console-{uuid4().hex}"
    now = datetime.now(UTC)
    own_ids = sorted(uuid4().hex for _ in range(3))
    other_id = uuid4().hex
    try:
        async with sessions() as session, session.begin():
            session.add_all(
                [
                    Conversation(principal_id=DEMO_PRINCIPAL, conversation_id=conversation_id),
                    Conversation(principal_id="another-principal", conversation_id=conversation_id),
                ]
            )
            await session.flush()
            for index, request_id in enumerate(own_ids):
                session.add(
                    AuditEvent(
                        request_id=request_id,
                        principal_id=DEMO_PRINCIPAL,
                        conversation_id=conversation_id,
                        started_at=now,
                        status="BLOCKED" if index == 2 else "SUCCEEDED",
                        policy_action="BLOCK" if index == 2 else "CLOUD",
                        actual_destination="NONE",
                        simulation=False,
                        blocked=index == 2,
                        masked=False,
                        detected_categories=[],
                        detection_status="SUCCEEDED",
                        detector_durations_ms={},
                        prompt_hmac="a" * 64,
                    )
                )
            session.add(
                AuditEvent(
                    request_id=other_id,
                    principal_id="another-principal",
                    conversation_id=conversation_id,
                    started_at=now + timedelta(seconds=4),
                    status="SUCCEEDED",
                    policy_action="CLOUD",
                    actual_destination="NONE",
                    simulation=False,
                    blocked=False,
                    masked=False,
                    detected_categories=[],
                    detection_status="SUCCEEDED",
                    detector_durations_ms={},
                )
            )
        config = Settings(
            database_url=url,
            api_keys={"integration": "integration-token"},
            hmac_key="integration-hmac-key-longer-than-32-bytes",
            run_mode="demo",
            demo_provider="mock",
        )
        app = create_app(config, store=PostgresRequestStore(sessions), ner_detector=EmptyNer())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 1234)),
            base_url="http://127.0.0.1",
        ) as client:
            token = (await client.get("/demo/bootstrap")).json()["token"]
            headers = {"Authorization": f"Bearer {token}"}
            params = {"conversation_id": conversation_id, "limit": 2}
            first = (await client.get("/demo/audits", params=params, headers=headers)).json()
            assert [item["request_id"] for item in first["items"]] == own_ids[::-1][:2]
            second = (
                await client.get(
                    "/demo/audits",
                    params={**params, "cursor": first["next_cursor"]},
                    headers=headers,
                )
            ).json()
            assert [item["request_id"] for item in second["items"]] == [own_ids[0]]
            assert other_id not in [item["request_id"] for item in first["items"]]
            blocked = (
                await client.get(
                    "/demo/audits",
                    params={
                        "conversation_id": conversation_id,
                        "policy_action": "BLOCK",
                        "status": "BLOCKED",
                    },
                    headers=headers,
                )
            ).json()
            assert [item["request_id"] for item in blocked["items"]] == [own_ids[2]]
            assert (
                await client.get(
                    "/demo/audits",
                    params={**params, "cursor": first["next_cursor"], "status": "BLOCKED"},
                    headers=headers,
                )
            ).status_code == 400
            assert (
                await client.get(
                    "/demo/audits",
                    params={**params, "cursor": first["next_cursor"] + "x"},
                    headers=headers,
                )
            ).status_code == 400
            assert "prompt_hmac" not in str(first)
            assert (await client.get(f"/demo/audit/{other_id}", headers=headers)).status_code == 404
            conversation = await client.get(
                f"/demo/conversations/{conversation_id}", headers=headers
            )
            assert conversation.json()["state"] == "NORMAL"
            async with sessions() as session, session.begin():
                stored = await session.get(Conversation, (DEMO_PRINCIPAL, conversation_id))
                assert stored is not None
                stored.closed_at = datetime.now(UTC)
                stored.state_version += 1
            closed = await client.get(f"/demo/conversations/{conversation_id}", headers=headers)
            assert closed.json()["state"] == "CLOSED"
            assert closed.json()["state_version"] == 1
    finally:
        await engine.dispose()
