"""PostgreSQL audit pagination and principal isolation."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aegis.config import Settings
from aegis.main import DEMO_PRINCIPAL, create_app
from aegis.models import AuditEvent, Conversation
from aegis.store import PostgresRequestStore
from tests.support import EmptyNer


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
