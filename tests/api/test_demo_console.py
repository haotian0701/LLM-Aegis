"""Demo console read endpoints and signed pagination."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from aegis.main import create_app
from tests.support import EmptyNer, FakeSemantic, MemoryStore, auth, payload, settings


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
