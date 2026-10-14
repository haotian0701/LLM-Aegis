"""HTTP behavior, fail-closed routing and conversation state tests."""

from __future__ import annotations

import hmac
import json
from hashlib import sha256
from typing import Any

import httpx
import pytest

from aegis.config import Settings
from aegis.detection import TextFragment
from aegis.main import create_app
from aegis.policy import PolicyEngine
from aegis.semantic import OpenAICompatibleSemanticDetector
from tests.support import (
    HMAC_KEY,
    EmptyNer,
    FakeSemantic,
    MemoryStore,
    RecordingProvider,
    app_for,
    auth,
    payload,
    settings,
)


@pytest.mark.asyncio
async def test_clean_request_selects_cloud_without_calling_mock() -> None:
    store = MemoryStore()
    provider = RecordingProvider()
    semantic = FakeSemantic()
    app = app_for(store, provider, semantic)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload("Hello"))
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "ROUTE_UNAVAILABLE"
    assert len(result.headers["x-aegis-conversation-id"]) == 32
    assert provider.calls == []
    event = store.events[result.headers["x-aegis-request-id"]]
    assert event["policy_action"] == "CLOUD"
    assert event["actual_destination"] == "NONE"
    assert event["semantic_destination"] == "EXTERNAL"
    assert event["semantic_call_status"] == "SUCCEEDED"
    assert event["status"] == "FAILED"
    canonical = json.dumps(
        [{"role": "user", "content": "Hello"}],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    assert event["prompt_hmac"] == hmac.new(HMAC_KEY.encode(), canonical, sha256).hexdigest()
    assert "Hello" not in repr(event)


@pytest.mark.asyncio
async def test_business_secret_upgrades_session_and_routes_to_mock() -> None:
    store = MemoryStore()
    provider = RecordingProvider()
    semantic = FakeSemantic(business_secret=True)
    app = app_for(store, provider, semantic)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/chat/completions",
            headers={**auth(), "X-Aegis-Conversation-Id": "shared"},
            json=payload("Synthetic merger plan"),
        )
        assert first.status_code == 200
        assert first.json()["choices"][0]["message"]["content"] == "fixed test answer"
        second = await client.post(
            "/v1/chat/completions",
            headers={**auth(), "X-Aegis-Conversation-Id": "shared"},
            json=payload("Next turn"),
        )
        semantic.business_secret = False
        other = await client.post(
            "/v1/chat/completions",
            headers={**auth("bob-secret-token"), "X-Aegis-Conversation-Id": "shared"},
            json=payload("Next turn"),
        )
    assert second.status_code == 200
    assert other.status_code == 503
    assert other.json()["error"]["code"] == "ROUTE_UNAVAILABLE"
    assert len(semantic.calls) == 2  # first request and the other principal
    assert len(provider.calls) == 2
    assert store.conversations == {("alice", "shared"): True, ("bob", "shared"): False}
    event = store.events[first.headers["x-aegis-request-id"]]
    assert event["policy_action"] == "LOCAL"
    assert event["actual_destination"] == "MOCK"
    assert event["simulation"] is True
    assert event["detected_categories"] == ["BUSINESS_SECRET"]


@pytest.mark.asyncio
@pytest.mark.parametrize("secret_text", ["api_key=abcdefghijklmnop12345", "password=synthetic123"])
async def test_rule_block_skips_external_detector_and_model(secret_text: str) -> None:
    store = MemoryStore()
    provider = RecordingProvider()
    semantic = FakeSemantic()
    app = app_for(store, provider, semantic)
    body = {
        "model": "aegis-mock",
        "messages": [
            {"role": "system", "content": "Historical context"},
            {"role": "user", "content": secret_text},
        ],
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=body)
    assert result.status_code == 403
    assert result.json()["error"]["code"] == "POLICY_BLOCKED"
    assert semantic.calls == provider.calls == []
    conversation_id = result.headers["x-aegis-conversation-id"]
    assert store.conversations[("alice", conversation_id)] is True
    event = store.events[result.headers["x-aegis-request-id"]]
    assert event["status"] == "BLOCKED"
    assert event["blocked"] is True
    assert event["actual_destination"] == "NONE"
    assert (event["conversation_state_before"], event["conversation_state_after"]) == (
        "NORMAL",
        "SENSITIVE",
    )


@pytest.mark.asyncio
async def test_tool_arguments_are_scanned_and_never_sent_when_blocked() -> None:
    store = MemoryStore()
    semantic = FakeSemantic()
    provider = RecordingProvider()
    app = app_for(store, provider, semantic)
    body = {
        "model": "aegis-mock",
        "messages": [
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "lookup",
                            "arguments": '{"credential":"api_key=abcdefghijklmnop12345"}',
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "done"},
        ],
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=body)
    assert result.status_code == 403
    assert semantic.calls == provider.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("text", "category"),
    [
        ("Contact synthetic@example.org", "EMAIL"),
        ("Account DE89370400440532013000", "IBAN"),
        ("Call +4915112345678", "PHONE"),
        ("Server 192.0.2.10", "IP_ADDRESS"),
    ],
)
async def test_pii_selects_mask_cloud_without_dispatch(text: str, category: str) -> None:
    store = MemoryStore()
    provider = RecordingProvider()
    app = app_for(store, provider, FakeSemantic())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload(text))
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "ROUTE_UNAVAILABLE"
    assert provider.calls == []
    event = store.events[result.headers["x-aegis-request-id"]]
    assert event["policy_action"] == "MASK_CLOUD"
    assert category in event["detected_categories"]


@pytest.mark.asyncio
async def test_business_secret_and_email_choose_local() -> None:
    store = MemoryStore()
    app = app_for(store, RecordingProvider(), FakeSemantic(business_secret=True))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post(
            "/v1/chat/completions", headers=auth(), json=payload("synthetic@example.org")
        )
    assert result.status_code == 200
    event = store.events[result.headers["x-aegis-request-id"]]
    assert event["policy_action"] == "LOCAL"
    assert event["detected_categories"] == ["BUSINESS_SECRET", "EMAIL"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "body", "status", "code"),
    [
        ({}, payload(), 401, "UNAUTHORIZED"),
        (auth("wrong"), payload(), 401, "UNAUTHORIZED"),
        (auth(), {**payload(), "stream": True}, 400, "INVALID_REQUEST"),
        (auth(), {**payload(), "extra": "unscanned"}, 400, "INVALID_REQUEST"),
        ({**auth(), "X-Aegis-Conversation-Id": "bad id"}, payload(), 400, "INVALID_REQUEST"),
    ],
)
async def test_rejected_requests_do_not_create_session_or_call_detectors(
    headers: dict[str, str], body: dict[str, object], status: int, code: str
) -> None:
    store = MemoryStore()
    semantic = FakeSemantic()
    provider = RecordingProvider()
    app = app_for(store, provider, semantic)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=headers, json=body)
    assert result.status_code == status
    assert result.json()["error"]["code"] == code
    assert "x-aegis-request-id" in result.headers
    assert "x-aegis-conversation-id" not in result.headers
    assert not store.conversations
    assert semantic.calls == provider.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [128 * 1024 + 1, 33 * 1024])
async def test_oversized_requests_are_rejected_before_dispatch(size: int) -> None:
    store = MemoryStore()
    semantic = FakeSemantic()
    app = app_for(store, RecordingProvider(), semantic)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload("x" * size))
    assert result.status_code == 413
    assert "x-aegis-conversation-id" not in result.headers
    assert not store.conversations
    assert semantic.calls == []


@pytest.mark.asyncio
async def test_missing_or_failing_semantic_detector_returns_security_error() -> None:
    for semantic in (None, FakeSemantic(failure=TimeoutError("private upstream detail"))):
        store = MemoryStore()
        provider = RecordingProvider()
        app = app_for(store, provider, semantic)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "SECURITY_UNAVAILABLE"
        assert "private upstream detail" not in result.text
        assert provider.calls == []
        event = store.events[result.headers["x-aegis-request-id"]]
        assert event["detection_status"] in {"FAILED", "UNAVAILABLE"}


@pytest.mark.asyncio
async def test_semantic_failure_preserves_local_detection_metadata() -> None:
    store = MemoryStore()
    app = app_for(store, RecordingProvider(), FakeSemantic(failure=TimeoutError()))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post(
            "/v1/chat/completions", headers=auth(), json=payload("synthetic@example.org")
        )
    assert result.status_code == 503
    event = store.events[result.headers["x-aegis-request-id"]]
    assert event["detected_categories"] == ["EMAIL"]
    assert event["semantic_call_status"] == "FAILED"
    assert set(event["detector_durations_ms"]) == {"rules", "ner", "semantic"}


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["strict", "demo"])
async def test_ner_failure_is_conservative(mode: str) -> None:
    store = MemoryStore()
    app = app_for(
        store,
        semantic=FakeSemantic() if mode == "demo" else None,
        mode=mode,
        ner=EmptyNer(RuntimeError()),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
    assert result.status_code == 503
    assert result.json()["error"]["code"] == (
        "LOCAL_UNAVAILABLE" if mode == "strict" else "SECURITY_UNAVAILABLE"
    )


@pytest.mark.asyncio
async def test_strict_blocks_known_key_without_external_detection() -> None:
    store = MemoryStore()
    app = app_for(store, mode="strict")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post(
            "/v1/chat/completions",
            headers=auth(),
            json=payload("api_key=abcdefghijklmnop12345"),
        )
    assert result.status_code == 403
    event = store.events[result.headers["x-aegis-request-id"]]
    assert event["semantic_call_status"] is None
    assert event["policy_action"] == "BLOCK"


@pytest.mark.asyncio
async def test_strict_never_uses_external_semantic_and_fails_local() -> None:
    store = MemoryStore()
    app = app_for(store, mode="strict")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "LOCAL_UNAVAILABLE"
    event = store.events[result.headers["x-aegis-request-id"]]
    assert event["policy_action"] == "LOCAL"
    assert event["semantic_call_status"] is None
    assert event["detection_status"] == "DEGRADED"


@pytest.mark.asyncio
async def test_audit_failure_prevents_external_or_model_call() -> None:
    for failure_field in ("fail_begin", "fail_intent"):
        store = MemoryStore()
        setattr(store, failure_field, True)
        semantic = FakeSemantic()
        provider = RecordingProvider()
        app = app_for(store, provider, semantic)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
        assert semantic.calls == provider.calls == []


@pytest.mark.asyncio
async def test_decision_or_final_audit_failure_never_returns_unlogged_model_answer() -> None:
    for failure_field in ("fail_decision", "fail_finish"):
        store = MemoryStore()
        setattr(store, failure_field, True)
        semantic = FakeSemantic(business_secret=True)
        provider = RecordingProvider()
        app = app_for(store, provider, semantic)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
        assert result.status_code == 503
        assert result.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
        assert len(semantic.calls) == 1
        assert len(provider.calls) == (1 if failure_field == "fail_finish" else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [TimeoutError(), RuntimeError("private error")])
async def test_provider_errors_are_sanitized_and_audited(failure: Exception) -> None:
    store = MemoryStore()
    app = app_for(store, RecordingProvider(failure), FakeSemantic(business_secret=True))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
    assert result.status_code in {502, 504}
    assert "private error" not in result.text
    assert store.events[result.headers["x-aegis-request-id"]]["status"] == "FAILED"


def test_policy_validation_and_configuration_boundaries(tmp_path) -> None:
    invalid = tmp_path / "bad.yaml"
    invalid.write_text("default_action: CLOUD\nrules: []\n", encoding="utf-8")
    with pytest.raises(ValueError):
        PolicyEngine.load(str(invalid))
    with pytest.raises(ValueError):
        Settings.model_validate({**settings().model_dump(), "run_mode": "strict"})
    with pytest.raises(ValueError):
        create_app(
            settings("strict"),
            store=MemoryStore(),
            ner_detector=EmptyNer(),
            semantic_detector=FakeSemantic(),
        )
    with pytest.raises(ValueError):
        Settings.model_validate(
            {
                **settings().model_dump(),
                "semantic_url": "https://semantic.example/v1/chat/completions",
            }
        )
    with pytest.raises(ValueError):
        Settings.model_validate(
            {
                **settings().model_dump(),
                "semantic_url": "http://semantic.example/v1/chat/completions",
                "semantic_api_key": "test",
                "semantic_model": "classifier",
            }
        )


@pytest.mark.asyncio
async def test_concrete_semantic_detector_sends_all_fragments_and_rejects_bad_results() -> None:
    seen: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer fake-cloud-key"
        body = json.loads(request.content)
        seen.append(body)
        items = json.loads(body["messages"][1]["content"])["items"]
        content = json.dumps({"results": [{"id": item["id"], "label": "CLEAR"} for item in items]})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        detector = OpenAICompatibleSemanticDetector(
            url="https://semantic.example/v1/chat/completions",
            api_key="fake-cloud-key",
            model="classifier",
            client=client,
        )
        fragments = [
            TextFragment("a", 0, "messages[0].content", "synthetic first"),
            TextFragment("b", 1, "messages[1].content", "synthetic second"),
        ]
        assert await detector.detect(fragments) == []
    assert len(seen) == 1
    assert [item["text"] for item in json.loads(seen[0]["messages"][1]["content"])["items"]] == [
        "synthetic first",
        "synthetic second",
    ]
