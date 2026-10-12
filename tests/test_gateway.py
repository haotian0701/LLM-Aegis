from __future__ import annotations

import hmac
import json
from hashlib import sha256

import httpx
import pytest

from aegis.config import Settings
from aegis.main import create_app
from aegis.provider import ProviderResult
from aegis.schemas import ChatRequest
from aegis.store import AuditDraft

HMAC_KEY = "test-hmac-key-longer-than-thirty-two-bytes"
DB_URL = "postgresql+psycopg://unused:unused@localhost/unused"


class MemoryStore:
    def __init__(self) -> None:
        self.events: dict[str, dict[str, object]] = {}
        self.conversations: set[tuple[str, str]] = set()
        self.fail_prepare = False
        self.fail_finish = False

    async def record_rejection(self, draft: AuditDraft) -> None:
        self.events[draft.request_id] = vars(draft).copy()

    async def prepare_dispatch(self, draft: AuditDraft) -> None:
        if self.fail_prepare:
            raise RuntimeError("database unavailable")
        assert draft.principal_id is not None
        assert draft.conversation_id is not None
        self.conversations.add((draft.principal_id, draft.conversation_id))
        self.events[draft.request_id] = vars(draft).copy()

    async def finish_dispatch(
        self, request_id: str, *, status: str, error_code: str | None, duration_ms: int
    ) -> None:
        if self.fail_finish:
            raise RuntimeError("database unavailable")
        event = self.events[request_id]
        event.update(status=status, error_code=error_code, total_duration_ms=duration_ms)


class RecordingProvider:
    name = "recording-mock"
    destination = "MOCK"
    simulation = True

    def __init__(self, failure: Exception | None = None) -> None:
        self.calls: list[ChatRequest] = []
        self.failure = failure

    async def complete(self, request: ChatRequest) -> ProviderResult:
        self.calls.append(request)
        if self.failure:
            raise self.failure
        return ProviderResult(content="fixed test answer")


def settings(mode: str = "demo") -> Settings:
    data = {
        "database_url": DB_URL,
        "api_keys": {"alice": "alice-secret-token", "bob": "bob-secret-token"},
        "hmac_key": HMAC_KEY,
        "run_mode": mode,
        "demo_provider": "mock" if mode == "demo" else None,
        "model_aliases": {"aegis-mock": "mock-v1"},
    }
    return Settings.model_validate(data)


def payload(text: str = "Hello") -> dict[str, object]:
    return {"model": "aegis-mock", "messages": [{"role": "user", "content": text}]}


def auth(token: str = "alice-secret-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_demo_response_session_ids_and_keyed_prompt_hash() -> None:
    store = MemoryStore()
    provider = RecordingProvider()
    app = create_app(settings(), store=store, provider=provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        first = await client.post(
            "/v1/chat/completions", headers=auth(), json=payload("private text")
        )
        assert first.status_code == 200
        conversation_id = first.headers["x-aegis-conversation-id"]
        assert len(conversation_id) == 32
        assert first.json()["choices"][0]["message"]["content"] == "fixed test answer"
        assert first.json()["model"] == "aegis-mock"
        assert first.json()["object"] == "chat.completion"
        assert first.json()["id"].endswith(first.headers["x-aegis-request-id"])

        same = await client.post(
            "/v1/chat/completions",
            headers={**auth(), "X-Aegis-Conversation-Id": conversation_id},
            json=payload("next turn"),
        )
        assert same.status_code == 200
        assert same.headers["x-aegis-conversation-id"] == conversation_id
        assert len(provider.calls) == 2

    event = store.events[first.headers["x-aegis-request-id"]]
    assert event["policy_action"] == "LOCAL"
    assert event["actual_destination"] == "MOCK"
    assert event["simulation"] is True
    assert event["status"] == "SUCCEEDED"
    canonical = json.dumps(
        [{"role": "user", "content": "private text"}],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    expected = hmac.new(HMAC_KEY.encode(), canonical, sha256).hexdigest()
    assert event["prompt_hmac"] == expected
    assert "private text" not in repr(event)


@pytest.mark.asyncio
async def test_client_id_is_scoped_to_authenticated_principal() -> None:
    store = MemoryStore()
    app = create_app(settings(), store=store)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for token in ("alice-secret-token", "bob-secret-token"):
            result = await client.post(
                "/v1/chat/completions",
                headers={**auth(token), "X-Aegis-Conversation-Id": "shared-id"},
                json=payload(),
            )
            assert result.status_code == 200
            assert result.headers["x-aegis-conversation-id"] == "shared-id"
    assert store.conversations == {("alice", "shared-id"), ("bob", "shared-id")}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "body", "expected_code"),
    [
        ({}, payload(), "UNAUTHORIZED"),
        (auth("wrong"), payload(), "UNAUTHORIZED"),
        (auth(), {**payload(), "stream": True}, "INVALID_REQUEST"),
        (auth(), {**payload(), "extra": "unscanned"}, "INVALID_REQUEST"),
        (auth(), {**payload(), "temperature": 0}, "UNSUPPORTED_FEATURE"),
        (
            auth(),
            {
                "model": "aegis-mock",
                "messages": [{"role": "user", "content": [{"type": "image_url"}]}],
            },
            "INVALID_REQUEST",
        ),
        ({**auth(), "X-Aegis-Conversation-Id": "bad id"}, payload(), "INVALID_REQUEST"),
    ],
)
async def test_rejected_requests_never_call_provider(
    headers: dict[str, str], body: dict[str, object], expected_code: str
) -> None:
    store = MemoryStore()
    provider = RecordingProvider()
    app = create_app(settings(), store=store, provider=provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=headers, json=body)
    assert result.status_code in (400, 401)
    assert result.json()["error"]["code"] == expected_code
    assert "x-aegis-request-id" in result.headers
    assert "x-aegis-conversation-id" not in result.headers
    assert provider.calls == []
    assert store.events[result.headers["x-aegis-request-id"]]["status"] == "REJECTED"


@pytest.mark.asyncio
async def test_strict_mode_without_local_provider_fails_after_auditing() -> None:
    store = MemoryStore()
    app = create_app(settings("strict"), store=store)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "LOCAL_UNAVAILABLE"
    assert "x-aegis-conversation-id" in result.headers
    event = store.events[result.headers["x-aegis-request-id"]]
    assert event["policy_action"] == "LOCAL"
    assert event["actual_destination"] == "NONE"
    assert event["status"] == "FAILED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        (TimeoutError(), 504, "PROVIDER_TIMEOUT"),
        (RuntimeError("do not expose this exception"), 502, "PROVIDER_ERROR"),
    ],
)
async def test_provider_failures_are_sanitized_and_audited(
    failure: Exception, status: int, code: str
) -> None:
    store = MemoryStore()
    provider = RecordingProvider(failure)
    app = create_app(settings(), store=store, provider=provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
    assert result.status_code == status
    assert result.json()["error"]["code"] == code
    assert "do not expose" not in result.text
    assert store.events[result.headers["x-aegis-request-id"]]["status"] == "FAILED"


@pytest.mark.asyncio
async def test_audit_failure_prevents_model_call() -> None:
    store = MemoryStore()
    store.fail_prepare = True
    provider = RecordingProvider()
    app = create_app(settings(), store=store, provider=provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
    assert provider.calls == []


@pytest.mark.asyncio
async def test_final_audit_failure_returns_error_with_pending_record() -> None:
    store = MemoryStore()
    store.fail_finish = True
    provider = RecordingProvider()
    app = create_app(settings(), store=store, provider=provider)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/chat/completions", headers=auth(), json=payload())
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
    assert len(provider.calls) == 1
    assert store.events[result.headers["x-aegis-request-id"]]["status"] == "PENDING"


def test_configuration_rejects_unsafe_modes_and_duplicate_tokens() -> None:
    with pytest.raises(ValueError):
        Settings.model_validate(
            {**settings().model_dump(), "run_mode": "strict", "demo_provider": "mock"}
        )
    with pytest.raises(ValueError):
        Settings.model_validate(
            {**settings().model_dump(), "api_keys": {"alice": "same", "bob": "same"}}
        )
    with pytest.raises(ValueError):
        create_app(settings("strict"), store=MemoryStore(), provider=RecordingProvider())
