"""Cloud dispatch, masking and audit gates through the public ASGI endpoint."""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

import httpx
import pytest

from aegis.config import Settings
from aegis.detection import Finding, RuleDetector, TextFragment
from aegis.main import create_app
from aegis.policy import Category
from aegis.provider import OpenAICompatibleCloudProvider
from tests.support import (
    EmptyNer,
    FakeSemantic,
    MemoryStore,
    RecordingProvider,
    auth,
    payload,
    settings,
)


def cloud(client: httpx.AsyncClient) -> OpenAICompatibleCloudProvider:
    return OpenAICompatibleCloudProvider(
        base_url="https://cloud.example/v1",
        api_key="private-cloud-test-key",
        model_aliases={"aegis-mock": "upstream-model"},
        client=client,
    )


def completion(content: str, reason: str = "stop") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {"message": {"role": "assistant", "content": content}, "finish_reason": reason}
            ]
        },
    )


@pytest.mark.asyncio
async def test_clear_content_reaches_cloud_with_server_model_and_generation_parameters() -> None:
    outbound: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://cloud.example/v1/chat/completions"
        assert request.headers["Authorization"] == "Bearer private-cloud-test-key"
        outbound.append(json.loads(request.content))
        return completion("cloud answer", "length")

    store = MemoryStore()
    local = RecordingProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        gateway_settings = settings().model_copy(
            update={"model_aliases": {"aegis-mock": "upstream-model"}}
        )
        app = create_app(
            gateway_settings,
            store=store,
            provider=local,
            cloud_provider=cloud(upstream),
            semantic_detector=FakeSemantic(),
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            body = {**payload("Hello"), "temperature": 0, "top_p": 0.9, "max_tokens": 100}
            result = await client.post("/v1/chat/completions", headers=auth(), json=body)
    assert result.status_code == 200
    assert result.json()["model"] == "aegis-mock"
    assert result.json()["choices"][0]["finish_reason"] == "length"
    assert outbound == [
        {
            "model": "upstream-model",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False,
            "temperature": 0.0,
            "top_p": 0.9,
            "max_tokens": 100,
        }
    ]
    assert local.calls == []
    event = store.events[result.headers["x-aegis-request-id"]]
    assert (event["policy_action"], event["actual_destination"]) == ("CLOUD", "EXTERNAL")
    assert (event["model_call_status"], event["masked"]) == ("SUCCEEDED", False)
    assert event["provider_model"] == "upstream-model"


@pytest.mark.asyncio
async def test_masked_history_and_tool_arguments_reach_cloud_as_placeholders() -> None:
    email = "synthetic@example.org"
    seen: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        outbound = json.dumps(body)
        assert email not in outbound
        token = re.search(r"\[\[AEGIS_[A-F0-9]{24}_EMAIL_001\]\]", outbound)
        assert token is not None
        assert outbound.count(token.group()) == 3
        args = body["messages"][1]["tool_calls"][0]["function"]["arguments"]
        assert json.loads(args) == {"recipient": token.group()}
        return completion(f"Send to {token.group()}")

    request = {
        "model": "aegis-mock",
        "messages": [
            {"role": "user", "content": f"Write to {email} and {email}"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "lookup",
                            "arguments": json.dumps({"recipient": email}),
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "Found a record"},
        ],
    }
    store = MemoryStore()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        app = create_app(
            settings(),
            store=store,
            cloud_provider=cloud(upstream),
            semantic_detector=FakeSemantic(),
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post("/v1/chat/completions", headers=auth(), json=request)
    assert result.status_code == 200, result.text
    assert result.json()["choices"][0]["message"]["content"] == f"Send to {email}"
    assert len(seen) == 1
    event = store.events[result.headers["x-aegis-request-id"]]
    assert (event["policy_action"], event["masking_status"]) == ("MASK_CLOUD", "SUCCEEDED")
    assert (event["model_call_status"], event["masked"]) == ("SUCCEEDED", True)
    assert event["masked_messages"] is None
    assert email not in repr(event)


@pytest.mark.asyncio
async def test_forwarded_metadata_is_scanned_and_masked() -> None:
    email = "synthetic@example.org"
    seen: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return completion("done")

    body = {
        "model": "aegis-mock",
        "messages": [
            {"role": "user", "content": "Hello", "name": email},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": email,
                        "type": "function",
                        "function": {"name": "lookup", "arguments": "{}"},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": email, "content": "done"},
        ],
    }
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        app = create_app(
            settings(),
            store=MemoryStore(),
            cloud_provider=cloud(upstream),
            semantic_detector=FakeSemantic(),
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post("/v1/chat/completions", headers=auth(), json=body)
    assert result.status_code == 200, result.text
    assert email not in json.dumps(seen)
    messages = seen[0]["messages"]
    token = messages[0]["name"]
    assert token.startswith("[[AEGIS_")
    assert messages[1]["tool_calls"][0]["id"] == token
    assert messages[2]["tool_call_id"] == token


class IncompleteRuleDetector(RuleDetector):
    def detect(self, fragments: list[TextFragment]) -> list[Finding]:
        fragment = fragments[0]
        return [
            Finding(
                Category.EMAIL,
                "test",
                fragment.text_id,
                fragment.message_index,
                fragment.path,
                0,
                len("a@b.com"),
                1.0,
                "test",
            )
        ]


@pytest.mark.asyncio
async def test_masking_failure_and_audit_intent_failure_never_call_cloud() -> None:
    calls = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return completion("unexpected")

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        store = MemoryStore()
        app = create_app(
            settings(),
            store=store,
            cloud_provider=cloud(upstream),
            rule_detector=IncompleteRuleDetector(),
            semantic_detector=FakeSemantic(),
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            failed = await client.post(
                "/v1/chat/completions", headers=auth(), json=payload("a@b.com and a@b.com")
            )
        assert failed.status_code == 503
        assert failed.json()["error"]["code"] == "SECURITY_UNAVAILABLE"
        event = store.events[failed.headers["x-aegis-request-id"]]
        assert event["policy_action"] == "MASK_CLOUD"
        assert event["masking_status"] == "FAILED"
        assert event["actual_destination"] == "NONE"

        store = MemoryStore()
        store.fail_model_intent = True
        app = create_app(
            settings(),
            store=store,
            cloud_provider=cloud(upstream),
            semantic_detector=FakeSemantic(),
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            audit_failed = await client.post(
                "/v1/chat/completions", headers=auth(), json=payload("Hello")
            )
        assert audit_failed.status_code == 503
        assert audit_failed.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
        assert calls == 0


@pytest.mark.asyncio
async def test_provider_timeout_invalid_response_and_restore_failure_are_audited() -> None:
    for behavior, expected_status, expected_code, model_status in (
        ("timeout", 504, "PROVIDER_TIMEOUT", "FAILED"),
        ("invalid", 502, "PROVIDER_ERROR", "FAILED"),
        ("restore", 503, "SECURITY_UNAVAILABLE", "SUCCEEDED"),
    ):

        def respond(request: httpx.Request, kind: str = behavior) -> httpx.Response:
            if kind == "timeout":
                raise httpx.ReadTimeout("private detail")
            if kind == "invalid":
                return httpx.Response(200, json={"choices": []})
            token = re.search(r"\[\[AEGIS_[A-F0-9]{24}_EMAIL_001\]\]", request.content.decode())
            assert token is not None
            return completion(token.group().replace("001", "999"))

        store = MemoryStore()
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
            app = create_app(
                settings(),
                store=store,
                cloud_provider=cloud(upstream),
                semantic_detector=FakeSemantic(),
                ner_detector=EmptyNer(),
            )
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                result = await client.post(
                    "/v1/chat/completions",
                    headers=auth(),
                    json=payload("synthetic@example.org"),
                )
        assert result.status_code == expected_status
        assert result.json()["error"]["code"] == expected_code
        event = store.events[result.headers["x-aegis-request-id"]]
        assert event["model_call_status"] == model_status
        assert event["actual_destination"] == "EXTERNAL"
        assert "private detail" not in result.text


@pytest.mark.asyncio
async def test_same_conversation_is_busy_while_cloud_call_is_running() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def respond(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return completion("done")

    store = MemoryStore()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        app = create_app(
            settings(),
            store=store,
            cloud_provider=cloud(upstream),
            semantic_detector=FakeSemantic(),
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            headers = {**auth(), "X-Aegis-Conversation-Id": "cloud-busy"}
            first_task = asyncio.create_task(
                client.post("/v1/chat/completions", headers=headers, json=payload("Hello"))
            )
            try:
                await asyncio.wait_for(entered.wait(), timeout=5)
                busy = await client.post(
                    "/v1/chat/completions", headers=headers, json=payload("Second")
                )
                assert busy.status_code == 409
                assert busy.json()["error"]["code"] == "CONVERSATION_BUSY"
                assert calls == 1
            finally:
                release.set()
            first = await first_task
            assert first.status_code == 200
    assert not store.active


@pytest.mark.asyncio
async def test_local_generation_parameters_are_rejected_after_decision() -> None:
    store = MemoryStore()
    local = RecordingProvider()
    app = create_app(
        settings(),
        store=store,
        provider=local,
        semantic_detector=FakeSemantic(business_secret=True),
        ner_detector=EmptyNer(),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post(
            "/v1/chat/completions", headers=auth(), json={**payload("Hello"), "temperature": 0}
        )
    assert result.status_code == 400
    assert result.json()["error"]["code"] == "UNSUPPORTED_FEATURE"
    assert local.calls == []
    assert store.events[result.headers["x-aegis-request-id"]]["policy_action"] == "LOCAL"


def test_cloud_configuration_validation_and_strict_boundary() -> None:
    with pytest.raises(ValueError):
        Settings.model_validate(
            {**settings().model_dump(), "cloud_base_url": "https://cloud.example/v1"}
        )
    with pytest.raises(ValueError):
        Settings.model_validate(
            {
                **settings().model_dump(),
                "cloud_base_url": "http://cloud.example/v1",
                "cloud_api_key": "secret",
            }
        )
    with pytest.raises(ValueError):
        Settings.model_validate(
            {
                **settings("strict").model_dump(),
                "cloud_base_url": "https://cloud.example/v1",
                "cloud_api_key": "secret",
            }
        )
