"""Simulated LOCAL routing, external audit gates and loopback demo access."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from aegis.config import Settings
from aegis.main import DEMO_PRINCIPAL, create_app
from aegis.policy import Action, Category, PolicyEngine
from aegis.provider import OpenAICompatibleCloudProvider, SimulatedLocalProvider
from tests.support import EmptyNer, FakeSemantic, MemoryStore, auth, payload, settings


def simulated_settings() -> Settings:
    return settings().model_copy(
        update={
            "demo_provider": "simulated_local",
            "cloud_base_url": "https://model.example/v1",
            "cloud_api_key": "test-cloud-key",
            "model_aliases": {"aegis-mock": "upstream-model"},
        }
    )


def model_response(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [
                {"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
            ]
        },
    )


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"demo_provider": "simulated_local"}, "requires cloud configuration"),
        (
            {"demo_provider": "simulated_local", "cloud_base_url": "https://x.example/v1"},
            "configured together",
        ),
        ({"run_mode": "strict", "demo_provider": "simulated_local"}, "strict mode"),
    ],
)
def test_simulated_local_configuration_requires_explicit_demo_and_cloud(
    updates: dict[str, str], expected: str
) -> None:
    with pytest.raises(ValidationError, match=expected):
        Settings.model_validate({**settings().model_dump(), **updates})


def test_simulated_local_is_selected_without_injection() -> None:
    app = create_app(simulated_settings(), store=MemoryStore(), ner_detector=EmptyNer())
    assert isinstance(app.state.provider, SimulatedLocalProvider)
    assert isinstance(app.state.cloud_provider, OpenAICompatibleCloudProvider)
    assert app.state.provider.name != app.state.cloud_provider.name


@pytest.mark.asyncio
async def test_four_routes_and_persistent_local_state_have_truthful_headers_and_audit() -> None:
    outbound: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://model.example/v1/chat/completions"
        assert request.headers["authorization"] == "Bearer test-cloud-key"
        body = json.loads(request.content)
        outbound.append(body)
        return model_response("synthetic answer")

    store = MemoryStore()
    config = simulated_settings()
    semantic = FakeSemantic()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        local = SimulatedLocalProvider(
            base_url=config.cloud_base_url or "",
            api_key=config.cloud_api_key or "",
            model_aliases=config.model_aliases,
            client=upstream,
        )
        cloud = OpenAICompatibleCloudProvider(
            base_url=config.cloud_base_url or "",
            api_key=config.cloud_api_key or "",
            model_aliases=config.model_aliases,
            client=upstream,
        )
        app = create_app(
            config,
            store=store,
            provider=local,
            cloud_provider=cloud,
            semantic_detector=semantic,
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            clear = await client.post("/v1/chat/completions", headers=auth(), json=payload("Hello"))
            masked = await client.post(
                "/v1/chat/completions", headers=auth(), json=payload("demo.user@example.com")
            )
            blocked = await client.post(
                "/v1/chat/completions",
                headers=auth(),
                json=payload("api_key=abcdefghijklmnop12345"),
            )
            local_response = await client.post(
                "/v1/chat/completions",
                headers={
                    **auth(),
                    "X-Aegis-Conversation-Id": blocked.headers["x-aegis-conversation-id"],
                },
                json={**payload("Follow-up without the old text"), "temperature": 0.3},
            )
            later_local = await client.post(
                "/v1/chat/completions",
                headers={
                    **auth(),
                    "X-Aegis-Conversation-Id": blocked.headers["x-aegis-conversation-id"],
                },
                json=payload("Another synthetic follow-up"),
            )

    responses = (clear, masked, blocked, local_response, later_local)
    assert [r.status_code for r in responses] == [200, 200, 403, 200, 200]
    assert [r.headers["x-aegis-policy-action"] for r in responses] == [
        "CLOUD",
        "MASK_CLOUD",
        "BLOCK",
        "LOCAL",
        "LOCAL",
    ]
    assert [r.headers["x-aegis-actual-destination"] for r in responses] == [
        "EXTERNAL",
        "EXTERNAL",
        "NONE",
        "EXTERNAL",
        "EXTERNAL",
    ]
    assert local_response.headers["x-aegis-simulation"] == "true"
    assert clear.headers["x-aegis-simulation"] == "false"
    assert blocked.headers["x-aegis-simulation"] == "false"
    assert len(outbound) == 4
    assert "demo.user@example.com" not in json.dumps(outbound[1])
    assert outbound[2]["messages"] == [
        {"role": "user", "content": "Follow-up without the old text"}
    ]
    assert outbound[2]["temperature"] == 0.3
    assert outbound[3]["messages"] == [{"role": "user", "content": "Another synthetic follow-up"}]
    assert len(semantic.calls) == 2
    audit = store.events[local_response.headers["x-aegis-request-id"]]
    assert (audit["policy_action"], audit["actual_destination"], audit["simulation"]) == (
        "LOCAL",
        "EXTERNAL",
        True,
    )
    assert (audit["provider_name"], audit["provider_model"], audit["model_call_status"]) == (
        "simulated-local-openai-compatible",
        "upstream-model",
        "SUCCEEDED",
    )


@pytest.mark.asyncio
async def test_business_secret_routes_unmasked_to_simulated_local() -> None:
    outbound: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        outbound.append(json.loads(request.content))
        return model_response("answer")

    config = simulated_settings()
    store = MemoryStore()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        local = SimulatedLocalProvider(
            base_url=config.cloud_base_url or "",
            api_key=config.cloud_api_key or "",
            model_aliases=config.model_aliases,
            client=upstream,
        )
        app = create_app(
            config,
            store=store,
            provider=local,
            semantic_detector=FakeSemantic(business_secret=True),
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/chat/completions", headers=auth(), json=payload("fictional internal merger")
            )
    assert response.status_code == 200
    assert response.headers["x-aegis-policy-action"] == "LOCAL"
    assert outbound[0]["messages"][0]["content"] == "fictional internal merger"
    audit = store.events[response.headers["x-aegis-request-id"]]
    assert audit["detected_categories"] == ["BUSINESS_SECRET"]
    assert audit["conversation_state_after"] == "SENSITIVE"


@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_code"),
    [
        ("audit", 503, "AUDIT_UNAVAILABLE"),
        ("timeout", 504, "PROVIDER_TIMEOUT"),
        ("error", 502, "PROVIDER_ERROR"),
    ],
)
@pytest.mark.asyncio
async def test_simulated_local_failure_does_not_fallback(
    failure: str, expected_status: int, expected_code: str
) -> None:
    calls = 0

    def respond(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if failure == "timeout":
            raise httpx.ReadTimeout("synthetic timeout")
        if failure == "error":
            return httpx.Response(200, json={"choices": []})
        return model_response("unexpected")

    config = simulated_settings()
    store = MemoryStore()
    store.fail_model_intent = failure == "audit"
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        local = SimulatedLocalProvider(
            base_url=config.cloud_base_url or "",
            api_key=config.cloud_api_key or "",
            model_aliases=config.model_aliases,
            client=upstream,
        )
        app = create_app(
            config,
            store=store,
            provider=local,
            semantic_detector=FakeSemantic(business_secret=True),
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post(
                "/v1/chat/completions", headers=auth(), json=payload("fictional internal merger")
            )
    assert response.status_code == expected_status
    assert response.json()["error"]["code"] == expected_code
    assert response.headers["x-aegis-policy-action"] == "LOCAL"
    assert response.headers["x-aegis-actual-destination"] == (
        "NONE" if failure == "audit" else "EXTERNAL"
    )
    assert calls == (0 if failure == "audit" else 1)
    audit = store.events[response.headers["x-aegis-request-id"]]
    assert audit["model_call_status"] == (None if failure == "audit" else "FAILED")


class FailingPolicy(PolicyEngine):
    def __init__(self) -> None:
        pass

    def decide(self, categories: Iterable[Category], *, was_sensitive: bool) -> Action:
        raise RuntimeError("synthetic policy failure")


@pytest.mark.parametrize("failure", ["semantic", "ner", "policy"])
@pytest.mark.asyncio
async def test_security_failure_never_dispatches_simulated_local(failure: str) -> None:
    calls = 0

    def respond(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return model_response("unexpected")

    config = simulated_settings()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        local = SimulatedLocalProvider(
            base_url=config.cloud_base_url or "",
            api_key=config.cloud_api_key or "",
            model_aliases=config.model_aliases,
            client=upstream,
        )
        app = create_app(
            config,
            store=MemoryStore(),
            provider=local,
            semantic_detector=FakeSemantic(
                failure=TimeoutError() if failure == "semantic" else None
            ),
            ner_detector=EmptyNer(failure=RuntimeError() if failure == "ner" else None),
            policy=FailingPolicy() if failure == "policy" else None,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.post("/v1/chat/completions", headers=auth(), json=payload())
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "SECURITY_UNAVAILABLE"
    assert "x-aegis-policy-action" not in response.headers
    assert calls == 0


@pytest.mark.asyncio
async def test_demo_page_bootstrap_is_loopback_only_and_token_is_process_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "index.html").write_text(
        '<html lang="en"><title>Decision Console</title></html>', encoding="utf-8"
    )
    monkeypatch.setattr("aegis.main.FRONTEND_DIST", tmp_path)
    config = settings()
    first = create_app(
        config, store=MemoryStore(), semantic_detector=FakeSemantic(), ner_detector=EmptyNer()
    )
    second = create_app(
        config, store=MemoryStore(), semantic_detector=FakeSemantic(), ner_detector=EmptyNer()
    )
    local_transport = httpx.ASGITransport(app=first, client=("127.0.0.1", 1234))
    async with httpx.AsyncClient(transport=local_transport, base_url="http://127.0.0.1") as client:
        page = await client.get("/")
        bootstrap = await client.get("/demo/bootstrap")
        token = bootstrap.json()["token"]
        accepted = await client.post(
            "/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json=payload()
        )
    assert page.status_code == 200
    assert '<html lang="en">' in page.text and "Decision Console" in page.text
    assert "alice-secret-token" not in page.text
    assert bootstrap.status_code == 200
    assert bootstrap.headers["cache-control"] == "no-store"
    assert accepted.status_code == 503
    assert (
        first.state.store.events[accepted.headers["x-aegis-request-id"]]["principal_id"]
        == DEMO_PRINCIPAL
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=second, client=("127.0.0.1", 1234)),
        base_url="http://127.0.0.1",
    ) as client:
        old_token = await client.post(
            "/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json=payload()
        )
    assert old_token.status_code == 401

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=first, client=("192.0.2.10", 1234)),
        base_url="http://127.0.0.1",
    ) as client:
        assert (await client.get("/")).status_code == 404
        assert (await client.get("/demo/bootstrap")).status_code == 404
        remote_token = await client.post(
            "/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json=payload()
        )
        assert remote_token.status_code == 401

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=first, client=("127.0.0.1", 1234)),
        base_url="http://example.invalid",
    ) as client:
        assert (await client.get("/demo/bootstrap")).status_code == 404
        spoofed_host = await client.post(
            "/v1/chat/completions", headers={"Authorization": f"Bearer {token}"}, json=payload()
        )
        assert spoofed_host.status_code == 401

    strict_app = create_app(settings("strict"), store=MemoryStore(), ner_detector=EmptyNer())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=strict_app, client=("127.0.0.1", 1234)),
        base_url="http://127.0.0.1",
    ) as client:
        assert (await client.get("/")).status_code == 404
        assert (await client.get("/demo/bootstrap")).status_code == 404
