"""Acceptance matrix for policy decisions, actual model payloads, and demo audit details."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from aegis.main import create_app
from aegis.provider import OpenAICompatibleCloudProvider, SimulatedLocalProvider
from tests.support import EmptyNer, FakeSemantic, MemoryStore, auth, payload, settings


@pytest.mark.parametrize(
    ("name", "message", "business_secret", "action", "categories", "sent"),
    [
        ("clear", "Hello, please greet me.", False, "CLOUD", [], "RAW"),
        ("email", "demo.user@example.com", False, "MASK_CLOUD", ["EMAIL"], "MASKED"),
        ("phone", "+14155552671", False, "MASK_CLOUD", ["PHONE"], "MASKED"),
        ("ip", "203.0.113.42", False, "MASK_CLOUD", ["IP_ADDRESS"], "MASKED"),
        ("api_key", "api_key=abcdefghijklmnop12345", False, "BLOCK", ["API_KEY"], "NONE"),
        ("secret", "password=synthetic123", False, "BLOCK", ["SECRET"], "NONE"),
        (
            "priority",
            "demo.user@example.com api_key=abcdefghijklmnop12345",
            False,
            "BLOCK",
            ["API_KEY", "EMAIL"],
            "NONE",
        ),
        (
            "business",
            "fictional internal merger",
            True,
            "LOCAL",
            ["BUSINESS_SECRET"],
            "RAW",
        ),
    ],
)
@pytest.mark.asyncio
async def test_acceptance_matrix_inspects_actual_model_request(
    name: str,
    message: str,
    business_secret: bool,
    action: str,
    categories: list[str],
    sent: str,
) -> None:
    outbound: list[dict[str, Any]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        outbound.append(body)
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {"role": "assistant", "content": body["messages"][0]["content"]},
                        "finish_reason": "stop",
                    }
                ]
            },
        )

    config = settings().model_copy(
        update={
            "demo_provider": "simulated_local",
            "cloud_base_url": "https://model.example/v1",
            "cloud_api_key": "test-cloud-key",
        }
    )
    store = MemoryStore()
    detector = FakeSemantic(business_secret=business_secret)
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        app = create_app(
            config,
            store=store,
            provider=SimulatedLocalProvider(
                base_url=config.cloud_base_url or "",
                api_key=config.cloud_api_key or "",
                model_aliases=config.model_aliases,
                client=upstream,
            ),
            cloud_provider=OpenAICompatibleCloudProvider(
                base_url=config.cloud_base_url or "",
                api_key=config.cloud_api_key or "",
                model_aliases=config.model_aliases,
                client=upstream,
            ),
            semantic_detector=detector,
            ner_detector=EmptyNer(),
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 1234)),
            base_url="http://127.0.0.1",
        ) as client:
            token = (await client.get("/demo/bootstrap")).json()["token"]
            demo_headers = {"Authorization": f"Bearer {token}"}
            response = await client.post(
                "/v1/chat/completions", headers=demo_headers, json=payload(message)
            )
            summary_response = await client.get(
                f"/demo/audit/{response.headers['x-aegis-request-id']}", headers=demo_headers
            )

    assert summary_response.status_code == 200, name
    summary = summary_response.json()
    assert response.headers["x-aegis-policy-action"] == action, name
    assert response.status_code == (403 if action == "BLOCK" else 200), name
    audit = store.events[response.headers["x-aegis-request-id"]]
    assert audit["detected_categories"] == categories, name
    assert audit["policy_action"] == action, name
    assert summary["policy_action"] == action, name
    assert summary["detected_categories"] == categories, name
    assert summary["masking_status"] == audit["masking_status"], name
    assert summary["model_call_status"] == audit["model_call_status"], name
    assert summary["masked_messages"] == (outbound[0]["messages"] if sent == "MASKED" else None), (
        name
    )
    assert "prompt_hmac" not in summary and message not in summary_response.text, name
    assert audit["masking_status"] == ("SUCCEEDED" if sent == "MASKED" else None), name
    assert audit["model_call_status"] == ("SUCCEEDED" if sent != "NONE" else None), name
    assert len(outbound) == (0 if sent == "NONE" else 1), name
    assert len(detector.calls) == (0 if action == "BLOCK" else 1), name
    if sent == "NONE":
        assert response.headers["x-aegis-actual-destination"] == "NONE"
        return

    sent_text = outbound[0]["messages"][0]["content"]
    if sent == "MASKED":
        assert message not in json.dumps(outbound[0]), name
        assert sent_text.startswith("[[AEGIS_") and sent_text.endswith("]]"), name
    else:
        assert sent_text == message, name
    assert response.json()["choices"][0]["message"]["content"] == message, name
    assert response.headers["x-aegis-actual-destination"] == "EXTERNAL"
    assert response.headers["x-aegis-simulation"] == ("true" if action == "LOCAL" else "false")


@pytest.mark.asyncio
async def test_demo_audit_lookup_is_scoped_to_process_token_and_principal() -> None:
    store = MemoryStore()
    app = create_app(
        settings(), store=store, semantic_detector=FakeSemantic(), ner_detector=EmptyNer()
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("127.0.0.1", 1234)),
        base_url="http://127.0.0.1",
    ) as client:
        page = await client.get("/")
        assert "Aegis" in page.text
        token = (await client.get("/demo/bootstrap")).json()["token"]
        demo_headers = {"Authorization": f"Bearer {token}"}
        masked = await client.post(
            "/v1/chat/completions", headers=demo_headers, json=payload("demo.user@example.com")
        )
        masked_id = masked.headers["x-aegis-request-id"]
        audit = await client.get(f"/demo/audit/{masked_id}", headers=demo_headers)
        assert audit.status_code == 200
        # Without a cloud route the decision is still MASK_CLOUD, but no masking is attempted.
        assert audit.json().get("policy_action") == "MASK_CLOUD"
        assert audit.json().get("detected_categories") == ["EMAIL"]
        assert audit.json().get("masking_status") is None
        assert audit.headers["cache-control"] == "no-store"
        assert "prompt_hmac" not in audit.json()
        assert "demo.user@example.com" not in audit.text

        other = await client.post(
            "/v1/chat/completions", headers=auth(), json=payload("api_key=abcdefghijklmnop12345")
        )
        other_id = other.headers["x-aegis-request-id"]
        assert (
            await client.get(f"/demo/audit/{other_id}", headers=demo_headers)
        ).status_code == 404
        assert (await client.get(f"/demo/audit/{masked_id}", headers=auth())).status_code == 401
        assert (
            await client.get(f"/demo/audit/{'a' * 32}", headers=demo_headers)
        ).status_code == 404
        assert (await client.get("/demo/audit/invalid", headers=demo_headers)).status_code == 404

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=("192.0.2.10", 1234)),
        base_url="http://127.0.0.1",
    ) as remote:
        assert (
            await remote.get(f"/demo/audit/{masked_id}", headers=demo_headers)
        ).status_code == 404

    strict_app = create_app(settings("strict"), store=MemoryStore(), ner_detector=EmptyNer())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=strict_app, client=("127.0.0.1", 1234)),
        base_url="http://127.0.0.1",
    ) as strict:
        assert (
            await strict.get(f"/demo/audit/{masked_id}", headers=demo_headers)
        ).status_code == 404
