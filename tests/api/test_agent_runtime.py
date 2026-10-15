"""Runtime boundaries and demo-only agent execution."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from aegis.agent_provider import (
    ATTACK_PROMPT,
    NORMAL_PROMPT,
    TIMEOUT_PROMPT,
    OpenAICompatibleAgentModel,
)
from aegis.main import create_app
from aegis.runtime_policy import SyntheticDocument, SyntheticTools
from tests.support import EmptyNer, FakeSemantic, MemoryStore, auth, payload, settings


def request(input_text: str, engine: str = "fixture") -> dict[str, str]:
    return {"model": "aegis-mock", "input": input_text, "engine": engine}


@pytest.mark.asyncio
async def test_fixture_retrieval_scopes_documents_and_records_ordered_steps() -> None:
    store = MemoryStore()
    tools = SyntheticTools()
    app = create_app(settings(), store=store, ner_detector=EmptyNer(), agent_tools=tools)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/agent/runs", headers=auth(), json=request(NORMAL_PROMPT))
    assert result.status_code == 200
    assert result.json()["sources"][0]["document_id"] == "alice-launch"
    assert "Wednesday" in result.json()["answer"]
    assert tools.search_calls == 1
    audit = await store.get_audit_summary(result.json()["task_id"], "alice")
    assert audit is not None
    assert audit.task_type == "AGENT"
    assert audit.steps is not None
    assert [step.sequence for step in audit.steps] == list(range(1, len(audit.steps) + 1))
    assert any(step.kind == "RETRIEVAL" and step.decision == "EXCLUDE" for step in audit.steps)
    assert any(step.kind == "RETRIEVAL" and step.decision == "INCLUDE" for step in audit.steps)
    assert "Alice's synthetic" not in repr(audit)


@pytest.mark.asyncio
async def test_fixture_injection_is_denied_before_email_adapter() -> None:
    store = MemoryStore()
    tools = SyntheticTools()
    app = create_app(settings(), store=store, ner_detector=EmptyNer(), agent_tools=tools)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post(
            "/v1/agent/runs",
            headers=auth(),
            json=request(ATTACK_PROMPT),
        )
    assert result.status_code == 403
    assert result.json()["error"]["code"] == "TOOL_DENIED"
    assert tools.email_calls == 0
    audit = await store.get_audit_summary(result.headers["x-aegis-request-id"], "alice")
    assert audit is not None and audit.steps is not None
    denied = [step for step in audit.steps if step.kind == "TOOL_CALL" and step.decision == "DENY"]
    assert len(denied) == 1
    assert denied[0].executed is False
    assert denied[0].matched_rules == ["write_tool_disabled"]


@pytest.mark.asyncio
async def test_audit_failure_and_timeout_do_not_retry_tools() -> None:
    store = MemoryStore()
    store.fail_intent = True
    tools = SyntheticTools()
    app = create_app(settings(), store=store, ner_detector=EmptyNer(), agent_tools=tools)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        denied = await client.post("/v1/agent/runs", headers=auth(), json=request(NORMAL_PROMPT))
    assert denied.status_code == 503
    assert denied.json()["error"]["code"] == "AUDIT_UNAVAILABLE"
    assert tools.search_calls == 0

    store = MemoryStore()
    tools = SyntheticTools()
    app = create_app(settings(), store=store, ner_detector=EmptyNer(), agent_tools=tools)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        timeout = await client.post("/v1/agent/runs", headers=auth(), json=request(TIMEOUT_PROMPT))
    assert timeout.status_code == 504
    assert tools.search_calls == 1
    audit = await store.get_audit_summary(timeout.headers["x-aegis-request-id"], "alice")
    assert audit is not None and audit.steps is not None
    call = next(step for step in audit.steps if step.kind == "TOOL_CALL")
    assert call.execution_status == "UNKNOWN"
    assert call.executed is None


@pytest.mark.asyncio
async def test_agent_claim_blocks_chat_in_same_conversation() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    class PausingTools(SyntheticTools):
        async def search_docs(self, query: str) -> list[SyntheticDocument]:
            entered.set()
            await release.wait()
            return await super().search_docs(query)

    app = create_app(
        settings(), store=MemoryStore(), ner_detector=EmptyNer(), agent_tools=PausingTools()
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        headers = {**auth(), "X-Aegis-Conversation-Id": "agent-shared"}
        first = asyncio.create_task(
            client.post("/v1/agent/runs", headers=headers, json=request(NORMAL_PROMPT))
        )
        await entered.wait()
        busy = await client.post("/v1/chat/completions", headers=headers, json=payload())
        release.set()
        completed = await first
    assert busy.status_code == 409
    assert busy.json()["error"]["code"] == "CONVERSATION_BUSY"
    assert completed.status_code == 200


@pytest.mark.asyncio
async def test_cloud_agent_sends_only_authorized_tool_results() -> None:
    outbound: list[dict[str, object]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        outbound.append(payload)
        if len(outbound) == 1:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "search_docs", "arguments": '{"query":"launch"}'},
                    }
                ],
            }
        else:
            message = {"role": "assistant", "content": "Synthetic launch summary."}
        return httpx.Response(200, json={"choices": [{"message": message}]})

    config = settings()
    config.cloud_base_url = "https://model.example/v1"
    config.cloud_api_key = "test-only-key"
    store = MemoryStore()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        cloud = OpenAICompatibleAgentModel(
            base_url=config.cloud_base_url,
            api_key=config.cloud_api_key,
            model_aliases=config.model_aliases,
            client=upstream,
        )
        app = create_app(
            config,
            store=store,
            ner_detector=EmptyNer(),
            semantic_detector=FakeSemantic(),
            agent_model=cloud,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            result = await client.post(
                "/v1/agent/runs", headers=auth(), json=request("Tell me about launch.", "cloud")
            )
    assert result.status_code == 200
    assert len(outbound) == 2
    messages = outbound[1]["messages"]
    assert isinstance(messages, list)
    tool_message = messages[-1]
    assert isinstance(tool_message, dict)
    content = tool_message["content"]
    assert isinstance(content, str)
    assert "alice-launch" in content
    assert "bob-launch" not in content
    audit = await store.get_audit_summary(result.json()["task_id"], "alice")
    assert audit is not None and audit.steps is not None
    assert sum(step.kind == "MODEL_REQUEST" for step in audit.steps) == 2
    assert all(step.execution_status == "SUCCEEDED" for step in audit.steps)


@pytest.mark.asyncio
async def test_cloud_agent_masks_model_input_and_rejects_sensitive_tool_arguments() -> None:
    outbound: list[dict[str, object]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        outbound.append(payload)
        if len(outbound) == 1:
            return httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": "Safe reply."}}]},
            )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "bad-args",
                                    "type": "function",
                                    "function": {
                                        "name": "search_docs",
                                        "arguments": '{"query":"api_key=abcdefghijklmnop12345"}',
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
        )

    config = settings()
    config.cloud_base_url = "https://model.example/v1"
    config.cloud_api_key = "test-only-key"
    tools = SyntheticTools()
    store = MemoryStore()
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as upstream:
        cloud = OpenAICompatibleAgentModel(
            base_url=config.cloud_base_url,
            api_key=config.cloud_api_key,
            model_aliases=config.model_aliases,
            client=upstream,
        )
        app = create_app(
            config,
            store=store,
            ner_detector=EmptyNer(),
            semantic_detector=FakeSemantic(),
            agent_model=cloud,
            agent_tools=tools,
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            masked = await client.post(
                "/v1/agent/runs",
                headers=auth(),
                json=request("Please greet demo.user@example.com.", "cloud"),
            )
            denied = await client.post(
                "/v1/agent/runs",
                headers=auth(),
                json=request("Search the synthetic launch docs.", "cloud"),
            )
    assert masked.status_code == 200
    assert "demo.user@example.com" not in json.dumps(outbound[0])
    assert "[[AEGIS_" in json.dumps(outbound[0])
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "TOOL_DENIED"
    assert tools.search_calls == 0
    audit = await store.get_audit_summary(denied.headers["x-aegis-request-id"], "alice")
    assert audit is not None and audit.steps is not None
    call = next(step for step in audit.steps if step.kind == "TOOL_CALL")
    assert call.matched_rules == ["protected_data_in_tool_arguments"]
    assert call.executed is False


@pytest.mark.asyncio
async def test_cloud_agent_requires_configured_model_and_classifier() -> None:
    store = MemoryStore()
    app = create_app(
        settings(), store=store, ner_detector=EmptyNer(), semantic_detector=FakeSemantic()
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        missing_model = await client.post(
            "/v1/agent/runs", headers=auth(), json=request("Synthetic task.", "cloud")
        )
    assert missing_model.status_code == 503
    assert missing_model.json()["error"]["code"] == "ROUTE_UNAVAILABLE"
    assert store.steps[missing_model.headers["x-aegis-request-id"]][-1]["executed"] is False

    store = MemoryStore()
    config = settings()
    config.cloud_base_url = "https://model.example/v1"
    config.cloud_api_key = "test-only-key"
    app = create_app(config, store=store, ner_detector=EmptyNer())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        missing_classifier = await client.post(
            "/v1/agent/runs", headers=auth(), json=request("Synthetic task.", "cloud")
        )
    assert missing_classifier.status_code == 503
    assert missing_classifier.json()["error"]["code"] == "SECURITY_UNAVAILABLE"


@pytest.mark.asyncio
async def test_agent_endpoint_is_absent_in_strict_mode() -> None:
    app = create_app(settings("strict"), store=MemoryStore(), ner_detector=EmptyNer())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        result = await client.post("/v1/agent/runs", headers=auth(), json=request(NORMAL_PROMPT))
    assert result.status_code == 404
