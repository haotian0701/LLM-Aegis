"""Injection classifier transport contracts."""

from __future__ import annotations

import json

import httpx
import pytest

from aegis.injection import OpenAICompatibleIssueDetector


@pytest.mark.asyncio
async def test_openrouter_injection_request_requires_structured_verdict() -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["response_format"]["type"] == "json_schema"
        assert body["response_format"]["json_schema"]["strict"] is True
        assert body["provider"]["require_parameters"] is True
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"label":"CLEAR"}'}}]},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        detector = OpenAICompatibleIssueDetector(
            "https://openrouter.ai/api/v1/chat/completions", "test-key", "test-model", client
        )
        assert await detector.classify("synthetic source text") == "CLEAR"
