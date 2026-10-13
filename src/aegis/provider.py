"""Model provider boundary and demo-only OpenAI-compatible cloud adapter."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal, Protocol

import httpx

from aegis.schemas import ChatRequest


@dataclass(frozen=True)
class ProviderResult:
    content: str
    finish_reason: Literal["stop", "length"] = "stop"


class ModelProvider(Protocol):
    name: str
    destination: str
    simulation: bool

    async def complete(self, request: ChatRequest) -> ProviderResult: ...


class MockLocalProvider:
    name = "mock-local"
    destination = "MOCK"
    simulation = True

    async def complete(self, request: ChatRequest) -> ProviderResult:
        return ProviderResult(content="Aegis mock response.")


class OpenAICompatibleCloudProvider:
    name = "openai-compatible-cloud"
    destination = "EXTERNAL"
    simulation = False

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model_aliases: dict[str, str],
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.url = f"{base_url.rstrip('/')}/chat/completions"
        self._api_key = api_key
        self._model_aliases = model_aliases
        self._client = client

    async def complete(self, request: ChatRequest) -> ProviderResult:
        payload: dict[str, object] = {
            "model": self._model_aliases[request.model],
            "messages": [message.model_dump(exclude_none=True) for message in request.messages],
            "stream": False,
        }
        for name in ("temperature", "top_p", "max_tokens"):
            value = getattr(request, name)
            if value is not None:
                payload[name] = value
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
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
            envelope = response.json()
            choice = envelope["choices"][0]
            message = choice["message"]
            content = message["content"]
            reason = choice["finish_reason"]
            if message["role"] != "assistant" or not isinstance(content, str):
                raise ValueError("invalid assistant response")
            if reason not in {"stop", "length"}:
                raise ValueError("unsupported finish reason")
            return ProviderResult(content=content, finish_reason=reason)
        except (TimeoutError, httpx.TimeoutException) as exc:
            raise TimeoutError("cloud provider timed out") from exc
        except (httpx.HTTPError, ValueError, TypeError, KeyError, IndexError) as exc:
            raise RuntimeError("cloud provider unavailable or invalid") from exc
