"""Model provider boundary. Stage 1 includes only an in-process mock."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from aegis.schemas import ChatRequest


@dataclass(frozen=True)
class ProviderResult:
    content: str


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
