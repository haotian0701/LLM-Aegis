"""Deterministic local app for browser acceptance checks."""

from __future__ import annotations

import uvicorn

from aegis.main import create_app
from aegis.provider import ProviderResult
from tests.support import EmptyNer, FakeSemantic, MemoryStore, settings


class BrowserModel:
    destination = "EXTERNAL"

    def __init__(self, simulation: bool) -> None:
        self.simulation = simulation
        self.name = "browser-simulated-local" if simulation else "browser-cloud"

    async def complete(self, request):  # type: ignore[no-untyped-def]
        return ProviderResult(content=request.messages[-1].content)


config = settings().model_copy(update={"demo_provider": "simulated_local"})
app = create_app(
    config,
    store=MemoryStore(),
    provider=BrowserModel(True),
    cloud_provider=BrowserModel(False),
    semantic_detector=FakeSemantic(),
    ner_detector=EmptyNer(),
)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)
