"""Browser fixture for the real local file tool workflow."""

from __future__ import annotations

from typing import Literal

import uvicorn

from aegis.agent_provider import AgentTurn, ProposedToolCall
from aegis.main import create_app
from tests.support import EmptyNer, FakeSemantic, MemoryStore, settings


class BrowserAgent:
    name = "browser-project-agent"
    destination = "EXTERNAL"
    simulation = False

    async def next_turn(self, request):  # type: ignore[no-untyped-def]
        user_text = next(message.content for message in request.messages if message.role == "user")
        if user_text == "Read .env":
            return AgentTurn(tool_call=ProposedToolCall("read-1", "read_file", '{"path":".env"}'))
        if not any(message.role == "tool" for message in request.messages):
            return AgentTurn(
                tool_call=ProposedToolCall("search-1", "search_repo", '{"query":"routing"}')
            )
        return AgentTurn(content="Routing is implemented in src/aegis/main.py.")


class BrowserScreen:
    async def classify(self, text: str) -> Literal["CLEAR", "INJECTION", "UNCERTAIN"]:
        return "CLEAR"


config = settings().model_copy(
    update={
        "cloud_base_url": "https://model.example/v1",
        "cloud_api_key": "browser-key",
        "semantic_url": "https://screen.example/v1/chat/completions",
        "semantic_api_key": "browser-key",
        "semantic_model": "screen",
    }
)
app = create_app(
    config,
    store=MemoryStore(),
    semantic_detector=FakeSemantic(),
    ner_detector=EmptyNer(),
    agent_model=BrowserAgent(),
    injection_detector=BrowserScreen(),
)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8767)
