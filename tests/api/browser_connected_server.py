"""Connected UI fixture with a fake GitHub MCP provider and agent model."""

from __future__ import annotations

import json

import uvicorn

from aegis.agent_provider import AgentTurn, ProposedToolCall
from tests.api.test_github_workflow import FakeApprovals, FakeGithub, connected_app
from tests.support import MemoryStore


class BrowserAgent:
    name = "browser-agent"
    destination = "EXTERNAL"
    simulation = False

    async def next_turn(self, request):  # type: ignore[no-untyped-def]
        user = next(message.content for message in request.messages if message.role == "user")
        if user and "comment" in user.lower():
            return AgentTurn(
                tool_call=ProposedToolCall(
                    "browser-comment",
                    "add_issue_comment",
                    json.dumps(
                        {
                            "owner": "alice",
                            "repo": "sandbox",
                            "issue_number": 4,
                            "body": "I will investigate this bug.",
                        }
                    ),
                )
            )
        return AgentTurn(content="The issue needs investigation.")


memory = MemoryStore()
github = FakeGithub()
app = connected_app(memory, github, BrowserAgent(), FakeApprovals(memory))  # type: ignore[arg-type]

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8766)
