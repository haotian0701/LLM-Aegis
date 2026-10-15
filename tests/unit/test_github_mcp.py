"""The hosted MCP inventory must match the reviewed tool boundary."""

from __future__ import annotations

from typing import Literal

import httpx2
import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ListToolsResult, Tool

from aegis.github_mcp import GithubToolError, RemoteGithubMcp


def inventory() -> ListToolsResult:
    fields = {
        "issue_read": {
            "owner": "string",
            "repo": "string",
            "issue_number": "number",
            "method": "string",
        },
        "search_code": {"query": "string"},
        "get_file_contents": {"owner": "string", "repo": "string", "path": "string"},
        "add_issue_comment": {
            "owner": "string",
            "repo": "string",
            "issue_number": "number",
            "body": "string",
        },
    }
    return ListToolsResult(
        tools=[
            Tool(
                name=name,
                input_schema={
                    "type": "object",
                    "properties": {
                        field: {
                            "type": field_type,
                            **({"enum": ["get", "get_comments"]} if field == "method" else {}),
                        }
                        for field, field_type in properties.items()
                    },
                    "required": list(properties),
                },
            )
            for name, properties in fields.items()
        ]
    )


def test_expected_inventory_is_accepted() -> None:
    RemoteGithubMcp._validate_inventory(inventory())


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "duplicate", "wrong_type", "new_required", "method"]
)
def test_inventory_change_stops_workflow(mutation: str) -> None:
    result = inventory()
    if mutation == "missing":
        result.tools.pop()
    elif mutation == "extra":
        result.tools.append(Tool(name="delete_issue", input_schema={"type": "object"}))
    elif mutation == "duplicate":
        result.tools.append(result.tools[0])
    elif mutation == "wrong_type":
        result.tools[0].input_schema["properties"]["issue_number"]["type"] = "string"
    elif mutation == "new_required":
        result.tools[0].input_schema["required"].append("page")
    else:
        result.tools[0].input_schema["properties"]["method"]["enum"] = ["get"]
    with pytest.raises(GithubToolError):
        RemoteGithubMcp._validate_inventory(result)


@pytest.mark.asyncio
async def test_remote_transport_with_mock_mcp_server(monkeypatch: pytest.MonkeyPatch) -> None:
    server = MCPServer("fake-github")
    calls: list[str] = []

    @server.tool()
    def issue_read(
        owner: str, repo: str, issue_number: int, method: Literal["get", "get_comments"]
    ) -> str:
        calls.append("issue_read")
        return f"{owner}/{repo}#{issue_number}:{method}"

    @server.tool()
    def search_code(query: str) -> str:
        calls.append("search_code")
        return query

    @server.tool()
    def get_file_contents(owner: str, repo: str, path: str) -> str:
        calls.append("get_file_contents")
        return f"{owner}/{repo}:{path}"

    @server.tool()
    def add_issue_comment(owner: str, repo: str, issue_number: int, body: str) -> str:
        calls.append("add_issue_comment")
        return body

    app = server.streamable_http_app(
        streamable_http_path="/mcp/",
        json_response=True,
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    provider = RemoteGithubMcp("test-token")

    def fake_http_client() -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            headers={"Authorization": "Bearer test-token"},
            timeout=20,
        )

    monkeypatch.setattr(provider, "_http_client", fake_http_client)
    async with app.router.lifespan_context(app):
        await provider.validate()
        result = await provider.call(
            "issue_read",
            {"owner": "alice", "repo": "sandbox", "issue_number": 4, "method": "get"},
        )
    assert "alice/sandbox#4:get" in result
    assert calls == ["issue_read"]
