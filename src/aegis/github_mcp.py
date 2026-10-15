"""Narrow client for GitHub's hosted MCP server."""

from __future__ import annotations

import json
from typing import Any, Protocol

import httpx2
from mcp.client import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import ListToolsResult

GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/"
ALLOWED_TOOLS = frozenset({"issue_read", "search_code", "get_file_contents", "add_issue_comment"})
REQUIRED_ARGUMENTS = {
    "issue_read": {"owner", "repo", "issue_number", "method"},
    "search_code": {"query"},
    "get_file_contents": {"owner", "repo", "path"},
    "add_issue_comment": {"owner", "repo", "issue_number", "body"},
}
ARGUMENT_TYPES = {
    "owner": "string",
    "repo": "string",
    "issue_number": ("number", "integer"),
    "method": "string",
    "query": "string",
    "path": "string",
    "body": "string",
}


class GithubToolError(Exception):
    pass


class GithubToolProvider(Protocol):
    async def validate(self) -> None: ...

    async def call(self, name: str, arguments: dict[str, Any]) -> str: ...


class RemoteGithubMcp:
    def __init__(self, token: str, url: str = GITHUB_MCP_URL) -> None:
        if url != GITHUB_MCP_URL:
            raise ValueError("GitHub MCP URL is fixed")
        self._token = token
        self._url = url
        self._ready = False

    def _http_client(self) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            headers={
                "Authorization": f"Bearer {self._token}",
                "X-MCP-Tools": ",".join(sorted(ALLOWED_TOOLS)),
            },
            timeout=20,
            follow_redirects=False,
        )

    async def validate(self) -> None:
        async with self._http_client() as http_client:
            async with Client(
                streamable_http_client(self._url, http_client=http_client),
                mode="2026-07-28",
                read_timeout_seconds=20,
            ) as client:
                result = await client.list_tools()
        self._validate_inventory(result)
        self._ready = True

    @staticmethod
    def _validate_inventory(result: ListToolsResult) -> None:
        tools = {tool.name: tool for tool in result.tools}
        if (
            set(tools) != ALLOWED_TOOLS
            or len(result.tools) != len(ALLOWED_TOOLS)
            or result.next_cursor is not None
        ):
            raise GithubToolError("GitHub MCP tool inventory changed")
        for name, tool in tools.items():
            schema = tool.input_schema
            if schema.get("type") != "object":
                raise GithubToolError(f"invalid GitHub MCP schema for {name}")
            properties = schema.get("properties")
            required = schema.get("required")
            if (
                not isinstance(properties, dict)
                or not isinstance(required, list)
                or set(required) != REQUIRED_ARGUMENTS[name]
                or any(
                    not isinstance(properties.get(field), dict)
                    or properties[field].get("type")
                    not in (
                        ARGUMENT_TYPES[field]
                        if isinstance(ARGUMENT_TYPES[field], tuple)
                        else (ARGUMENT_TYPES[field],)
                    )
                    for field in REQUIRED_ARGUMENTS[name]
                )
            ):
                raise GithubToolError(f"GitHub MCP schema changed for {name}")
            if name == "issue_read" and not {"get", "get_comments"} <= set(
                properties["method"].get("enum", [])
            ):
                raise GithubToolError("GitHub MCP issue_read methods changed")

    async def call(self, name: str, arguments: dict[str, Any]) -> str:
        if not self._ready or name not in ALLOWED_TOOLS:
            raise GithubToolError("GitHub MCP tool is unavailable")
        async with self._http_client() as http_client:
            async with Client(
                streamable_http_client(self._url, http_client=http_client),
                mode="2026-07-28",
                read_timeout_seconds=20,
            ) as client:
                result = await client.call_tool(name, arguments)
        if result.is_error or result.result_type != "complete":
            raise GithubToolError("GitHub MCP tool returned an error")
        if result.structured_content is not None:
            text = json.dumps(result.structured_content, ensure_ascii=False)
        else:
            if any(item.type != "text" for item in result.content):
                raise GithubToolError("unsupported GitHub MCP result content")
            text = "\n".join(item.text for item in result.content if item.type == "text")
        if not text or len(text.encode("utf-8")) > 65536:
            raise GithubToolError("GitHub MCP result is empty or too large")
        return text
