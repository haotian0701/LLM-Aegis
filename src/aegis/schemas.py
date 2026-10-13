"""The deliberately small Chat Completions request and response contract."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator


class ToolFunction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: StrictStr = Field(min_length=1)
    arguments: StrictStr

    @model_validator(mode="after")
    def arguments_are_json_object(self) -> ToolFunction:
        try:
            parsed = json.loads(self.arguments)
        except json.JSONDecodeError as exc:
            raise ValueError("historical tool arguments must be valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ValueError("historical tool arguments must be a JSON object")
        return self


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: StrictStr = Field(min_length=1)
    type: Literal["function"]
    function: ToolFunction


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["system", "developer", "user", "assistant", "tool"]
    content: StrictStr | None
    name: StrictStr | None = None
    tool_call_id: StrictStr | None = None
    tool_calls: list[ToolCall] | None = None

    @model_validator(mode="after")
    def validate_role_fields(self) -> ChatMessage:
        if self.role == "tool":
            if not self.tool_call_id or self.content is None:
                raise ValueError("tool messages need text content and tool_call_id")
            if self.tool_calls is not None:
                raise ValueError("tool messages cannot contain tool_calls")
        elif self.tool_call_id is not None:
            raise ValueError("tool_call_id is only allowed on tool messages")
        if self.role != "assistant" and self.tool_calls is not None:
            raise ValueError("tool_calls are only allowed on assistant messages")
        if self.content is None and not (self.role == "assistant" and self.tool_calls):
            raise ValueError("text content is required")
        return self


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: StrictStr = Field(min_length=1)
    messages: list[ChatMessage] = Field(min_length=1)
    stream: Literal[False] = False
    temperature: float | None = Field(default=None, ge=0, le=2)
    top_p: float | None = Field(default=None, ge=0, le=1)
    max_tokens: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_tool_history(self) -> ChatRequest:
        issued: set[str] = set()
        answered: set[str] = set()
        for message in self.messages:
            if message.tool_calls:
                for call in message.tool_calls:
                    if call.id in issued:
                        raise ValueError("duplicate tool call id")
                    issued.add(call.id)
            if message.role == "tool":
                assert message.tool_call_id is not None
                if message.tool_call_id not in issued or message.tool_call_id in answered:
                    raise ValueError("tool message must follow a matching assistant tool call")
                answered.add(message.tool_call_id)
        if issued != answered:
            raise ValueError("all historical tool calls must have tool responses")
        return self


class ChatCompletionMessage(BaseModel):
    role: Literal["assistant"] = "assistant"
    content: str


class ChatCompletionChoice(BaseModel):
    index: int = 0
    message: ChatCompletionMessage
    finish_reason: Literal["stop", "length"] = "stop"


class ChatCompletionResponse(BaseModel):
    id: str
    object: Literal["chat.completion"] = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
