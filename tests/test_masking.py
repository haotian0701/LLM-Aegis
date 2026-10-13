"""Masking behavior at exact text positions, including historical tool JSON."""

from __future__ import annotations

import json

import pytest

from aegis.detection import Finding, RuleDetector, extract_fragments
from aegis.masking import MaskingError, mask_request
from aegis.policy import Category
from aegis.schemas import ChatRequest


def finding(*, start: int, end: int, category: Category = Category.EMAIL) -> Finding:
    return Finding(
        category, "test", "messages[0].content", 0, "messages[0].content", start, end, 1.0, "test"
    )


def test_repeated_values_and_tool_arguments_get_one_placeholder() -> None:
    email = "synthetic@example.org"
    request = ChatRequest.model_validate(
        {
            "model": "demo",
            "messages": [
                {"role": "user", "content": f"Send to {email} and {email}"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "lookup",
                                "arguments": json.dumps({"recipient": email}),
                            },
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": f"Found {email}"},
            ],
        }
    )
    original_findings = RuleDetector().detect(extract_fragments(request))
    masked = mask_request(request, original_findings, nonce="A" * 24)
    token = next(iter(masked.replacements))
    assert masked.replacements == {token: email}
    assert token.startswith("[[AEGIS_")
    assert email not in repr(masked.request.model_dump())
    assert masked.request.messages[0].content == f"Send to {token} and {token}"
    args = masked.request.messages[1].tool_calls
    assert args is not None
    assert json.loads(args[0].function.arguments) == {"recipient": token}
    assert masked.restore(f"Use {token} now") == f"Use {email} now"
    assert masked.restore("No reference") == "No reference"


def test_overlapping_ranges_merge_and_restore() -> None:
    request = ChatRequest.model_validate(
        {"model": "demo", "messages": [{"role": "user", "content": "Alice Smith"}]}
    )
    findings = [
        finding(start=0, end=5, category=Category.PERSON),
        finding(start=0, end=11, category=Category.ORGANIZATION),
    ]
    masked = mask_request(request, findings, nonce="B" * 24)
    assert len(masked.replacements) == 1
    assert list(masked.replacements.values()) == ["Alice Smith"]
    assert masked.request.messages[0].content == next(iter(masked.replacements))


def test_placeholder_collision_and_unresolved_response_fail() -> None:
    marker = f"[[AEGIS_{'C' * 24}_"
    request = ChatRequest.model_validate(
        {"model": "demo", "messages": [{"role": "user", "content": f"Jane {marker} Smith"}]}
    )
    with pytest.raises(MaskingError):
        mask_request(request, [finding(start=0, end=4)], nonce="C" * 24)
    clean = ChatRequest.model_validate(
        {"model": "demo", "messages": [{"role": "user", "content": "Jane Doe"}]}
    )
    masked = mask_request(clean, [finding(start=0, end=8)], nonce="D" * 24)
    with pytest.raises(MaskingError):
        masked.restore(masked.marker + "PERSON_999]]")
    with pytest.raises(MaskingError):
        masked.restore(masked.marker + "PERSON_001")


def test_missing_detection_or_invalid_tool_json_fails_before_dispatch() -> None:
    request = ChatRequest.model_validate(
        {"model": "demo", "messages": [{"role": "user", "content": "a@b.com and a@b.com"}]}
    )
    with pytest.raises(MaskingError):
        mask_request(request, [finding(start=0, end=7)])
    tool_request = ChatRequest.model_validate(
        {
            "model": "demo",
            "messages": [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "run", "arguments": '{"email":"a@b.com"}'},
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "done"},
            ],
        }
    )
    path = "messages[0].tool_calls[0].function.arguments"
    structural = Finding(Category.EMAIL, "test", path, 0, path, 0, 2, 1.0, "test")
    with pytest.raises(MaskingError):
        mask_request(tool_request, [structural])
