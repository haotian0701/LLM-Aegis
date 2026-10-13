"""Detector position, validation, overlap and classifier contract checks."""

from __future__ import annotations

import json

import httpx
import pytest

from aegis.detection import (
    Finding,
    RuleDetector,
    SpacyEnglishNer,
    TextFragment,
    extract_fragments,
    unique_findings,
)
from aegis.policy import Action, Category, PolicyEngine
from aegis.schemas import ChatRequest
from aegis.semantic import OpenAICompatibleSemanticDetector, SemanticDetectionError


def test_rule_positions_and_iban_checksum() -> None:
    text = "Wrong DE00370400440532013000; valid DE89370400440532013000."
    fragment = TextFragment("message", 2, "messages[2].content", text)
    findings = RuleDetector().detect([fragment])
    ibans = [finding for finding in findings if finding.category == Category.IBAN]
    assert len(ibans) == 1
    assert text[ibans[0].start : ibans[0].end] == "DE89370400440532013000"
    assert ibans[0].message_index == 2


def test_quoted_json_key_and_secret_values_are_detected() -> None:
    text = '{"api_key":"abcdefghijklmnop1234","password":"secretvalue123"}'
    fragment = TextFragment("args", 0, "messages[0].tool_calls[0].function.arguments", text)
    findings = RuleDetector().detect([fragment])
    assert {finding.category for finding in findings} == {Category.API_KEY, Category.SECRET}
    assert {text[finding.start : finding.end] for finding in findings} == {
        "abcdefghijklmnop1234",
        "secretvalue123",
    }


def test_tool_arguments_are_extracted_with_stable_paths() -> None:
    request = ChatRequest.model_validate(
        {
            "model": "aegis-mock",
            "messages": [
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "lookup",
                                "arguments": '{"email":"x@example.org"}',
                            },
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "done"},
            ],
        }
    )
    fragments = extract_fragments(request)
    assert [item.path for item in fragments] == [
        "messages[0].tool_calls[0].function.arguments",
        "messages[1].content",
    ]
    assert RuleDetector().detect(fragments)[0].category == Category.EMAIL


def test_overlap_keeps_distinct_categories_and_deduplicates_exact_matches() -> None:
    base = ("same", 0, "messages[0].content", 0, 5, None, "uncalibrated")
    person = Finding(Category.PERSON, "ner", *base)
    org = Finding(Category.ORGANIZATION, "ner", *base)
    results = unique_findings([person, person, org])
    assert len(results) == 2
    assert (
        PolicyEngine.load().decide((item.category for item in results), was_sensitive=False)
        == Action.MASK_CLOUD
    )


@pytest.mark.asyncio
async def test_real_english_ner_reports_uncalibrated_offsets() -> None:
    text = "Barack Obama met Microsoft in London."
    fragments = [TextFragment("a", 0, "messages[0].content", text)]
    results = await SpacyEnglishNer().detect(fragments)
    assert {finding.category for finding in results} >= {
        Category.PERSON,
        Category.ORGANIZATION,
        Category.LOCATION,
    }
    assert all(finding.confidence is None for finding in results)
    assert all(finding.confidence_kind == "uncalibrated" for finding in results)
    assert all(text[finding.start : finding.end] for finding in results)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content",
    [
        '{"results":[]}',
        '{"results":[{"id":"a","label":"UNCERTAIN"}]}',
        '{"results":[{"id":"a","label":"CLEAR"},{"id":"a","label":"CLEAR"}]}',
        '{"results":[{"id":"other","label":"CLEAR"}]}',
        "not JSON",
    ],
)
async def test_semantic_invalid_or_uncertain_results_fail_closed(content: str) -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["model"] == "fake-model"
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        detector = OpenAICompatibleSemanticDetector(
            url="https://semantic.example/v1/chat/completions",
            api_key="fake-key",
            model="fake-model",
            client=client,
        )
        with pytest.raises(SemanticDetectionError):
            await detector.detect([TextFragment("a", 0, "messages[0].content", "synthetic")])
