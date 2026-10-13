"""Extract every supported text field and detect local sensitive entities."""

from __future__ import annotations

import asyncio
import ipaddress
import re
from dataclasses import dataclass
from typing import Protocol

import spacy

from aegis.policy import Category
from aegis.schemas import ChatRequest


@dataclass(frozen=True)
class TextFragment:
    text_id: str
    message_index: int
    path: str
    text: str


@dataclass(frozen=True)
class Finding:
    category: Category
    source: str
    text_id: str
    message_index: int
    path: str
    start: int
    end: int
    confidence: float | None
    confidence_kind: str


class NerDetector(Protocol):
    async def detect(self, fragments: list[TextFragment]) -> list[Finding]: ...


def extract_fragments(request: ChatRequest) -> list[TextFragment]:
    fragments: list[TextFragment] = []
    for index, message in enumerate(request.messages):
        if message.content:
            path = f"messages[{index}].content"
            fragments.append(TextFragment(path, index, path, message.content))
        if message.tool_calls:
            for call_index, call in enumerate(message.tool_calls):
                path = f"messages[{index}].tool_calls[{call_index}].function.arguments"
                fragments.append(TextFragment(path, index, path, call.function.arguments))
    return fragments


def text_bytes(fragments: list[TextFragment]) -> int:
    return sum(len(fragment.text.encode("utf-8")) for fragment in fragments)


def unique_findings(findings: list[Finding]) -> list[Finding]:
    unique = {
        (finding.category, finding.source, finding.text_id, finding.start, finding.end): finding
        for finding in findings
    }
    return sorted(
        unique.values(),
        key=lambda item: (item.message_index, item.path, item.start, item.end, item.category),
    )


class RuleDetector:
    EMAIL = re.compile(r"(?<![\w.])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?!\w)")
    IBAN = re.compile(r"(?<!\w)[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}(?!\w)", re.I)
    PHONE = re.compile(r"(?<!\w)\+[1-9]\d{7,14}(?!\d)")
    IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    IPV6 = re.compile(
        r"(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9:]{0,4}(?![A-Fa-f0-9:])"
    )
    PREFIXED_KEY = re.compile(
        r"(?<![A-Za-z0-9])(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|"
        r"github_pat_[A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{16})(?![A-Za-z0-9])"
    )
    LABELED_KEY = re.compile(
        r"\b(?:api[_ -]?key|access[_ -]?token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{16,})",
        re.I,
    )
    LABELED_SECRET = re.compile(
        r"\b(?:password|secret|client_secret|private_key)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})",
        re.I,
    )

    @staticmethod
    def _valid_iban(value: str) -> bool:
        compact = re.sub(r"[ -]", "", value).upper()
        if not 15 <= len(compact) <= 34 or not compact.isalnum():
            return False
        rearranged = compact[4:] + compact[:4]
        remainder = 0
        for char in rearranged:
            digits = str(ord(char) - ord("A") + 10) if char.isalpha() else char
            for digit in digits:
                remainder = (remainder * 10 + int(digit)) % 97
        return remainder == 1

    def detect(self, fragments: list[TextFragment]) -> list[Finding]:
        findings: list[Finding] = []
        for fragment in fragments:
            for category, pattern, validator, group in (
                (Category.EMAIL, self.EMAIL, None, 0),
                (Category.IBAN, self.IBAN, self._valid_iban, 0),
                (Category.PHONE, self.PHONE, None, 0),
                (Category.IP_ADDRESS, self.IPV4, self._valid_ip, 0),
                (Category.IP_ADDRESS, self.IPV6, self._valid_ip, 0),
                (Category.API_KEY, self.PREFIXED_KEY, None, 0),
                (Category.API_KEY, self.LABELED_KEY, None, 1),
                (Category.SECRET, self.LABELED_SECRET, None, 1),
            ):
                for match in pattern.finditer(fragment.text):
                    value = match.group(group)
                    if validator is not None and not validator(value):
                        continue
                    findings.append(
                        Finding(
                            category=category,
                            source="rule",
                            text_id=fragment.text_id,
                            message_index=fragment.message_index,
                            path=fragment.path,
                            start=match.start(group),
                            end=match.end(group),
                            confidence=1.0,
                            confidence_kind="validated_pattern",
                        )
                    )
        return unique_findings(findings)

    @staticmethod
    def _valid_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return False
        return True


class SpacyEnglishNer:
    LABELS = {
        "PERSON": Category.PERSON,
        "ORG": Category.ORGANIZATION,
        "GPE": Category.LOCATION,
        "LOC": Category.LOCATION,
    }

    def __init__(self) -> None:
        try:
            self._pipeline = spacy.load("en_core_web_sm")
        except OSError as exc:
            raise ValueError("English NER model en_core_web_sm is not installed") from exc

    async def detect(self, fragments: list[TextFragment]) -> list[Finding]:
        return await asyncio.wait_for(asyncio.to_thread(self._detect_sync, fragments), timeout=10.0)

    def _detect_sync(self, fragments: list[TextFragment]) -> list[Finding]:
        findings: list[Finding] = []
        for fragment in fragments:
            doc = self._pipeline(fragment.text)
            for entity in doc.ents:
                category = self.LABELS.get(entity.label_)
                if category is None:
                    continue
                findings.append(
                    Finding(
                        category=category,
                        source="spacy_en",
                        text_id=fragment.text_id,
                        message_index=fragment.message_index,
                        path=fragment.path,
                        start=entity.start_char,
                        end=entity.end_char,
                        confidence=None,
                        confidence_kind="uncalibrated",
                    )
                )
        return unique_findings(findings)
