"""Request-scoped reversible masking for the supported text-only contract."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

from pydantic import ValidationError

from aegis.detection import Finding, extract_fragments
from aegis.schemas import ChatRequest


class MaskingError(Exception):
    """A masked request or restored response could not be verified."""


@dataclass(frozen=True)
class MaskedRequest:
    request: ChatRequest
    replacements: dict[str, str]
    marker: str

    def restore(self, content: str) -> str:
        if self.marker not in content:
            return content
        pattern = re.compile(re.escape(self.marker) + r"[^\]]*\]\]")
        restored = pattern.sub(
            lambda match: self.replacements.get(match.group(), match.group()), content
        )
        if self.marker in restored:
            raise MaskingError("response contains an unresolved placeholder")
        return restored


def mask_request(
    request: ChatRequest, findings: list[Finding], *, nonce: str | None = None
) -> MaskedRequest:
    fragments = extract_fragments(request)
    by_id = {fragment.text_id: fragment for fragment in fragments}
    if not findings:
        raise MaskingError("mask route has no located findings")
    nonce = nonce or secrets.token_hex(12).upper()
    if re.fullmatch(r"[A-F0-9]{24}", nonce) is None:
        raise MaskingError("invalid placeholder nonce")
    marker = f"[[AEGIS_{nonce}_"
    if any(marker in fragment.text for fragment in fragments):
        raise MaskingError("placeholder collides with request text")

    spans: dict[str, list[tuple[int, int, str]]] = {}
    for finding in findings:
        fragment = by_id.get(finding.text_id)
        if (
            fragment is None
            or fragment.path != finding.path
            or fragment.message_index != finding.message_index
            or not 0 <= finding.start < finding.end <= len(fragment.text)
        ):
            raise MaskingError("finding has no reliable text position")
        spans.setdefault(finding.text_id, []).append(
            (finding.start, finding.end, finding.category.value)
        )

    values: dict[str, str] = {}
    replacements: dict[str, str] = {}
    masked_texts: dict[str, str] = {}
    for fragment in fragments:
        intervals = sorted(spans.get(fragment.text_id, []))
        if not intervals:
            masked_texts[fragment.text_id] = fragment.text
            continue
        merged: list[tuple[int, int, str]] = []
        for start, end, category in intervals:
            if merged and start < merged[-1][1]:
                old_start, old_end, old_category = merged[-1]
                merged[-1] = (old_start, max(old_end, end), old_category)
            else:
                merged.append((start, end, category))
        parts: list[str] = []
        cursor = 0
        for start, end, category in merged:
            original = fragment.text[start:end]
            placeholder = values.get(original)
            if placeholder is None:
                placeholder = f"{marker}{category}_{len(values) + 1:03d}]]"
                values[original] = placeholder
                replacements[placeholder] = original
            parts.extend((fragment.text[cursor:start], placeholder))
            cursor = end
        parts.append(fragment.text[cursor:])
        masked_texts[fragment.text_id] = "".join(parts)

    body = request.model_dump()
    for fragment in fragments:
        text = masked_texts[fragment.text_id]
        message = body["messages"][fragment.message_index]
        suffix = fragment.path.split("].", 1)[1]
        if suffix in {"content", "name", "tool_call_id"}:
            message[suffix] = text
        elif suffix.startswith("tool_calls["):
            call_index = int(fragment.path.split(".tool_calls[", 1)[1].split("]", 1)[0])
            call = message["tool_calls"][call_index]
            field = suffix.split("].", 1)[1]
            if field == "id":
                call["id"] = text
            elif field in {"function.name", "function.arguments"}:
                call["function"][field.split(".", 1)[1]] = text
            else:
                raise MaskingError("unsupported finding field")
        else:
            raise MaskingError("unsupported finding field")
    try:
        masked = ChatRequest.model_validate(body)
    except ValidationError as exc:
        raise MaskingError("masked request violates the supported contract") from exc
    if any(
        original in fragment.text for fragment in extract_fragments(masked) for original in values
    ):
        raise MaskingError("sensitive value remains in masked request")
    return MaskedRequest(masked, replacements, marker)
