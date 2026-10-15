"""Audited model boundary for the local project workflow."""

from __future__ import annotations

import json
from hashlib import sha256
from urllib.parse import urlsplit
from uuid import uuid4

from aegis.agent_provider import AgentModel, OpenAICompatibleAgentModel, ProposedToolCall
from aegis.config import Settings
from aegis.detection import (
    NerDetector,
    RuleDetector,
    extract_fragments,
    text_bytes,
    unique_findings,
)
from aegis.masking import MaskingError, mask_request
from aegis.policy import UPGRADE_CATEGORIES, Action, PolicyEngine
from aegis.schemas import ChatMessage, ChatRequest
from aegis.semantic import SemanticDetectionError, SemanticDetector
from aegis.store import RequestStore, StepDraft


class AgentFailure(Exception):
    def __init__(self, http_status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.code = code
        self.message = message


class AgentService:
    MAX_TEXT_BYTES = 32 * 1024

    def __init__(
        self,
        *,
        settings: Settings,
        store: RequestStore,
        policy: PolicyEngine,
        rule_detector: RuleDetector,
        ner_detector: NerDetector,
        semantic_detector: SemanticDetector | None,
        cloud_model: AgentModel,
    ) -> None:
        self.settings = settings
        self.store = store
        self.policy = policy
        self.rule_detector = rule_detector
        self.ner_detector = ner_detector
        self.semantic_detector = semantic_detector
        self.cloud_model = cloud_model
        configured_actions = getattr(policy, "actions", {})
        configured_default = getattr(policy, "default_action", Action.BLOCK)
        model_rules = {
            "default": configured_default.value,
            "categories": {key.value: value.value for key, value in configured_actions.items()},
        }
        self.model_policy_version = sha256(
            json.dumps(model_rules, sort_keys=True).encode("utf-8")
        ).hexdigest()

    async def _start(
        self,
        task_id: str,
        kind: str,
        source: str,
        target: str,
        summary: str,
        version: str,
        rules: list[str],
        categories: list[str],
        decision: str,
        *,
        model_action: Action | None = None,
        simulation: bool = False,
        upgrade_sensitive: bool = False,
    ) -> str:
        step_id = uuid4().hex
        try:
            await self.store.start_step(
                StepDraft(
                    step_id=step_id,
                    task_id=task_id,
                    kind=kind,
                    source=source[:128],
                    target=target[:256],
                    input_summary=summary[:256],
                    policy_version=version,
                    matched_rules=rules,
                    data_categories=categories,
                    decision=decision,
                ),
                model_action=model_action,
                simulation=simulation,
                upgrade_sensitive=upgrade_sensitive,
            )
        except Exception as exc:
            raise AgentFailure(503, "AUDIT_UNAVAILABLE", "Audit storage is unavailable.") from exc
        return step_id

    async def _finish(
        self,
        step_id: str,
        status: str,
        executed: bool | None,
        destination: str,
        error: str | None = None,
    ) -> None:
        try:
            await self.store.finish_step(
                step_id,
                execution_status=status,
                executed=executed,
                actual_destination=destination,
                error_code=error,
            )
        except Exception as exc:
            raise AgentFailure(503, "AUDIT_UNAVAILABLE", "Audit storage is unavailable.") from exc

    async def _model_turn(
        self,
        task_id: str,
        model_alias: str,
        messages: list[ChatMessage],
        was_sensitive: bool,
        *,
        trusted_system: bool = False,
        user_only_ner: bool = False,
    ) -> tuple[str | None, ProposedToolCall | None, bool]:
        request = ChatRequest(model=model_alias, messages=messages)
        all_fragments = extract_fragments(request)
        if text_bytes(all_fragments) > self.MAX_TEXT_BYTES:
            raise AgentFailure(413, "INVALID_REQUEST", "Task context is too large.")
        if trusted_system and (not messages or messages[0].role != "system"):
            raise ValueError("trusted system message is missing")
        fragments = (
            [fragment for fragment in all_fragments if fragment.message_index != 0]
            if trusted_system
            else all_fragments
        )
        try:
            findings = self.rule_detector.detect(fragments)
            initial_action = self.policy.decide(
                (finding.category for finding in findings), was_sensitive=was_sensitive
            )
            if initial_action != Action.BLOCK:
                ner_fragments = (
                    [
                        fragment
                        for fragment in fragments
                        if messages[fragment.message_index].role == "user"
                    ]
                    if user_only_ner
                    else fragments
                )
                findings.extend(await self.ner_detector.detect(ner_fragments))
            findings = unique_findings(findings)
            categories = {finding.category for finding in findings}
            action = self.policy.decide(categories, was_sensitive=was_sensitive)
        except Exception as exc:
            raise AgentFailure(503, "SECURITY_UNAVAILABLE", "Security detection failed.") from exc

        if action != Action.BLOCK and not was_sensitive and fragments:
            detector = self.semantic_detector
            if detector is None:
                step_id = await self._start(
                    task_id,
                    "SEMANTIC_CHECK",
                    "none",
                    "none",
                    "classifier unavailable",
                    self.model_policy_version,
                    ["semantic_required"],
                    [],
                    "DENY",
                )
                await self._finish(step_id, "FAILED", False, "NONE", "SECURITY_UNAVAILABLE")
                raise AgentFailure(
                    503, "SECURITY_UNAVAILABLE", "Semantic detection is unavailable."
                )
            target = getattr(detector, "url", detector.name)
            step_id = await self._start(
                task_id,
                "SEMANTIC_CHECK",
                detector.name,
                str(target),
                f"fragments={len(fragments)};bytes={text_bytes(fragments)}",
                self.model_policy_version,
                ["semantic_required"],
                [],
                "CLASSIFY",
            )
            try:
                findings.extend(await detector.detect(fragments))
            except SemanticDetectionError as exc:
                if exc.reason == "UNCERTAIN":
                    await self._finish(
                        step_id, "FAILED", None, detector.destination, "SEMANTIC_UNCERTAIN"
                    )
                    raise AgentFailure(
                        403,
                        "SEMANTIC_UNCERTAIN",
                        "Classifier could not determine whether this task may leave the machine.",
                    ) from exc
                await self._finish(
                    step_id, "FAILED", None, detector.destination, "SECURITY_UNAVAILABLE"
                )
                raise AgentFailure(
                    503, "SECURITY_UNAVAILABLE", "Semantic detection failed."
                ) from exc
            except Exception as exc:
                await self._finish(
                    step_id, "FAILED", None, detector.destination, "SECURITY_UNAVAILABLE"
                )
                raise AgentFailure(
                    503, "SECURITY_UNAVAILABLE", "Semantic detection failed."
                ) from exc
            await self._finish(step_id, "SUCCEEDED", True, detector.destination)
            findings = unique_findings(findings)
            categories = {finding.category for finding in findings}
            action = self.policy.decide(categories, was_sensitive=was_sensitive)

        category_names = sorted(category.value for category in categories)
        sensitive = was_sensitive or bool(categories & UPGRADE_CATEGORIES)
        model: AgentModel | None = self.cloud_model
        if action == Action.BLOCK:
            step_id = await self._start(
                task_id,
                "MODEL_REQUEST",
                "policy",
                "none",
                "model request denied",
                self.model_policy_version,
                ["model_block"],
                category_names,
                action.value,
                model_action=action,
                upgrade_sensitive=sensitive,
            )
            await self._finish(step_id, "FAILED", False, "NONE", "POLICY_BLOCKED")
            raise AgentFailure(403, "POLICY_BLOCKED", "Model request blocked by policy.")
        if action == Action.LOCAL and self.settings.demo_provider != "simulated_local":
            model = None
        if model is None:
            step_id = await self._start(
                task_id,
                "MODEL_REQUEST",
                "none",
                "none",
                "model route unavailable",
                self.model_policy_version,
                ["route_unavailable"],
                category_names,
                action.value,
                model_action=action,
                upgrade_sensitive=sensitive,
            )
            await self._finish(step_id, "FAILED", False, "NONE", "ROUTE_UNAVAILABLE")
            raise AgentFailure(503, "ROUTE_UNAVAILABLE", "Agent model route is unavailable.")

        outbound = request
        masked = None
        if action == Action.MASK_CLOUD:
            try:
                masked = mask_request(request, findings)
                outbound = masked.request
            except MaskingError as exc:
                raise AgentFailure(
                    503, "SECURITY_UNAVAILABLE", "Model request could not be masked."
                ) from exc
        destination = model.destination
        target = (
            urlsplit(model.url).netloc
            if isinstance(model, OpenAICompatibleAgentModel)
            else model.name
        )
        step_id = await self._start(
            task_id,
            "MODEL_REQUEST",
            model.name,
            target,
            f"messages={len(messages)};bytes={text_bytes(fragments)}",
            self.model_policy_version,
            [f"model_route_{action.value.lower()}"],
            category_names,
            action.value,
            model_action=action,
            simulation=model.simulation
            or (action == Action.LOCAL and model.destination == "EXTERNAL"),
            upgrade_sensitive=sensitive,
        )
        try:
            turn = await model.next_turn(outbound)
            content = (
                masked.restore(turn.content)
                if masked and turn.content is not None
                else turn.content
            )
            tool_call = turn.tool_call
            if masked and tool_call is not None:
                tool_call = ProposedToolCall(
                    tool_call.id,
                    tool_call.name,
                    masked.restore(tool_call.arguments),
                )
        except TimeoutError as exc:
            await self._finish(step_id, "UNKNOWN", None, destination, "PROVIDER_TIMEOUT")
            raise AgentFailure(504, "PROVIDER_TIMEOUT", "Agent model timed out.") from exc
        except Exception as exc:
            await self._finish(step_id, "FAILED", None, destination, "PROVIDER_ERROR")
            raise AgentFailure(502, "PROVIDER_ERROR", "Agent model failed.") from exc
        await self._finish(step_id, "SUCCEEDED", True, destination)
        return content, tool_call, sensitive
