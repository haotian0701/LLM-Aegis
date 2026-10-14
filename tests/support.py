"""Reusable fake dependencies for API and browser tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from aegis.config import Settings
from aegis.detection import Finding, TextFragment
from aegis.main import create_app
from aegis.policy import Action, Category
from aegis.provider import ProviderResult
from aegis.schemas import ChatRequest
from aegis.semantic import OpenAICompatibleSemanticDetector
from aegis.store import AuditDraft, AuditSummary, BeginResult, ConversationSummary

HMAC_KEY = "test-hmac-key-longer-than-thirty-two-bytes"
DB_URL = "postgresql+psycopg://unused:unused@localhost/unused"


class MemoryStore:
    def __init__(self) -> None:
        self.events: dict[str, dict[str, Any]] = {}
        self.conversations: dict[tuple[str, str], bool] = {}
        self.active: dict[tuple[str, str], str] = {}
        self.closed: set[tuple[str, str]] = set()
        self.versions: dict[tuple[str, str], int] = {}
        self.fail_begin = False
        self.fail_intent = False
        self.fail_model_intent = False
        self.fail_decision = False
        self.fail_finish = False

    async def get_audit_summary(self, request_id: str, principal_id: str) -> AuditSummary | None:
        event = self.events.get(request_id)
        if event is None or event["principal_id"] != principal_id:
            return None
        return AuditSummary(
            request_id=request_id,
            conversation_id=event["conversation_id"],
            status=event["status"],
            policy_action=event["policy_action"],
            actual_destination=event["actual_destination"],
            simulation=event.get("simulation", False),
            detected_categories=event["detected_categories"],
            detection_status=event["detection_status"],
            semantic_call_status=event.get("semantic_call_status"),
            masking_status=event.get("masking_status"),
            model_call_status=event.get("model_call_status"),
            error_code=event.get("error_code"),
            started_at=event.get("started_at"),
            finished_at=event.get("finished_at"),
            conversation_state_before=event.get("conversation_state_before"),
            conversation_state_after=event.get("conversation_state_after"),
            conversation_state_version=event.get("conversation_state_version"),
            provider_name=event.get("provider_name"),
            provider_model=event.get("provider_model"),
            detector_durations_ms=event.get("detector_durations_ms"),
            total_duration_ms=event.get("total_duration_ms"),
        )

    async def list_audits(
        self,
        principal_id: str,
        *,
        limit: int,
        policy_action: str | None,
        status: str | None,
        conversation_id: str | None,
        before: tuple[datetime, str] | None,
    ) -> list[AuditSummary]:
        events = [
            event
            for event in self.events.values()
            if event["principal_id"] == principal_id
            and (policy_action is None or event["policy_action"] == policy_action)
            and (status is None or event["status"] == status)
            and (conversation_id is None or event["conversation_id"] == conversation_id)
        ]
        events.sort(key=lambda event: (event["started_at"], event["request_id"]), reverse=True)
        if before is not None:
            events = [
                event for event in events if (event["started_at"], event["request_id"]) < before
            ]
        summaries = [
            await self.get_audit_summary(event["request_id"], principal_id)
            for event in events[:limit]
        ]
        return [summary for summary in summaries if summary is not None]

    async def get_conversation_summary(
        self, conversation_id: str, principal_id: str
    ) -> ConversationSummary | None:
        key = (principal_id, conversation_id)
        if key not in self.conversations:
            return None
        state = (
            "CLOSED" if key in self.closed else "SENSITIVE" if self.conversations[key] else "NORMAL"
        )
        return ConversationSummary(
            conversation_id=conversation_id,
            state=state,
            state_version=self.versions[key],
            active_request=key in self.active,
            updated_at=datetime.now(UTC),
        )

    async def record_rejection(self, draft: AuditDraft) -> None:
        self.events[draft.request_id] = {
            **vars(draft),
            "policy_action": None,
            "actual_destination": "NONE",
            "detected_categories": [],
            "detection_status": "NOT_RUN",
            "started_at": datetime.now(UTC),
        }

    async def begin_request(self, draft: AuditDraft) -> BeginResult:
        if self.fail_begin:
            raise RuntimeError("database unavailable")
        assert draft.principal_id is not None
        assert draft.conversation_id is not None
        key = (draft.principal_id, draft.conversation_id)
        self.conversations.setdefault(key, False)
        self.versions.setdefault(key, 0)
        state = "SENSITIVE" if self.conversations[key] else "NORMAL"
        self.events[draft.request_id] = {
            **vars(draft),
            "policy_action": None,
            "actual_destination": "NONE",
            "detected_categories": [],
            "detection_status": "PENDING",
            "semantic_call_status": None,
            "model_call_status": None,
            "masking_status": None,
            "conversation_state_before": state,
            "conversation_state_after": None,
            "conversation_state_version": self.versions[key],
            "started_at": datetime.now(UTC),
        }
        if key in self.closed:
            self.events[draft.request_id].update(
                status="REJECTED",
                error_code="CONVERSATION_CLOSED",
                conversation_state_before="CLOSED",
                conversation_state_after="CLOSED",
                detection_status="NOT_RUN",
            )
            return BeginResult("CLOSED")
        if key in self.active:
            self.events[draft.request_id].update(
                status="REJECTED",
                error_code="CONVERSATION_BUSY",
                conversation_state_after=state,
                detection_status="NOT_RUN",
            )
            return BeginResult("BUSY")
        self.active[key] = draft.request_id
        return BeginResult("CLAIMED", self.conversations[key])

    async def record_external_intent(
        self, request_id: str, *, provider_name: str, model: str
    ) -> None:
        if self.fail_intent:
            raise RuntimeError("database unavailable")
        event = self.events[request_id]
        assert self.active[(event["principal_id"], event["conversation_id"])] == request_id
        self.events[request_id].update(
            semantic_destination="EXTERNAL",
            semantic_provider_name=provider_name,
            semantic_model=model,
            semantic_call_status="INTENDED",
        )

    async def record_model_intent(
        self, request_id: str, *, provider_name: str, model: str, masked: bool
    ) -> None:
        if self.fail_model_intent:
            raise RuntimeError("database unavailable")
        event = self.events[request_id]
        assert self.active[(event["principal_id"], event["conversation_id"])] == request_id
        assert event["policy_action"] in {"CLOUD", "MASK_CLOUD"} or (
            event["policy_action"] == "LOCAL" and event["simulation"]
        )
        assert masked == (event["policy_action"] == "MASK_CLOUD")
        event.update(
            actual_destination="EXTERNAL",
            provider_name=provider_name,
            provider_model=model,
            model_call_status="INTENDED",
            masked=masked,
            masking_status="SUCCEEDED" if masked else None,
        )

    async def record_decision(
        self,
        request_id: str,
        *,
        principal_id: str,
        conversation_id: str,
        action: Action,
        categories: list[str],
        detection_status: str,
        detector_durations_ms: dict[str, int],
        upgrade_sensitive: bool,
        local_destination: str,
        local_provider_name: str | None,
        local_model: str | None,
        local_simulation: bool,
        semantic_succeeded: bool,
    ) -> Action:
        if self.fail_decision:
            raise RuntimeError("database unavailable")
        key = (principal_id, conversation_id)
        assert self.active[key] == request_id
        if upgrade_sensitive and not self.conversations[key]:
            self.conversations[key] = True
            self.versions[key] += 1
        if self.conversations[key] and action in {Action.CLOUD, Action.MASK_CLOUD}:
            action = Action.LOCAL
        self.events[request_id].update(
            policy_action=action.value,
            actual_destination=local_destination if action == Action.LOCAL else "NONE",
            provider_name=local_provider_name if action == Action.LOCAL else None,
            provider_model=local_model if action == Action.LOCAL else None,
            simulation=local_simulation if action == Action.LOCAL else False,
            blocked=action == Action.BLOCK,
            detected_categories=categories,
            detection_status=detection_status,
            detector_durations_ms=detector_durations_ms,
            conversation_state_after="SENSITIVE" if self.conversations[key] else "NORMAL",
            conversation_state_version=self.versions[key],
        )
        if semantic_succeeded:
            assert self.events[request_id]["semantic_call_status"] == "INTENDED"
            self.events[request_id]["semantic_call_status"] = "SUCCEEDED"
        return action

    async def finish_dispatch(
        self,
        request_id: str,
        *,
        status: str,
        error_code: str | None,
        duration_ms: int,
        detection_status: str | None = None,
        semantic_call_status: str | None = None,
        model_call_status: str | None = None,
        masking_status: str | None = None,
        detected_categories: list[str] | None = None,
        detector_durations_ms: dict[str, int] | None = None,
    ) -> None:
        if self.fail_finish:
            raise RuntimeError("database unavailable")
        event = self.events[request_id]
        key = (event["principal_id"], event["conversation_id"])
        assert self.active[key] == request_id
        event.update(status=status, error_code=error_code, total_duration_ms=duration_ms)
        event["finished_at"] = datetime.now(UTC)
        if event["conversation_state_after"] is None:
            event["conversation_state_after"] = event["conversation_state_before"]
        if detection_status is not None:
            event["detection_status"] = detection_status
        if semantic_call_status is not None:
            event["semantic_call_status"] = semantic_call_status
        if model_call_status is not None:
            event["model_call_status"] = model_call_status
        elif event["model_call_status"] == "INTENDED":
            event["model_call_status"] = "UNKNOWN"
        if masking_status is not None:
            event["masking_status"] = masking_status
        if detected_categories is not None:
            event["detected_categories"] = detected_categories
        if detector_durations_ms is not None:
            event["detector_durations_ms"] = detector_durations_ms
        del self.active[key]


class RecordingProvider:
    name = "recording-mock"
    destination = "MOCK"
    simulation = True

    def __init__(self, failure: Exception | None = None) -> None:
        self.calls: list[ChatRequest] = []
        self.failure = failure

    async def complete(self, request: ChatRequest) -> ProviderResult:
        self.calls.append(request)
        if self.failure:
            raise self.failure
        return ProviderResult(content="fixed test answer")


class EmptyNer:
    def __init__(self, failure: Exception | None = None) -> None:
        self.calls = 0
        self.failure = failure

    async def detect(self, fragments: list[TextFragment]) -> list[Finding]:
        self.calls += 1
        if self.failure:
            raise self.failure
        return []


class FakeSemantic:
    name = "fake-external"
    model = "fake-classifier"
    destination = "EXTERNAL"
    external = True

    def __init__(self, business_secret: bool = False, failure: Exception | None = None) -> None:
        self.calls: list[list[TextFragment]] = []
        self.business_secret = business_secret
        self.failure = failure

    async def detect(self, fragments: list[TextFragment]) -> list[Finding]:
        self.calls.append(fragments)
        if self.failure:
            raise self.failure
        if not self.business_secret:
            return []
        return [
            Finding(
                Category.BUSINESS_SECRET,
                "semantic_external",
                item.text_id,
                item.message_index,
                item.path,
                0,
                len(item.text),
                None,
                "uncalibrated",
            )
            for item in fragments
        ]


def settings(mode: str = "demo") -> Settings:
    return Settings.model_validate(
        {
            "database_url": DB_URL,
            "api_keys": {"alice": "alice-secret-token", "bob": "bob-secret-token"},
            "hmac_key": HMAC_KEY,
            "run_mode": mode,
            "demo_provider": "mock" if mode == "demo" else None,
        }
    )


def payload(text: str = "Hello") -> dict[str, object]:
    return {"model": "aegis-mock", "messages": [{"role": "user", "content": text}]}


def auth(token: str = "alice-secret-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def app_for(
    store: MemoryStore,
    provider: RecordingProvider | None = None,
    semantic: FakeSemantic | OpenAICompatibleSemanticDetector | None = None,
    *,
    mode: str = "demo",
    ner: EmptyNer | None = None,
):
    return create_app(
        settings(mode),
        store=store,
        provider=provider,
        semantic_detector=semantic,
        ner_detector=ner or EmptyNer(),
    )
