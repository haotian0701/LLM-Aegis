"""Conversation state and fail-closed audit lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis.models import AuditEvent, Conversation
from aegis.policy import Action


@dataclass(frozen=True)
class AuditDraft:
    request_id: str
    principal_id: str | None
    conversation_id: str | None
    status: str
    model_alias: str | None
    prompt_hmac: str | None
    error_code: str | None = None


class RequestStore(Protocol):
    async def record_rejection(self, draft: AuditDraft) -> None: ...

    async def begin_request(self, draft: AuditDraft) -> bool: ...

    async def record_external_intent(
        self, request_id: str, *, provider_name: str, model: str
    ) -> None: ...

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
    ) -> Action: ...

    async def finish_dispatch(
        self,
        request_id: str,
        *,
        status: str,
        error_code: str | None,
        duration_ms: int,
        detection_status: str | None = None,
        semantic_call_status: str | None = None,
        detected_categories: list[str] | None = None,
        detector_durations_ms: dict[str, int] | None = None,
    ) -> None: ...


class PostgresRequestStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    @staticmethod
    def _event(draft: AuditDraft) -> AuditEvent:
        return AuditEvent(
            request_id=draft.request_id,
            principal_id=draft.principal_id,
            conversation_id=draft.conversation_id,
            status=draft.status,
            policy_action=None,
            actual_destination="NONE",
            provider_name=None,
            model_alias=draft.model_alias,
            provider_model=None,
            simulation=False,
            blocked=False,
            masked=False,
            prompt_hmac=draft.prompt_hmac,
            detected_categories=[],
            detection_status="NOT_RUN" if draft.status == "REJECTED" else "PENDING",
            detector_durations_ms={},
            error_code=draft.error_code,
        )

    async def record_rejection(self, draft: AuditDraft) -> None:
        async with self._sessions() as session, session.begin():
            session.add(self._event(draft))

    async def begin_request(self, draft: AuditDraft) -> bool:
        if draft.principal_id is None or draft.conversation_id is None:
            raise ValueError("valid request needs principal and conversation")
        async with self._sessions() as session, session.begin():
            statement = insert(Conversation).values(
                principal_id=draft.principal_id,
                conversation_id=draft.conversation_id,
                sensitive=False,
            )
            await session.execute(
                statement.on_conflict_do_nothing(
                    index_elements=[Conversation.principal_id, Conversation.conversation_id]
                )
            )
            conversation = await session.get(
                Conversation, (draft.principal_id, draft.conversation_id)
            )
            if conversation is None:
                raise RuntimeError("conversation was not created")
            session.add(self._event(draft))
            return conversation.sensitive

    async def record_external_intent(
        self, request_id: str, *, provider_name: str, model: str
    ) -> None:
        async with self._sessions() as session, session.begin():
            event = await session.get(AuditEvent, request_id, with_for_update=True)
            if event is None or event.status != "PENDING" or event.semantic_call_status is not None:
                raise RuntimeError("pending audit event was not found")
            event.semantic_destination = "EXTERNAL"
            event.semantic_provider_name = provider_name
            event.semantic_model = model
            event.semantic_call_status = "INTENDED"

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
        async with self._sessions() as session, session.begin():
            conversation = await session.get(
                Conversation, (principal_id, conversation_id), with_for_update=True
            )
            event = await session.get(AuditEvent, request_id, with_for_update=True)
            if conversation is None or event is None or event.status != "PENDING":
                raise RuntimeError("pending request was not found")
            if upgrade_sensitive:
                conversation.sensitive = True
                conversation.updated_at = datetime.now(UTC)
            effective_action = action
            if conversation.sensitive and action in {Action.CLOUD, Action.MASK_CLOUD}:
                effective_action = Action.LOCAL
            event.policy_action = effective_action.value
            event.actual_destination = (
                local_destination if effective_action == Action.LOCAL else "NONE"
            )
            event.provider_name = local_provider_name if effective_action == Action.LOCAL else None
            event.provider_model = local_model if effective_action == Action.LOCAL else None
            event.simulation = local_simulation if effective_action == Action.LOCAL else False
            event.blocked = effective_action == Action.BLOCK
            event.detected_categories = categories
            event.detection_status = detection_status
            event.detector_durations_ms = detector_durations_ms
            if semantic_succeeded:
                if event.semantic_call_status != "INTENDED":
                    raise RuntimeError("external detector intent was not recorded")
                event.semantic_call_status = "SUCCEEDED"
            return effective_action

    async def finish_dispatch(
        self,
        request_id: str,
        *,
        status: str,
        error_code: str | None,
        duration_ms: int,
        detection_status: str | None = None,
        semantic_call_status: str | None = None,
        detected_categories: list[str] | None = None,
        detector_durations_ms: dict[str, int] | None = None,
    ) -> None:
        async with self._sessions() as session, session.begin():
            event = await session.get(AuditEvent, request_id, with_for_update=True)
            if event is None or event.status != "PENDING":
                raise RuntimeError("pending audit event was not found")
            event.status = status
            event.error_code = error_code
            event.total_duration_ms = duration_ms
            event.finished_at = datetime.now(UTC)
            if detection_status is not None:
                event.detection_status = detection_status
            if semantic_call_status is not None:
                event.semantic_call_status = semantic_call_status
            if detected_categories is not None:
                event.detected_categories = detected_categories
            if detector_durations_ms is not None:
                event.detector_durations_ms = detector_durations_ms
