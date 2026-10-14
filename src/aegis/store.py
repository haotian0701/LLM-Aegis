"""Conversation state and fail-closed audit lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis.models import AuditEvent, Conversation, ConversationAdminEvent
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


@dataclass(frozen=True)
class BeginResult:
    status: Literal["CLAIMED", "BUSY", "CLOSED"]
    was_sensitive: bool | None = None


@dataclass(frozen=True)
class AuditSummary:
    request_id: str
    conversation_id: str | None
    status: str
    policy_action: str | None
    actual_destination: str
    simulation: bool
    detected_categories: list[str]
    detection_status: str
    semantic_call_status: str | None
    masking_status: str | None
    model_call_status: str | None
    error_code: str | None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    conversation_state_before: str | None = None
    conversation_state_after: str | None = None
    conversation_state_version: int | None = None
    provider_name: str | None = None
    provider_model: str | None = None
    detector_durations_ms: dict[str, int] | None = None
    total_duration_ms: int | None = None


@dataclass(frozen=True)
class ConversationSummary:
    conversation_id: str
    state: str
    state_version: int
    active_request: bool
    updated_at: datetime | None


class ConversationNotFound(Exception):
    pass


class ConversationBusy(Exception):
    pass


class RecoveryMismatch(Exception):
    pass


def _state(conversation: Conversation) -> str:
    return (
        "CLOSED" if conversation.closed_at else "SENSITIVE" if conversation.sensitive else "NORMAL"
    )


class RequestStore(Protocol):
    async def get_audit_summary(
        self, request_id: str, principal_id: str
    ) -> AuditSummary | None: ...

    async def list_audits(
        self,
        principal_id: str,
        *,
        limit: int,
        policy_action: str | None,
        status: str | None,
        conversation_id: str | None,
        before: tuple[datetime, str] | None,
    ) -> list[AuditSummary]: ...

    async def get_conversation_summary(
        self, conversation_id: str, principal_id: str
    ) -> ConversationSummary | None: ...

    async def record_rejection(self, draft: AuditDraft) -> None: ...

    async def begin_request(self, draft: AuditDraft) -> BeginResult: ...

    async def record_external_intent(
        self, request_id: str, *, provider_name: str, model: str
    ) -> None: ...

    async def record_model_intent(
        self, request_id: str, *, provider_name: str, model: str, masked: bool
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
        model_call_status: str | None = None,
        masking_status: str | None = None,
        detected_categories: list[str] | None = None,
        detector_durations_ms: dict[str, int] | None = None,
    ) -> None: ...


class PostgresRequestStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    @staticmethod
    def _summary(event: AuditEvent) -> AuditSummary:
        return AuditSummary(
            request_id=event.request_id,
            conversation_id=event.conversation_id,
            status=event.status,
            policy_action=event.policy_action,
            actual_destination=event.actual_destination,
            simulation=event.simulation,
            detected_categories=event.detected_categories,
            detection_status=event.detection_status,
            semantic_call_status=event.semantic_call_status,
            masking_status=event.masking_status,
            model_call_status=event.model_call_status,
            error_code=event.error_code,
            started_at=event.started_at,
            finished_at=event.finished_at,
            conversation_state_before=event.conversation_state_before,
            conversation_state_after=event.conversation_state_after,
            conversation_state_version=event.conversation_state_version,
            provider_name=event.provider_name,
            provider_model=event.provider_model,
            detector_durations_ms=event.detector_durations_ms,
            total_duration_ms=event.total_duration_ms,
        )

    async def get_audit_summary(self, request_id: str, principal_id: str) -> AuditSummary | None:
        async with self._sessions() as session:
            event = await session.scalar(
                select(AuditEvent).where(
                    AuditEvent.request_id == request_id, AuditEvent.principal_id == principal_id
                )
            )
            return self._summary(event) if event is not None else None

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
        statement = select(AuditEvent).where(AuditEvent.principal_id == principal_id)
        if policy_action is not None:
            statement = statement.where(AuditEvent.policy_action == policy_action)
        if status is not None:
            statement = statement.where(AuditEvent.status == status)
        if conversation_id is not None:
            statement = statement.where(AuditEvent.conversation_id == conversation_id)
        if before is not None:
            statement = statement.where(
                or_(
                    AuditEvent.started_at < before[0],
                    and_(
                        AuditEvent.started_at == before[0],
                        AuditEvent.request_id < before[1],
                    ),
                )
            )
        statement = statement.order_by(
            AuditEvent.started_at.desc(), AuditEvent.request_id.desc()
        ).limit(limit)
        async with self._sessions() as session:
            events = (await session.scalars(statement)).all()
            return [self._summary(event) for event in events]

    async def get_conversation_summary(
        self, conversation_id: str, principal_id: str
    ) -> ConversationSummary | None:
        async with self._sessions() as session:
            conversation = await session.get(Conversation, (principal_id, conversation_id))
            if conversation is None:
                return None
            return ConversationSummary(
                conversation_id=conversation.conversation_id,
                state=_state(conversation),
                state_version=conversation.state_version,
                active_request=conversation.active_request_id is not None,
                updated_at=conversation.updated_at,
            )

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

    async def begin_request(self, draft: AuditDraft) -> BeginResult:
        if draft.principal_id is None or draft.conversation_id is None:
            raise ValueError("valid request needs principal and conversation")
        async with self._sessions() as session, session.begin():
            statement = insert(Conversation).values(
                principal_id=draft.principal_id,
                conversation_id=draft.conversation_id,
                sensitive=False,
                state_version=0,
            )
            await session.execute(
                statement.on_conflict_do_nothing(
                    index_elements=[Conversation.principal_id, Conversation.conversation_id]
                )
            )
            conversation = await session.get(
                Conversation, (draft.principal_id, draft.conversation_id), with_for_update=True
            )
            if conversation is None:
                raise RuntimeError("conversation was not created")
            event = self._event(draft)
            event.conversation_state_before = _state(conversation)
            event.conversation_state_version = conversation.state_version
            if conversation.closed_at is not None:
                event.status = "REJECTED"
                event.detection_status = "NOT_RUN"
                event.error_code = "CONVERSATION_CLOSED"
                event.conversation_state_after = "CLOSED"
                event.finished_at = datetime.now(UTC)
                session.add(event)
                return BeginResult("CLOSED")
            if conversation.active_request_id is not None:
                event.status = "REJECTED"
                event.detection_status = "NOT_RUN"
                event.error_code = "CONVERSATION_BUSY"
                event.conversation_state_after = event.conversation_state_before
                event.finished_at = datetime.now(UTC)
                session.add(event)
                return BeginResult("BUSY")
            conversation.active_request_id = draft.request_id
            conversation.active_since = datetime.now(UTC)
            session.add(event)
            return BeginResult("CLAIMED", conversation.sensitive)

    async def _owned_event(
        self, session: AsyncSession, request_id: str
    ) -> tuple[Conversation, AuditEvent]:
        identity = (
            await session.execute(
                select(AuditEvent.principal_id, AuditEvent.conversation_id).where(
                    AuditEvent.request_id == request_id
                )
            )
        ).one_or_none()
        if identity is None or identity.principal_id is None or identity.conversation_id is None:
            raise RuntimeError("request audit was not found")
        conversation = await session.get(
            Conversation,
            (identity.principal_id, identity.conversation_id),
            with_for_update=True,
        )
        event = await session.get(AuditEvent, request_id, with_for_update=True)
        if (
            conversation is None
            or event is None
            or event.status != "PENDING"
            or conversation.active_request_id != request_id
            or conversation.closed_at is not None
        ):
            raise RuntimeError("request does not own the conversation")
        return conversation, event

    async def record_external_intent(
        self, request_id: str, *, provider_name: str, model: str
    ) -> None:
        async with self._sessions() as session, session.begin():
            _, event = await self._owned_event(session, request_id)
            if event.semantic_call_status is not None:
                raise RuntimeError("semantic call intent was already recorded")
            event.semantic_destination = "EXTERNAL"
            event.semantic_provider_name = provider_name
            event.semantic_model = model
            event.semantic_call_status = "INTENDED"

    async def record_model_intent(
        self, request_id: str, *, provider_name: str, model: str, masked: bool
    ) -> None:
        async with self._sessions() as session, session.begin():
            _, event = await self._owned_event(session, request_id)
            simulated_local = event.policy_action == Action.LOCAL.value and event.simulation
            if (
                event.policy_action not in {Action.CLOUD.value, Action.MASK_CLOUD.value}
                and not simulated_local
            ):
                raise RuntimeError("external model route was not selected")
            if event.model_call_status is not None or masked != (
                event.policy_action == "MASK_CLOUD"
            ):
                raise RuntimeError("external model intent is invalid")
            event.actual_destination = "EXTERNAL"
            event.provider_name = provider_name
            event.provider_model = model
            event.model_call_status = "INTENDED"
            event.masked = masked
            if masked:
                event.masking_status = "SUCCEEDED"

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
            conversation, event = await self._owned_event(session, request_id)
            if (conversation.principal_id, conversation.conversation_id) != (
                principal_id,
                conversation_id,
            ) or event.policy_action is not None:
                raise RuntimeError("request conversation or decision is invalid")
            if upgrade_sensitive and not conversation.sensitive:
                conversation.sensitive = True
                conversation.state_version += 1
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
            event.conversation_state_after = _state(conversation)
            event.conversation_state_version = conversation.state_version
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
        model_call_status: str | None = None,
        masking_status: str | None = None,
        detected_categories: list[str] | None = None,
        detector_durations_ms: dict[str, int] | None = None,
    ) -> None:
        async with self._sessions() as session, session.begin():
            conversation, event = await self._owned_event(session, request_id)
            if error_code == "REQUEST_CANCELLED" and event.policy_action is None:
                if not conversation.sensitive:
                    conversation.sensitive = True
                    conversation.state_version += 1
                    conversation.updated_at = datetime.now(UTC)
            event.status = status
            event.error_code = error_code
            event.total_duration_ms = duration_ms
            event.finished_at = datetime.now(UTC)
            if detection_status is not None:
                event.detection_status = detection_status
            if semantic_call_status is not None:
                event.semantic_call_status = semantic_call_status
            if model_call_status is not None:
                if event.model_call_status != "INTENDED":
                    raise RuntimeError("external model intent was not recorded")
                event.model_call_status = model_call_status
            elif event.model_call_status == "INTENDED":
                event.model_call_status = "UNKNOWN"
            if masking_status is not None:
                event.masking_status = masking_status
            if detected_categories is not None:
                event.detected_categories = detected_categories
            if detector_durations_ms is not None:
                event.detector_durations_ms = detector_durations_ms
            if event.conversation_state_after is None:
                event.conversation_state_after = _state(conversation)
                event.conversation_state_version = conversation.state_version
            conversation.active_request_id = None
            conversation.active_since = None

    async def close_conversation(
        self, *, principal_id: str, conversation_id: str, actor_id: str
    ) -> bool:
        async with self._sessions() as session, session.begin():
            conversation = await session.get(
                Conversation, (principal_id, conversation_id), with_for_update=True
            )
            if conversation is None:
                raise ConversationNotFound("conversation does not exist")
            if conversation.active_request_id is not None:
                raise ConversationBusy("conversation has an active request")
            if conversation.closed_at is not None:
                return False
            before = _state(conversation)
            now = datetime.now(UTC)
            conversation.closed_at = now
            conversation.updated_at = now
            conversation.state_version += 1
            session.add(
                ConversationAdminEvent(
                    event_id=uuid4().hex,
                    principal_id=principal_id,
                    conversation_id=conversation_id,
                    actor_id=actor_id,
                    action="CLOSE",
                    target_request_id=None,
                    state_before=before,
                    state_after="CLOSED",
                    state_version=conversation.state_version,
                )
            )
            return True

    async def recover_request(
        self, *, principal_id: str, conversation_id: str, request_id: str, actor_id: str
    ) -> None:
        async with self._sessions() as session, session.begin():
            conversation = await session.get(
                Conversation, (principal_id, conversation_id), with_for_update=True
            )
            if conversation is None:
                raise ConversationNotFound("conversation does not exist")
            event = await session.get(AuditEvent, request_id, with_for_update=True)
            if (
                conversation.active_request_id != request_id
                or event is None
                or event.status != "PENDING"
                or (event.principal_id, event.conversation_id) != (principal_id, conversation_id)
            ):
                raise RecoveryMismatch("request does not own a pending conversation")
            now = datetime.now(UTC)
            state_before = _state(conversation)
            if event.policy_action is None and not conversation.sensitive:
                conversation.sensitive = True
                conversation.state_version += 1
                conversation.updated_at = now
            state_after = _state(conversation)
            event.status = "FAILED"
            event.error_code = "REQUEST_ABANDONED"
            event.finished_at = now
            if event.conversation_state_after is None:
                event.conversation_state_after = state_after
            event.conversation_state_version = conversation.state_version
            if event.semantic_call_status == "INTENDED":
                event.semantic_call_status = "UNKNOWN"
            if event.model_call_status == "INTENDED":
                event.model_call_status = "UNKNOWN"
            conversation.active_request_id = None
            conversation.active_since = None
            session.add(
                ConversationAdminEvent(
                    event_id=uuid4().hex,
                    principal_id=principal_id,
                    conversation_id=conversation_id,
                    actor_id=actor_id,
                    action="RECOVER",
                    target_request_id=request_id,
                    state_before=state_before,
                    state_after=state_after,
                    state_version=conversation.state_version,
                )
            )
