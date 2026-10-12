"""Atomic conversation creation and auditable request lifecycle."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from aegis.models import AuditEvent, Conversation


@dataclass(frozen=True)
class AuditDraft:
    request_id: str
    principal_id: str | None
    conversation_id: str | None
    status: str
    policy_action: str | None
    actual_destination: str
    provider_name: str | None
    model_alias: str | None
    provider_model: str | None
    simulation: bool
    prompt_hmac: str | None
    error_code: str | None = None


class RequestStore(Protocol):
    async def record_rejection(self, draft: AuditDraft) -> None: ...

    async def prepare_dispatch(self, draft: AuditDraft) -> None: ...

    async def finish_dispatch(
        self, request_id: str, *, status: str, error_code: str | None, duration_ms: int
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
            policy_action=draft.policy_action,
            actual_destination=draft.actual_destination,
            provider_name=draft.provider_name,
            model_alias=draft.model_alias,
            provider_model=draft.provider_model,
            simulation=draft.simulation,
            blocked=False,
            masked=False,
            prompt_hmac=draft.prompt_hmac,
            detector_durations_ms={},
            error_code=draft.error_code,
        )

    async def record_rejection(self, draft: AuditDraft) -> None:
        async with self._sessions() as session, session.begin():
            session.add(self._event(draft))

    async def prepare_dispatch(self, draft: AuditDraft) -> None:
        if draft.principal_id is None or draft.conversation_id is None:
            raise ValueError("dispatch requires principal and conversation")
        async with self._sessions() as session, session.begin():
            statement = insert(Conversation).values(
                principal_id=draft.principal_id,
                conversation_id=draft.conversation_id,
                sensitive=False,
            )
            statement = statement.on_conflict_do_nothing(
                index_elements=[Conversation.principal_id, Conversation.conversation_id]
            )
            await session.execute(statement)
            session.add(self._event(draft))

    async def finish_dispatch(
        self, request_id: str, *, status: str, error_code: str | None, duration_ms: int
    ) -> None:
        async with self._sessions() as session, session.begin():
            statement = (
                update(AuditEvent)
                .where(AuditEvent.request_id == request_id, AuditEvent.status == "PENDING")
                .values(
                    status=status,
                    error_code=error_code,
                    total_duration_ms=duration_ms,
                    finished_at=datetime.now(UTC),
                )
                .returning(AuditEvent.request_id)
            )
            result = await session.execute(statement)
            if result.scalar_one_or_none() is None:
                raise RuntimeError("pending audit event was not found")
