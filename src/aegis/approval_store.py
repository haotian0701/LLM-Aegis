"""Durable approval lifecycle for one GitHub write per task."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from aegis.models import AuditEvent, AuditStep, Conversation, PendingApproval


class ApprovalUnavailable(Exception):
    pass


@dataclass(frozen=True)
class ApprovalRecord:
    approval_id: str
    task_id: str
    principal_id: str
    repo: str
    issue_number: int
    encrypted_arguments: str | None
    status: str
    expires_at: datetime


def _record(row: PendingApproval) -> ApprovalRecord:
    return ApprovalRecord(
        row.approval_id,
        row.task_id,
        row.principal_id,
        row.repo,
        row.issue_number,
        row.encrypted_arguments,
        row.status,
        row.expires_at,
    )


def _close(row: PendingApproval, event: AuditEvent, step: AuditStep, status: str) -> None:
    now = datetime.now(UTC)
    row.status = status
    row.encrypted_arguments = None
    row.finished_at = now
    step.execution_status = "FAILED" if status in {"DENIED", "EXPIRED"} else "UNKNOWN"
    step.executed = False if status in {"DENIED", "EXPIRED"} else None
    step.actual_destination = "NONE" if status in {"DENIED", "EXPIRED"} else "EXTERNAL"
    step.error_code = f"APPROVAL_{status}"
    step.finished_at = now
    event.status = "BLOCKED" if status == "DENIED" else "FAILED"
    event.error_code = step.error_code
    event.finished_at = now


class PostgresApprovalStore:
    def __init__(self, sessions: async_sessionmaker) -> None:
        self._sessions = sessions

    async def create(
        self,
        *,
        task_id: str,
        principal_id: str,
        repo: str,
        issue_number: int,
        encrypted_arguments: str,
        arguments_hmac: str,
        policy_version: str,
    ) -> ApprovalRecord:
        now = datetime.now(UTC)
        approval_id = uuid4().hex
        step_id = uuid4().hex
        async with self._sessions() as session, session.begin():
            event = await session.get(AuditEvent, task_id, with_for_update=True)
            if (
                event is None
                or event.principal_id != principal_id
                or event.conversation_id is None
                or event.status != "PENDING"
                or event.task_type != "AGENT"
            ):
                raise ApprovalUnavailable("task cannot request approval")
            conversation = await session.get(
                Conversation, (principal_id, event.conversation_id), with_for_update=True
            )
            if conversation is None or conversation.active_request_id != task_id:
                raise ApprovalUnavailable("task does not own conversation")
            sequence = (
                await session.scalar(
                    select(func.max(AuditStep.sequence)).where(AuditStep.task_id == task_id)
                )
                or 0
            ) + 1
            session.add(
                AuditStep(
                    step_id=step_id,
                    task_id=task_id,
                    sequence=sequence,
                    kind="TOOL_CALL",
                    source="agent-model",
                    target=f"{repo}#{issue_number}",
                    input_summary=f"arguments_hmac={arguments_hmac}",
                    policy_version=policy_version,
                    matched_rules=["github_comment_requires_approval"],
                    data_categories=[],
                    decision="REQUIRE_APPROVAL",
                    execution_status="PENDING",
                    executed=False,
                    actual_destination="NONE",
                )
            )
            row = PendingApproval(
                approval_id=approval_id,
                task_id=task_id,
                step_id=step_id,
                principal_id=principal_id,
                repo=repo,
                issue_number=issue_number,
                encrypted_arguments=encrypted_arguments,
                arguments_hmac=arguments_hmac,
                status="PENDING",
                created_at=now,
                expires_at=now + timedelta(minutes=10),
            )
            session.add(row)
            event.status = "PENDING_APPROVAL"
            event.finished_at = None
            conversation.active_request_id = None
            conversation.active_since = None
        return _record(row)

    async def get(self, approval_id: str, principal_id: str) -> ApprovalRecord | None:
        async with self._sessions() as session:
            row = await session.get(PendingApproval, approval_id)
            if row is None or row.principal_id != principal_id:
                return None
            return _record(row)

    async def list_pending(self, principal_id: str) -> list[ApprovalRecord]:
        async with self._sessions() as session:
            rows = (
                await session.scalars(
                    select(PendingApproval)
                    .where(
                        PendingApproval.principal_id == principal_id,
                        PendingApproval.status == "PENDING",
                    )
                    .order_by(PendingApproval.created_at.desc())
                )
            ).all()
            return [_record(row) for row in rows]

    async def claim(self, approval_id: str, principal_id: str) -> ApprovalRecord:
        expired = False
        result: ApprovalRecord | None = None
        async with self._sessions() as session, session.begin():
            row = await session.get(PendingApproval, approval_id, with_for_update=True)
            if row is None or row.principal_id != principal_id or row.status != "PENDING":
                raise ApprovalUnavailable("approval is unavailable")
            if row.expires_at <= datetime.now(UTC):
                event = await session.get(AuditEvent, row.task_id, with_for_update=True)
                step = await session.get(AuditStep, row.step_id, with_for_update=True)
                assert event is not None and step is not None
                _close(row, event, step, "EXPIRED")
                expired = True
            else:
                row.status = "DISPATCHING"
                row.claimed_at = datetime.now(UTC)
                result = _record(row)
        if expired:
            raise ApprovalUnavailable("approval expired")
        assert result is not None
        return result

    async def deny(self, approval_id: str, principal_id: str) -> None:
        async with self._sessions() as session, session.begin():
            row = await session.get(PendingApproval, approval_id, with_for_update=True)
            if row is None or row.principal_id != principal_id or row.status != "PENDING":
                raise ApprovalUnavailable("approval is unavailable")
            event = await session.get(AuditEvent, row.task_id, with_for_update=True)
            step = await session.get(AuditStep, row.step_id, with_for_update=True)
            assert event is not None and step is not None
            _close(row, event, step, "DENIED")

    async def finish(self, approval_id: str, status: str, error_code: str | None = None) -> None:
        if status not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
            raise ValueError("invalid approval result")
        async with self._sessions() as session, session.begin():
            row = await session.get(PendingApproval, approval_id, with_for_update=True)
            if row is None or row.status != "DISPATCHING":
                raise ApprovalUnavailable("approval was not claimed")
            event = await session.get(AuditEvent, row.task_id, with_for_update=True)
            step = await session.get(AuditStep, row.step_id, with_for_update=True)
            assert event is not None and step is not None
            now = datetime.now(UTC)
            row.status = status
            row.encrypted_arguments = None
            row.finished_at = now
            step.execution_status = status
            step.executed = True if status == "SUCCEEDED" else None
            step.actual_destination = "EXTERNAL"
            step.error_code = error_code
            step.finished_at = now
            event.status = "SUCCEEDED" if status == "SUCCEEDED" else "FAILED"
            event.error_code = error_code
            event.finished_at = now
            event.actual_destination = "EXTERNAL"

    async def recover(self) -> None:
        now = datetime.now(UTC)
        async with self._sessions() as session, session.begin():
            rows = (
                await session.scalars(
                    select(PendingApproval)
                    .where(
                        (
                            (PendingApproval.status == "DISPATCHING")
                            & (PendingApproval.claimed_at <= now - timedelta(seconds=60))
                        )
                        | (
                            (PendingApproval.status == "PENDING")
                            & (PendingApproval.expires_at <= now)
                        )
                    )
                    .with_for_update()
                )
            ).all()
            for row in rows:
                event = await session.get(AuditEvent, row.task_id, with_for_update=True)
                step = await session.get(AuditStep, row.step_id, with_for_update=True)
                assert event is not None and step is not None
                _close(
                    row,
                    event,
                    step,
                    "UNKNOWN" if row.status == "DISPATCHING" else "EXPIRED",
                )
