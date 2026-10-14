"""PostgreSQL persistence models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Conversation(Base):
    __tablename__ = "conversations"
    __table_args__ = (
        CheckConstraint(
            "(active_request_id IS NULL) = (active_since IS NULL)",
            name="ck_conversation_active_pair",
        ),
        CheckConstraint(
            "closed_at IS NULL OR active_request_id IS NULL",
            name="ck_conversation_closed_inactive",
        ),
    )

    principal_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active_request_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    active_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["principal_id", "conversation_id"],
            ["conversations.principal_id", "conversations.conversation_id"],
            name="fk_audit_conversation",
        ),
    )

    request_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    principal_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    conversation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_action: Mapped[str | None] = mapped_column(String(16), nullable=True)
    actual_destination: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model_alias: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provider_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detected_categories: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    detection_status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    conversation_state_before: Mapped[str | None] = mapped_column(String(16), nullable=True)
    conversation_state_after: Mapped[str | None] = mapped_column(String(16), nullable=True)
    conversation_state_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    semantic_destination: Mapped[str | None] = mapped_column(String(16), nullable=True)
    semantic_provider_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    semantic_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    semantic_call_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    model_call_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    masking_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    simulation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    masked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    prompt_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    masked_messages: Mapped[list[dict[str, object]] | None] = mapped_column(JSONB, nullable=True)
    detector_durations_ms: Mapped[dict[str, int]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    total_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class ConversationAdminEvent(Base):
    __tablename__ = "conversation_admin_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["principal_id", "conversation_id"],
            ["conversations.principal_id", "conversations.conversation_id"],
            name="fk_admin_event_conversation",
        ),
    )

    event_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    principal_id: Mapped[str] = mapped_column(String(128), nullable=False)
    conversation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    target_request_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    state_before: Mapped[str] = mapped_column(String(16), nullable=False)
    state_after: Mapped[str] = mapped_column(String(16), nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
