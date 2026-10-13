"""PostgreSQL persistence models."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKeyConstraint, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Conversation(Base):
    __tablename__ = "conversations"

    principal_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    conversation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    sensitive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


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
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    policy_action: Mapped[str | None] = mapped_column(String(16), nullable=True)
    actual_destination: Mapped[str] = mapped_column(String(16), nullable=False)
    provider_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model_alias: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provider_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detected_categories: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    detection_status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    semantic_destination: Mapped[str | None] = mapped_column(String(16), nullable=True)
    semantic_provider_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    semantic_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    semantic_call_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    simulation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    masked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    prompt_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detector_durations_ms: Mapped[dict[str, int]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    total_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
