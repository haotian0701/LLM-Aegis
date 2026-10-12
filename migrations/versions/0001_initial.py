"""Create conversations and audit events.

Revision ID: 0001_initial
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "conversations",
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("conversation_id", sa.String(length=128), nullable=False),
        sa.Column("sensitive", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("principal_id", "conversation_id"),
    )
    op.create_table(
        "audit_events",
        sa.Column("request_id", sa.String(length=32), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=True),
        sa.Column("conversation_id", sa.String(length=128), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("policy_action", sa.String(length=16), nullable=True),
        sa.Column("actual_destination", sa.String(length=16), nullable=False),
        sa.Column("provider_name", sa.String(length=128), nullable=True),
        sa.Column("model_alias", sa.String(length=128), nullable=True),
        sa.Column("provider_model", sa.String(length=128), nullable=True),
        sa.Column("simulation", sa.Boolean(), nullable=False),
        sa.Column("blocked", sa.Boolean(), nullable=False),
        sa.Column("masked", sa.Boolean(), nullable=False),
        sa.Column("prompt_hmac", sa.String(length=64), nullable=True),
        sa.Column("detector_durations_ms", postgresql.JSONB(), nullable=False),
        sa.Column("total_duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["principal_id", "conversation_id"],
            ["conversations.principal_id", "conversations.conversation_id"],
            name="fk_audit_conversation",
        ),
        sa.PrimaryKeyConstraint("request_id"),
    )
    op.create_index("ix_audit_events_principal_id", "audit_events", ["principal_id"])
    op.create_index("ix_audit_events_conversation_id", "audit_events", ["conversation_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_events_conversation_id", table_name="audit_events")
    op.drop_index("ix_audit_events_principal_id", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_table("conversations")
