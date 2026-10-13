"""Coordinate conversation requests and retain explicit closure history.

Revision ID: 0003_conversation_coordination
Revises: 0002_detection_audit
"""

import sqlalchemy as sa
from alembic import op

revision = "0003_conversation_coordination"
down_revision = "0002_detection_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "conversations",
        sa.Column("state_version", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("conversations", sa.Column("active_request_id", sa.String(32)))
    op.add_column("conversations", sa.Column("active_since", sa.DateTime(timezone=True)))
    op.add_column("conversations", sa.Column("closed_at", sa.DateTime(timezone=True)))
    op.create_check_constraint(
        "ck_conversation_active_pair",
        "conversations",
        "(active_request_id IS NULL) = (active_since IS NULL)",
    )
    op.create_check_constraint(
        "ck_conversation_closed_inactive",
        "conversations",
        "closed_at IS NULL OR active_request_id IS NULL",
    )
    op.add_column("audit_events", sa.Column("conversation_state_before", sa.String(16)))
    op.add_column("audit_events", sa.Column("conversation_state_after", sa.String(16)))
    op.add_column("audit_events", sa.Column("conversation_state_version", sa.Integer()))
    op.create_table(
        "conversation_admin_events",
        sa.Column("event_id", sa.String(32), primary_key=True),
        sa.Column("principal_id", sa.String(128), nullable=False),
        sa.Column("conversation_id", sa.String(128), nullable=False),
        sa.Column("actor_id", sa.String(128), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("target_request_id", sa.String(32)),
        sa.Column("state_before", sa.String(16), nullable=False),
        sa.Column("state_after", sa.String(16), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["principal_id", "conversation_id"],
            ["conversations.principal_id", "conversations.conversation_id"],
            name="fk_admin_event_conversation",
        ),
    )


def downgrade() -> None:
    op.drop_table("conversation_admin_events")
    op.drop_column("audit_events", "conversation_state_version")
    op.drop_column("audit_events", "conversation_state_after")
    op.drop_column("audit_events", "conversation_state_before")
    op.drop_constraint("ck_conversation_closed_inactive", "conversations", type_="check")
    op.drop_constraint("ck_conversation_active_pair", "conversations", type_="check")
    op.drop_column("conversations", "closed_at")
    op.drop_column("conversations", "active_since")
    op.drop_column("conversations", "active_request_id")
    op.drop_column("conversations", "state_version")
