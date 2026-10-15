"""Durable one-time approval for connected tool calls."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_pending_approvals"
down_revision: str | None = "0006_runtime_steps"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "pending_approvals",
        sa.Column("approval_id", sa.String(32), primary_key=True),
        sa.Column(
            "task_id",
            sa.String(32),
            sa.ForeignKey("audit_events.request_id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("step_id", sa.String(32), sa.ForeignKey("audit_steps.step_id"), nullable=False),
        sa.Column("principal_id", sa.String(128), nullable=False),
        sa.Column("repo", sa.String(256), nullable=False),
        sa.Column("issue_number", sa.Integer(), nullable=False),
        sa.Column("encrypted_arguments", sa.Text(), nullable=True),
        sa.Column("arguments_hmac", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_pending_approvals_principal_id", "pending_approvals", ["principal_id"])


def downgrade() -> None:
    op.drop_index("ix_pending_approvals_principal_id", table_name="pending_approvals")
    op.drop_table("pending_approvals")
