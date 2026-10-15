"""Add task type and ordered runtime boundary audit steps."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0006_runtime_steps"
down_revision = "0005_demo_masked_messages"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column("task_type", sa.String(16), nullable=False, server_default="CHAT"),
    )
    op.create_table(
        "audit_steps",
        sa.Column("step_id", sa.String(32), primary_key=True),
        sa.Column(
            "task_id",
            sa.String(32),
            sa.ForeignKey("audit_events.request_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("target", sa.String(256), nullable=False),
        sa.Column("input_summary", sa.String(256), nullable=False),
        sa.Column("policy_version", sa.String(64), nullable=False),
        sa.Column("matched_rules", JSONB(), nullable=False),
        sa.Column("data_categories", JSONB(), nullable=False),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("execution_status", sa.String(16), nullable=False),
        sa.Column("executed", sa.Boolean(), nullable=True),
        sa.Column("actual_destination", sa.String(256), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.UniqueConstraint("task_id", "sequence", name="uq_audit_step_order"),
    )
    op.create_index("ix_audit_steps_task_id", "audit_steps", ["task_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_steps_task_id", table_name="audit_steps")
    op.drop_table("audit_steps")
    op.drop_column("audit_events", "task_type")
