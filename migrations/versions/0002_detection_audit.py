"""Record detection metadata separately from model routing.

Revision ID: 0002_detection_audit
Revises: 0001_initial
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002_detection_audit"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column(
            "detected_categories",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        "audit_events",
        sa.Column(
            "detection_status", sa.String(length=16), nullable=False, server_default="NOT_RUN"
        ),
    )
    op.add_column("audit_events", sa.Column("semantic_destination", sa.String(length=16)))
    op.add_column("audit_events", sa.Column("semantic_provider_name", sa.String(length=128)))
    op.add_column("audit_events", sa.Column("semantic_model", sa.String(length=128)))
    op.add_column("audit_events", sa.Column("semantic_call_status", sa.String(length=16)))


def downgrade() -> None:
    op.drop_column("audit_events", "semantic_call_status")
    op.drop_column("audit_events", "semantic_model")
    op.drop_column("audit_events", "semantic_provider_name")
    op.drop_column("audit_events", "semantic_destination")
    op.drop_column("audit_events", "detection_status")
    op.drop_column("audit_events", "detected_categories")
