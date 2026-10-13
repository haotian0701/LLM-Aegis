"""Record external model dispatch and request-scoped masking outcomes.

Revision ID: 0004_cloud_model_audit
Revises: 0003_conversation_coordination
"""

import sqlalchemy as sa
from alembic import op

revision = "0004_cloud_model_audit"
down_revision = "0003_conversation_coordination"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("model_call_status", sa.String(16)))
    op.add_column("audit_events", sa.Column("masking_status", sa.String(16)))


def downgrade() -> None:
    op.drop_column("audit_events", "masking_status")
    op.drop_column("audit_events", "model_call_status")
