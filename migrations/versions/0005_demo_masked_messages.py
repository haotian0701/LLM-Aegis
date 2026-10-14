"""Save masked model messages for demo audit details.

Revision ID: 0005_demo_masked_messages
Revises: 0004_cloud_model_audit
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0005_demo_masked_messages"
down_revision = "0004_cloud_model_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_events", sa.Column("masked_messages", JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_events", "masked_messages")
