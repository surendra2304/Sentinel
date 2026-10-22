"""Persist human approval decisions and action bindings.

Revision ID: 0004_approval_records
Revises: 0003_task_checkpoints
Create Date: 2026-10-07
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004_approval_records"
down_revision: str | None = "0003_task_checkpoints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sentinel_approvals",
        sa.Column("approval_id", sa.String(length=64), primary_key=True),
        sa.Column(
            "task_id",
            sa.String(length=64),
            sa.ForeignKey("sentinel_tasks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action_id", sa.String(length=64), nullable=False),
        sa.Column("action_type", sa.String(length=128), nullable=False),
        sa.Column("target_refs", sa.JSON(), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("action_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("justification_needed", sa.Text(), nullable=False),
        sa.Column("justification_provided", sa.Text(), nullable=True),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("authorization_reference", sa.String(length=256), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sentinel_approvals_approval_id", "sentinel_approvals", ["approval_id"])
    op.create_index("ix_sentinel_approvals_task_id", "sentinel_approvals", ["task_id"])
    op.create_index("ix_sentinel_approvals_status", "sentinel_approvals", ["status"])
    op.create_index("ix_sentinel_approvals_action_id", "sentinel_approvals", ["action_id"])


def downgrade() -> None:
    op.drop_index("ix_sentinel_approvals_action_id", table_name="sentinel_approvals")
    op.drop_index("ix_sentinel_approvals_status", table_name="sentinel_approvals")
    op.drop_index("ix_sentinel_approvals_task_id", table_name="sentinel_approvals")
    op.drop_index("ix_sentinel_approvals_approval_id", table_name="sentinel_approvals")
    op.drop_table("sentinel_approvals")
