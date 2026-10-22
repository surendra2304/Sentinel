"""Persist versioned working-memory checkpoints.

Revision ID: 0003_task_checkpoints
Revises: 0002_preserve_task_contracts
Create Date: 2026-10-07
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003_task_checkpoints"
down_revision: str | None = "0002_preserve_task_contracts"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sentinel_task_checkpoints",
        sa.Column(
            "task_id",
            sa.String(length=64),
            sa.ForeignKey("sentinel_tasks.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("sentinel_task_checkpoints")
