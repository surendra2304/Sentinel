"""Persist complete scope and policy contracts for task rehydration.

Revision ID: 0002_preserve_task_contracts
Revises: 0001_initial_core_models
Create Date: 2026-10-05
"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_preserve_task_contracts"
down_revision: str | None = "0001_initial_core_models"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "sentinel_scopes",
        sa.Column("scope_contract", sa.JSON(), nullable=True),
    )
    op.add_column(
        "sentinel_policies",
        sa.Column("policy_contract", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sentinel_policies", "policy_contract")
    op.drop_column("sentinel_scopes", "scope_contract")
