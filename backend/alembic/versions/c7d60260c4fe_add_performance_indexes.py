"""add_performance_indexes

Revision ID: c7d60260c4fe
Revises: f3d6a7e2
Create Date: 2026-04-02 12:18:05.442368

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c7d60260c4fe'
down_revision: Union[str, Sequence[str], None] = 'f3d6a7e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add performance indexes to dashboard-critical tables."""
    # --- ActivityLogs: Speed up 24h filtering and tenant queries ---
    with op.batch_alter_table('ActivityLogs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ActivityLogs_TenantId'), ['TenantId'], unique=False)
        batch_op.create_index(batch_op.f('ix_ActivityLogs_Timestamp'), ['Timestamp'], unique=False)

    # --- AgentReports: Speed up online check, CPU/MEM trends, and 24h filters ---
    with op.batch_alter_table('AgentReports', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_AgentReports_AgentId'), ['AgentId'], unique=False)
        batch_op.create_index(batch_op.f('ix_AgentReports_TenantId'), ['TenantId'], unique=False)
        batch_op.create_index(batch_op.f('ix_AgentReports_Timestamp'), ['Timestamp'], unique=False)

    # --- EventLogs: Speed up threat trend analysis ---
    with op.batch_alter_table('EventLogs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_EventLogs_Timestamp'), ['Timestamp'], unique=False)


def downgrade() -> None:
    """Remove performance indexes."""
    with op.batch_alter_table('EventLogs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_EventLogs_Timestamp'))

    with op.batch_alter_table('AgentReports', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_AgentReports_Timestamp'))
        batch_op.drop_index(batch_op.f('ix_AgentReports_TenantId'))
        batch_op.drop_index(batch_op.f('ix_AgentReports_AgentId'))

    with op.batch_alter_table('ActivityLogs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ActivityLogs_Timestamp'))
        batch_op.drop_index(batch_op.f('ix_ActivityLogs_TenantId'))
