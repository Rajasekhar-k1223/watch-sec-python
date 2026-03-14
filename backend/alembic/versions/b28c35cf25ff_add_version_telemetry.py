"""add_version_telemetry

Revision ID: b28c35cf25ff
Revises: a17b35cf24ee
Create Date: 2026-01-29 08:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b28c35cf25ff'
down_revision: Union[str, Sequence[str], None] = 'a17b35cf24ee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    from sqlalchemy import inspect
    inspector = inspect(conn)
    existing_columns = [c['name'] for c in inspector.get_columns('Agents')]
    
    if 'Version' not in existing_columns:
        op.add_column('Agents', sa.Column('Version', sa.String(length=50), nullable=True))
    if 'TargetVersion' not in existing_columns:
        op.add_column('Agents', sa.Column('TargetVersion', sa.String(length=50), nullable=True))
    if 'CpuUsage' not in existing_columns:
        op.add_column('Agents', sa.Column('CpuUsage', sa.Float(), nullable=True))
    if 'MemoryUsage' not in existing_columns:
        op.add_column('Agents', sa.Column('MemoryUsage', sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column('Agents', 'MemoryUsage')
    op.drop_column('Agents', 'CpuUsage')
    op.drop_column('Agents', 'TargetVersion')
    op.drop_column('Agents', 'Version')
