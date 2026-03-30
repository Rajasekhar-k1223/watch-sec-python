"""add_missing_agent_fields

Revision ID: e51f6801
Revises: d40e57ef27bb
Create Date: 2026-03-24 13:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = 'e51f6801'
down_revision: Union[str, Sequence[str], None] = '643a3303126c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    
    # --- Agents Table ---
    existing_agent_cols = [c['name'] for c in inspector.get_columns('Agents')]
    
    agent_cols_to_add = [
        ('ScreenshotInterval', sa.Column('ScreenshotInterval', sa.Integer(), nullable=True, server_default='60')),
        ('IsPendingUninstall', sa.Column('IsPendingUninstall', sa.Boolean(), nullable=True, server_default='0')),
    ]
    
    for name, col in agent_cols_to_add:
        if name not in existing_agent_cols:
            op.add_column('Agents', col)

def downgrade() -> None:
    op.drop_column('Agents', 'IsPendingUninstall')
    op.drop_column('Agents', 'ScreenshotInterval')
